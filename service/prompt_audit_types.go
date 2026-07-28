package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const (
	PromptAuditModeOff      = "off"
	PromptAuditModeAsync    = "async_audit"
	PromptAuditModeBlocking = "blocking"

	PromptAuditTokenKeep    = "keep"
	PromptAuditTokenReplace = "replace"
	PromptAuditTokenClear   = "clear"

	PromptGuardBlockedCode         = "prompt_guard_blocked"
	PromptGuardUnavailableCode     = "prompt_guard_unavailable"
	PromptGuardInvalidResponseCode = "prompt_guard_invalid_response"
	PromptAuditConfigConflictCode  = "prompt_audit_config_conflict"

	PromptAuditDefaultModel       = "sileader/qwen3guard:0.6b"
	PromptAuditDefaultTimeoutMs   = 3000
	PromptAuditDefaultInputLimit  = 4000
	PromptAuditMaxFullPromptRunes = 65536
	PromptAuditPreviewRunes       = 96
)

var PromptAuditScannerIDs = []string{
	"violent",
	"non_violent_illegal_acts",
	"sexual_content_or_sexual_acts",
	"pii",
	"suicide_and_self_harm",
	"unethical_acts",
	"politically_sensitive_topics",
	"copyright_violation",
	"jailbreak",
}

type PromptAuditEndpoint struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	BaseUrl     string `json:"base_url"`
	Model       string `json:"model"`
	TimeoutMs   int    `json:"timeout_ms"`
	InputLimit  int    `json:"input_limit"`
	Enabled     bool   `json:"enabled"`
	HasToken    bool   `json:"has_token"`
	TokenStatus string `json:"token_status"`
	Token       string `json:"-"`
}

type PromptAuditConfig struct {
	Enabled                   bool `json:"enabled"`
	BlockingEnabled           bool `json:"blocking_enabled"`
	StorePassEvents           bool `json:"store_pass_events"`
	UpstreamPolicyEnabled     bool `json:"upstream_policy_enabled"`
	SensitiveWordAuditEnabled bool `json:"sensitive_word_audit_enabled"`
	// Mode 是面向管理 API 的稳定别名；EffectiveMode 保留运行态兼容字段。
	Mode          string                `json:"mode"`
	EffectiveMode string                `json:"effective_mode"`
	Strategy      string                `json:"strategy"`
	WorkerCount   int                   `json:"worker_count"`
	QueueCapacity int                   `json:"queue_capacity"`
	RetentionDays int                   `json:"retention_days"`
	Scanners      []string              `json:"scanners"`
	AllGroups     bool                  `json:"all_groups"`
	GroupIds      []int                 `json:"group_ids"`
	Endpoints     []PromptAuditEndpoint `json:"endpoints"`
	ConfigVersion int64                 `json:"config_version"`
	UpdatedAt     int64                 `json:"updated_at"`
	UpdatedBy     int                   `json:"updated_by"`
	ChangeSummary string                `json:"change_summary"`
}

type PromptAuditUpdateEndpoint struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	BaseUrl     string `json:"base_url"`
	Model       string `json:"model"`
	TokenAction string `json:"token_action"`
	Token       string `json:"token,omitempty"`
	TimeoutMs   int    `json:"timeout_ms"`
	InputLimit  int    `json:"input_limit"`
	Enabled     bool   `json:"enabled"`
}

type PromptAuditUpdateRequest struct {
	ExpectedConfigVersion     int64                       `json:"expected_version"`
	Mode                      string                      `json:"mode,omitempty"`
	Enabled                   bool                        `json:"enabled"`
	BlockingEnabled           bool                        `json:"blocking_enabled"`
	StorePassEvents           bool                        `json:"store_pass_events"`
	UpstreamPolicyEnabled     *bool                       `json:"upstream_policy_enabled,omitempty"`
	SensitiveWordAuditEnabled *bool                       `json:"sensitive_word_audit_enabled,omitempty"`
	Strategy                  string                      `json:"strategy"`
	WorkerCount               int                         `json:"worker_count"`
	QueueCapacity             int                         `json:"queue_capacity"`
	RetentionDays             int                         `json:"retention_days"`
	Scanners                  []string                    `json:"scanners"`
	AllGroups                 bool                        `json:"all_groups"`
	GroupIds                  []int                       `json:"group_ids"`
	Endpoints                 []PromptAuditUpdateEndpoint `json:"endpoints"`
}

type PromptAuditSnapshot struct {
	RequestId       string `json:"request_id"`
	UserId          int    `json:"user_id"`
	Username        string `json:"username"`
	UserEmail       string `json:"user_email"`
	TokenId         int    `json:"api_key_id"`
	TokenName       string `json:"api_key_name"`
	GroupId         int    `json:"group_id"`
	GroupName       string `json:"group_name"`
	Provider        string `json:"provider"`
	Endpoint        string `json:"endpoint"`
	Protocol        string `json:"protocol"`
	Model           string `json:"model"`
	PromptHash      string `json:"prompt_hash"`
	RedactedPreview string `json:"redacted_preview"`
	PromptLength    int    `json:"prompt_length"`
	PromptTruncated bool   `json:"prompt_truncated"`
	MessageCount    int    `json:"message_count"`
	Stage           string `json:"stage"`
	FullPrompt      string `json:"-"`
	ScanText        string `json:"-"`
}

type PromptAuditResult struct {
	Decision          string             `json:"decision"`
	RiskLevel         string             `json:"risk_level"`
	Action            string             `json:"action"`
	Safety            string             `json:"safety"`
	Categories        []string           `json:"categories"`
	MatchedScanners   []string           `json:"matched_scanners"`
	ScannerScores     map[string]float64 `json:"scanner_scores"`
	ScannerEvidence   map[string]string  `json:"scanner_evidence"`
	GuardEndpointId   string             `json:"guard_endpoint_id"`
	ScannerVersion    string             `json:"scanner_version"`
	ChunkTotal        int                `json:"chunk_total"`
	LatencyMs         int64              `json:"latency_ms"`
	UnknownCategories []string           `json:"unknown_categories,omitempty"`
}

type PromptAuditDecision struct {
	Allow      bool               `json:"allow"`
	ErrorCode  string             `json:"error_code,omitempty"`
	HTTPStatus int                `json:"http_status,omitempty"`
	Message    string             `json:"message,omitempty"`
	Result     *PromptAuditResult `json:"result,omitempty"`
}

type PromptGuardError struct {
	Code       string
	HTTPStatus int
	Retryable  bool
	Timeout    bool
	Cause      error
}

func (e *PromptGuardError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Cause != nil {
		return e.Code + ": " + e.Cause.Error()
	}
	return e.Code
}

func (e *PromptGuardError) Unwrap() error { return e.Cause }

type PromptAuditMetricsSnapshot struct {
	Total        int64 `json:"total"`
	Allowed      int64 `json:"allowed"`
	Flagged      int64 `json:"flagged"`
	Blocked      int64 `json:"blocked"`
	Unavailable  int64 `json:"unavailable"`
	Invalid      int64 `json:"invalid"`
	Timeouts     int64 `json:"timeouts"`
	Failovers    int64 `json:"failovers"`
	BulkheadFull int64 `json:"bulkhead_full"`
	RecordFailed int64 `json:"record_failed"`
	Enqueued     int64 `json:"enqueued"`
	Dropped      int64 `json:"dropped"`
	Processed    int64 `json:"processed"`
	Failed       int64 `json:"failed"`
	LatencyCount int64 `json:"latency_count"`
	LatencyAvgMs int64 `json:"latency_avg_ms"`
	LatencyMaxMs int64 `json:"latency_max_ms"`
}

type promptAuditMetrics struct {
	total, allowed, flagged, blocked, unavailable, invalid atomic.Int64
	timeouts, failovers, bulkheadFull, recordFailed        atomic.Int64
	enqueued, dropped, processed, failed                   atomic.Int64
	latencyCount, latencyTotalMs, latencyMaxMs             atomic.Int64
}

func (m *promptAuditMetrics) snapshot() PromptAuditMetricsSnapshot {
	result := PromptAuditMetricsSnapshot{
		Total: m.total.Load(), Allowed: m.allowed.Load(), Flagged: m.flagged.Load(),
		Blocked: m.blocked.Load(), Unavailable: m.unavailable.Load(), Invalid: m.invalid.Load(),
		Timeouts: m.timeouts.Load(), Failovers: m.failovers.Load(), BulkheadFull: m.bulkheadFull.Load(),
		RecordFailed: m.recordFailed.Load(), Enqueued: m.enqueued.Load(), Dropped: m.dropped.Load(),
		Processed: m.processed.Load(), Failed: m.failed.Load(),
		LatencyCount: m.latencyCount.Load(), LatencyMaxMs: m.latencyMaxMs.Load(),
	}
	if result.LatencyCount > 0 {
		result.LatencyAvgMs = m.latencyTotalMs.Load() / result.LatencyCount
	}
	return result
}

func (m *promptAuditMetrics) observeLatency(latencyMs int64) {
	if latencyMs < 0 {
		return
	}
	m.latencyCount.Add(1)
	m.latencyTotalMs.Add(latencyMs)
	for {
		current := m.latencyMaxMs.Load()
		if latencyMs <= current || m.latencyMaxMs.CompareAndSwap(current, latencyMs) {
			return
		}
	}
}

// RecordPromptAuditDropped 记录异步审计在提取或入队前被丢弃，
// 不把审计侧故障传播给主请求。
func RecordPromptAuditDropped() {
	promptAuditStats.dropped.Add(1)
}

var promptAuditStats promptAuditMetrics

type promptAuditConfigCacheState struct {
	mu       sync.RWMutex
	config   *PromptAuditConfig
	loadedAt time.Time
	err      error
}

var promptAuditConfigCache promptAuditConfigCacheState

func PromptAuditEffectiveMode(cfg *PromptAuditConfig) string {
	if cfg == nil || !cfg.Enabled {
		return PromptAuditModeOff
	}
	if cfg.BlockingEnabled {
		return PromptAuditModeBlocking
	}
	return PromptAuditModeAsync
}

func (cfg *PromptAuditConfig) includesGroup(groupId int) bool {
	if cfg == nil || cfg.AllGroups {
		return true
	}
	index := sort.SearchInts(cfg.GroupIds, groupId)
	return index < len(cfg.GroupIds) && cfg.GroupIds[index] == groupId
}

func InvalidatePromptAuditConfig() {
	promptAuditConfigCache.mu.Lock()
	promptAuditConfigCache.loadedAt = time.Time{}
	promptAuditConfigCache.config = nil
	promptAuditConfigCache.err = nil
	promptAuditConfigCache.mu.Unlock()
}

func GetPromptAuditConfig(ctx context.Context) (*PromptAuditConfig, error) {
	_ = ctx
	promptAuditConfigCache.mu.RLock()
	if !promptAuditConfigCache.loadedAt.IsZero() && time.Since(promptAuditConfigCache.loadedAt) < 5*time.Second {
		cfg := clonePromptAuditConfig(promptAuditConfigCache.config)
		err := promptAuditConfigCache.err
		promptAuditConfigCache.mu.RUnlock()
		return cfg, err
	}
	promptAuditConfigCache.mu.RUnlock()

	promptAuditConfigCache.mu.Lock()
	defer promptAuditConfigCache.mu.Unlock()
	if !promptAuditConfigCache.loadedAt.IsZero() && time.Since(promptAuditConfigCache.loadedAt) < 5*time.Second {
		return clonePromptAuditConfig(promptAuditConfigCache.config), promptAuditConfigCache.err
	}
	cfgRow, endpointRows, err := model.LoadPromptAuditConfig()
	if err != nil {
		stale := clonePromptAuditConfig(promptAuditConfigCache.config)
		promptAuditConfigCache.loadedAt = time.Now()
		promptAuditConfigCache.err = err
		return stale, err
	}
	cfg, err := promptAuditConfigFromModels(cfgRow, endpointRows, true)
	promptAuditConfigCache.config = cfg
	promptAuditConfigCache.loadedAt = time.Now()
	promptAuditConfigCache.err = err
	return clonePromptAuditConfig(cfg), err
}

func clonePromptAuditConfig(cfg *PromptAuditConfig) *PromptAuditConfig {
	if cfg == nil {
		return nil
	}
	clone := *cfg
	// 保留空 slice 的非 nil 形态，避免 Go JSON 将初始配置的数组字段
	// 序列化为 null，导致前端草稿和筛选控件在首次打开页面时崩溃。
	clone.Scanners = append(make([]string, 0, len(cfg.Scanners)), cfg.Scanners...)
	clone.GroupIds = append(make([]int, 0, len(cfg.GroupIds)), cfg.GroupIds...)
	clone.Endpoints = append(make([]PromptAuditEndpoint, 0, len(cfg.Endpoints)), cfg.Endpoints...)
	return &clone
}

func promptAuditConfigFromModels(row *model.PromptAuditConfig, endpointRows []model.PromptAuditEndpoint, includeSecrets bool) (*PromptAuditConfig, error) {
	if row == nil {
		return nil, errors.New("prompt audit config missing")
	}
	scanners := append([]string(nil), PromptAuditScannerIDs...)
	if strings.TrimSpace(row.Scanners) != "" {
		if err := common.UnmarshalJsonStr(row.Scanners, &scanners); err != nil {
			return nil, err
		}
	}
	groupIds := []int{}
	if strings.TrimSpace(row.GroupIds) != "" {
		if err := common.UnmarshalJsonStr(row.GroupIds, &groupIds); err != nil {
			return nil, err
		}
	}
	sort.Ints(groupIds)
	endpoints := make([]PromptAuditEndpoint, 0, len(endpointRows))
	var secretErr error
	for _, endpoint := range endpointRows {
		public := PromptAuditEndpoint{
			Id: endpoint.Id, Name: endpoint.Name, Protocol: endpoint.Protocol, BaseUrl: endpoint.BaseUrl,
			Model: endpoint.Model, TimeoutMs: endpoint.TimeoutMs, InputLimit: endpoint.InputLimit,
			Enabled: endpoint.Enabled, HasToken: endpoint.TokenCiphertext != "", TokenStatus: "missing",
		}
		if public.HasToken {
			public.TokenStatus = "configured"
			if includeSecrets {
				plain, err := DecryptPromptAuditSecret(endpoint.TokenCiphertext)
				if err != nil {
					public.TokenStatus = "unreadable"
					// 禁用节点不参与请求门禁，旧密钥不可读只影响该节点自身
					// 的 keep/探测操作，不能拖垮其他可用节点或整个审计队列。
					if endpoint.Enabled && secretErr == nil {
						secretErr = err
					}
				} else {
					public.Token = plain
				}
			} else if !PromptAuditCryptoReady() {
				public.TokenStatus = "unreadable"
			} else if _, err := DecryptPromptAuditSecret(endpoint.TokenCiphertext); err != nil {
				public.TokenStatus = "unreadable"
			}
		}
		endpoints = append(endpoints, public)
	}
	cfg := &PromptAuditConfig{
		Enabled: row.Enabled, BlockingEnabled: row.BlockingEnabled, StorePassEvents: row.StorePassEvents,
		UpstreamPolicyEnabled: row.UpstreamPolicyEnabled, SensitiveWordAuditEnabled: row.SensitiveWordAuditEnabled,
		Strategy: row.Strategy, WorkerCount: row.WorkerCount, QueueCapacity: row.QueueCapacity,
		RetentionDays: row.RetentionDays, Scanners: scanners, AllGroups: row.AllGroups,
		GroupIds: groupIds, Endpoints: endpoints, ConfigVersion: row.ConfigVersion,
		UpdatedAt: row.UpdatedAt, UpdatedBy: row.UpdatedBy, ChangeSummary: row.ChangeSummary,
	}
	cfg.EffectiveMode = PromptAuditEffectiveMode(cfg)
	cfg.Mode = cfg.EffectiveMode
	return cfg, secretErr
}

func PublicPromptAuditConfig(cfg *PromptAuditConfig) *PromptAuditConfig {
	clone := clonePromptAuditConfig(cfg)
	if clone == nil {
		return nil
	}
	for i := range clone.Endpoints {
		clone.Endpoints[i].Token = ""
	}
	return clone
}
