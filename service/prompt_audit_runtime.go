package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"gorm.io/gorm"
)

const (
	promptAuditMaxAttempts      = model.PromptAuditJobMaxAttempts
	promptAuditLease            = 5 * time.Minute
	promptAuditJobPayloadFormat = "new-api.prompt-audit-job.v1"
)

type promptAuditEncryptedPayload struct {
	Format     string `json:"format"`
	FullPrompt string `json:"full_prompt"`
	ScanText   string `json:"scan_text"`
}

// AuditPromptSnapshot 执行配置门禁。异步模式的记录失败不会影响主请求；同步模式按 fail-closed 处理。
func AuditPromptSnapshot(ctx context.Context, snapshot PromptAuditSnapshot) PromptAuditDecision {
	cfg, loadErr := GetPromptAuditConfig(ctx)
	mode := PromptAuditEffectiveMode(cfg)
	if cfg == nil && loadErr != nil {
		// 无法读取配置时不能证明审计处于关闭状态；按同步门禁的
		// fail-closed 约定拒绝请求，避免配置数据库短暂故障造成绕过。
		promptAuditStats.total.Add(1)
		promptAuditStats.unavailable.Add(1)
		return promptAuditFailureDecision(PromptGuardUnavailableCode)
	}
	if mode == PromptAuditModeOff {
		return PromptAuditDecision{Allow: true}
	}
	if mode == PromptAuditModeAsync {
		if loadErr == nil {
			_ = EnqueuePromptAuditSnapshot(snapshot, cfg)
		} else {
			promptAuditStats.dropped.Add(1)
		}
		return PromptAuditDecision{Allow: true}
	}
	if loadErr != nil || !PromptAuditCryptoReady() {
		promptAuditStats.total.Add(1)
		promptAuditStats.unavailable.Add(1)
		return promptAuditFailureDecision(PromptGuardUnavailableCode)
	}

	promptCiphertext, err := EncryptPromptAuditSecret(snapshot.FullPrompt)
	if err != nil {
		promptAuditStats.total.Add(1)
		promptAuditStats.unavailable.Add(1)
		return promptAuditFailureDecision(PromptGuardUnavailableCode)
	}
	pendingEvent := buildPromptAuditEvent(
		snapshot, cfg.ConfigVersion, cfg.RetentionDays, nil, promptCiphertext, "",
	)
	pendingEvent.Decision = "pending"
	pendingEvent.RiskLevel = "unknown"
	pendingEvent.Action = "Pending"
	pendingEvent.Safety = "Unknown"
	pendingEvent.ErrorCode = ""
	pendingEvent.ErrorMessage = ""
	if err := model.CreatePromptAuditEvent(pendingEvent); err != nil {
		promptAuditStats.total.Add(1)
		promptAuditStats.unavailable.Add(1)
		promptAuditStats.recordFailed.Add(1)
		return promptAuditFailureDecision(PromptGuardUnavailableCode)
	}
	result, guardErr := EvaluatePromptAuditGuard(ctx, cfg, snapshot)
	promptAuditStats.total.Add(1)
	if guardErr != nil {
		code := promptAuditGuardErrorCode(guardErr)
		observePromptAuditGuardError(code)
		event := buildPromptAuditEvent(snapshot, cfg.ConfigVersion, cfg.RetentionDays, nil, promptCiphertext, code)
		event.Id = pendingEvent.Id
		if persistErr := model.UpdatePromptAuditEvent(event); persistErr != nil {
			promptAuditStats.recordFailed.Add(1)
		}
		return promptAuditFailureDecision(code)
	}
	observePromptAuditResult(result)
	event := buildPromptAuditEvent(snapshot, cfg.ConfigVersion, cfg.RetentionDays, result, promptCiphertext, "")
	event.Id = pendingEvent.Id
	shouldStore := result.Action != "Allow" || cfg.StorePassEvents
	if shouldStore {
		if err := model.UpdatePromptAuditEvent(event); err != nil {
			promptAuditStats.recordFailed.Add(1)
			if result.Action != "Block" {
				return promptAuditFailureDecision(PromptGuardUnavailableCode)
			}
		}
	} else if _, _, err := model.DeletePromptAuditEvent(pendingEvent.Id); err != nil {
		promptAuditStats.recordFailed.Add(1)
		return promptAuditFailureDecision(PromptGuardUnavailableCode)
	}
	if result.Action == "Block" {
		return PromptAuditDecision{
			Allow: false, ErrorCode: PromptGuardBlockedCode, HTTPStatus: 403,
			Message: "提示词触发安全策略，已阻止本次请求", Result: result,
		}
	}
	return PromptAuditDecision{Allow: true, Result: result}
}

func promptAuditFailureDecision(code string) PromptAuditDecision {
	message := "提示词安全审计服务暂时不可用"
	if code == PromptGuardInvalidResponseCode {
		message = "提示词安全审计服务返回了无效响应"
	}
	return PromptAuditDecision{Allow: false, ErrorCode: code, HTTPStatus: 503, Message: message}
}

func observePromptAuditGuardError(code string) {
	if code == PromptGuardInvalidResponseCode {
		promptAuditStats.invalid.Add(1)
		return
	}
	promptAuditStats.unavailable.Add(1)
}

func observePromptAuditResult(result *PromptAuditResult) {
	if result == nil {
		promptAuditStats.invalid.Add(1)
		return
	}
	promptAuditStats.observeLatency(result.LatencyMs)
	switch result.Action {
	case "Block":
		promptAuditStats.blocked.Add(1)
	case "Warn":
		promptAuditStats.flagged.Add(1)
	default:
		promptAuditStats.allowed.Add(1)
	}
}

// EnqueuePromptAuditSnapshot 将完整正文作为版本化密文写入数据库队列。
func EnqueuePromptAuditSnapshot(snapshot PromptAuditSnapshot, cfg *PromptAuditConfig) error {
	if cfg == nil {
		promptAuditStats.dropped.Add(1)
		return errors.New("提示词审计配置不可用")
	}
	payloadJSON, err := common.Marshal(promptAuditEncryptedPayload{
		Format: promptAuditJobPayloadFormat, FullPrompt: snapshot.FullPrompt, ScanText: snapshot.ScanText,
	})
	if err != nil {
		promptAuditStats.dropped.Add(1)
		return err
	}
	promptCiphertext, err := EncryptPromptAuditSecret(string(payloadJSON))
	if err != nil {
		promptAuditStats.dropped.Add(1)
		return err
	}
	snapshotJSON, err := common.Marshal(snapshot)
	if err != nil {
		promptAuditStats.dropped.Add(1)
		return err
	}
	job := &model.PromptAuditJob{
		PromptCiphertext: model.PromptAuditLargeText(promptCiphertext), Snapshot: string(snapshotJSON), ConfigVersion: cfg.ConfigVersion,
	}
	if err := model.EnqueuePromptAuditJob(job, cfg.QueueCapacity); err != nil {
		promptAuditStats.dropped.Add(1)
		return err
	}
	promptAuditStats.enqueued.Add(1)
	return nil
}

func buildPromptAuditEvent(snapshot PromptAuditSnapshot, configVersion int64, retentionDays int, result *PromptAuditResult, ciphertext, errorCode string) *model.PromptAuditEvent {
	now := time.Now().Unix()
	if retentionDays < 1 {
		retentionDays = 30
	}
	event := &model.PromptAuditEvent{
		RequestId: snapshot.RequestId, UserId: snapshot.UserId, Username: snapshot.Username,
		UserEmail: snapshot.UserEmail, TokenId: snapshot.TokenId, TokenName: snapshot.TokenName,
		GroupId: snapshot.GroupId, GroupName: snapshot.GroupName, Provider: snapshot.Provider,
		Endpoint: snapshot.Endpoint, Protocol: snapshot.Protocol, Model: snapshot.Model,
		PromptHash: snapshot.PromptHash, RedactedPreview: snapshot.RedactedPreview,
		PromptCiphertext: model.PromptAuditLargeText(ciphertext), PromptCipherKind: model.PromptAuditCipherKindPrompt,
		PromptLength: snapshot.PromptLength, PromptTruncated: snapshot.PromptTruncated,
		PromptAvailable: ciphertext != "", MessageCount: snapshot.MessageCount,
		Source: PromptAuditSourceGuard, Stage: normalizeSecurityAuditStage(snapshot.Stage, "request"),
		ConfigVersion: configVersion, CreatedAt: now,
		ExpiresAt:  now + int64(retentionDays)*24*60*60,
		Categories: "[]", MatchedScanners: "[]", UnknownCategories: "[]",
	}
	if result == nil {
		event.Decision, event.RiskLevel, event.Action, event.Safety = "error", "unknown", "Error", "Unknown"
		event.ErrorCode = errorCode
		event.ErrorMessage = promptAuditSafeErrorMessage(errorCode)
		return event
	}
	event.Decision, event.RiskLevel, event.Action, event.Safety = result.Decision, result.RiskLevel, result.Action, result.Safety
	event.GuardEndpointId, event.ChunkTotal, event.LatencyMs = result.GuardEndpointId, result.ChunkTotal, result.LatencyMs
	for _, score := range result.ScannerScores {
		if score > event.RiskScore {
			event.RiskScore = score
		}
	}
	if categories, err := common.Marshal(result.Categories); err == nil {
		event.Categories = string(categories)
	}
	if scanners, err := common.Marshal(result.MatchedScanners); err == nil {
		event.MatchedScanners = string(scanners)
	}
	if unknown, err := common.Marshal(result.UnknownCategories); err == nil {
		event.UnknownCategories = string(unknown)
	}
	return event
}

func promptAuditSafeErrorMessage(code string) string {
	if code == PromptGuardInvalidResponseCode {
		return "Guard 返回格式无效"
	}
	return "Guard 服务不可用"
}

// ProcessNextPromptAuditJob 领取并处理一个数据库任务。返回 false 表示当前没有可领取任务。
func ProcessNextPromptAuditJob(ctx context.Context, workerId string) (bool, error) {
	cfg, err := GetPromptAuditConfig(ctx)
	if err != nil {
		return false, err
	}
	if cfg == nil || !cfg.Enabled {
		return false, nil
	}
	job, err := model.ClaimPromptAuditJob(workerId, promptAuditLease)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	plain, err := DecryptPromptAuditSecret(string(job.PromptCiphertext))
	if err != nil {
		return true, finishPromptAuditFailedJob(job, PromptGuardUnavailableCode, cfg.RetentionDays)
	}
	var payload promptAuditEncryptedPayload
	if err := common.UnmarshalJsonStr(plain, &payload); err != nil ||
		payload.Format != promptAuditJobPayloadFormat || payload.ScanText == "" {
		return true, finishPromptAuditFailedJob(job, PromptGuardInvalidResponseCode, cfg.RetentionDays)
	}
	var snapshot PromptAuditSnapshot
	if err := common.UnmarshalJsonStr(job.Snapshot, &snapshot); err != nil {
		return true, finishPromptAuditFailedJob(job, PromptGuardInvalidResponseCode, cfg.RetentionDays)
	}
	snapshot.FullPrompt, snapshot.ScanText = payload.FullPrompt, payload.ScanText
	evaluationContext, stopLeaseHeartbeat := startPromptAuditJobLeaseHeartbeat(ctx, job)
	result, guardErr := EvaluatePromptAuditGuard(evaluationContext, cfg, snapshot)
	leaseErr := stopLeaseHeartbeat()
	if leaseErr != nil {
		return true, leaseErr
	}
	promptAuditStats.total.Add(1)
	if guardErr != nil {
		code := promptAuditGuardErrorCode(guardErr)
		observePromptAuditGuardError(code)
		retryable := false
		var typedGuardErr *PromptGuardError
		if errors.As(guardErr, &typedGuardErr) {
			retryable = typedGuardErr.Retryable
		}
		return true, retryOrFinishPromptAuditJob(job, snapshot, nil, code, retryable, cfg)
	}
	observePromptAuditResult(result)
	promptCiphertext, err := EncryptPromptAuditSecret(snapshot.FullPrompt)
	if err != nil {
		return true, retryOrFinishPromptAuditJob(job, snapshot, nil, PromptGuardUnavailableCode, false, cfg)
	}
	var event *model.PromptAuditEvent
	if result.Action != "Allow" || cfg.StorePassEvents {
		event = buildPromptAuditEvent(snapshot, cfg.ConfigVersion, cfg.RetentionDays, result, promptCiphertext, "")
	}
	if err := model.FinishPromptAuditJob(job, event, false); err != nil {
		return true, err
	}
	promptAuditStats.processed.Add(1)
	markPromptAuditProcessed("")
	return true, nil
}

// startPromptAuditJobLeaseHeartbeat 在耗时的多分片 Guard 评估期间续租。
// 续租一旦丢失 fencing 所有权，立即取消评估，避免旧 Worker 继续调用节点。
func startPromptAuditJobLeaseHeartbeat(parent context.Context, job *model.PromptAuditJob) (context.Context, func() error) {
	evaluationContext, cancelEvaluation := context.WithCancel(parent)
	heartbeatContext, cancelHeartbeat := context.WithCancel(parent)
	done := make(chan error, 1)
	interval := promptAuditLease / 3
	if interval < time.Second {
		interval = time.Second
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := model.RenewPromptAuditJobLease(job, promptAuditLease); err != nil {
					cancelEvaluation()
					done <- err
					return
				}
			case <-heartbeatContext.Done():
				done <- nil
				return
			}
		}
	}()
	return evaluationContext, func() error {
		cancelHeartbeat()
		err := <-done
		cancelEvaluation()
		return err
	}
}

func retryOrFinishPromptAuditJob(job *model.PromptAuditJob, snapshot PromptAuditSnapshot, result *PromptAuditResult, code string, retryable bool, cfg *PromptAuditConfig) error {
	if retryable && job.Attempts < promptAuditMaxAttempts {
		// 与 sub2api 保持一致：5 秒、30 秒、2 分钟的有界退避。
		// 正常领取流程会先把 Attempts 增加到 1，但恢复旧数据或内部
		// 调用可能带着零值。退避索引必须有界，避免错误路径 panic。
		backoff := []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute}
		attemptIndex := job.Attempts - 1
		if attemptIndex < 0 {
			attemptIndex = 0
		}
		if attemptIndex >= len(backoff) {
			attemptIndex = len(backoff) - 1
		}
		delay := backoff[attemptIndex]
		return model.RetryPromptAuditJob(job, code, promptAuditSafeErrorMessage(code), time.Now().Add(delay))
	}
	retentionDays, configVersion := 30, job.ConfigVersion
	if cfg != nil {
		retentionDays, configVersion = cfg.RetentionDays, cfg.ConfigVersion
	}
	promptCiphertext, promptCipherKind := promptAuditFailureCiphertext(job, snapshot)
	event := buildPromptAuditEvent(snapshot, configVersion, retentionDays, result, promptCiphertext, code)
	event.PromptCipherKind = promptCipherKind
	if err := model.FinishPromptAuditJob(job, event, true); err != nil {
		return err
	}
	promptAuditStats.failed.Add(1)
	markPromptAuditProcessed(code)
	return nil
}

func finishPromptAuditFailedJob(job *model.PromptAuditJob, code string, retentionDays int) error {
	var snapshot PromptAuditSnapshot
	_ = common.UnmarshalJsonStr(job.Snapshot, &snapshot)
	promptCiphertext, promptCipherKind := promptAuditFailureCiphertext(job, snapshot)
	event := buildPromptAuditEvent(snapshot, job.ConfigVersion, retentionDays, nil, promptCiphertext, code)
	event.PromptCipherKind = promptCipherKind
	if err := model.FinishPromptAuditJob(job, event, true); err != nil {
		return err
	}
	promptAuditStats.failed.Add(1)
	markPromptAuditProcessed(code)
	return nil
}

// promptAuditFailureCiphertext 尽量把失败任务中的完整提示词重新封装成
// 事件密文。任务负载本身是一个版本化密文，不能在失败路径中直接清空；
// 当密钥已经轮换或密文损坏时，至少原样保留该密文，避免失败事件退化为
// 没有任何加密正文的记录。详情读取会兼容任务负载格式并提取 FullPrompt。
func promptAuditFailureCiphertext(job *model.PromptAuditJob, snapshot PromptAuditSnapshot) (string, string) {
	if snapshot.FullPrompt != "" {
		if ciphertext, err := EncryptPromptAuditSecret(snapshot.FullPrompt); err == nil && ciphertext != "" {
			return ciphertext, model.PromptAuditCipherKindPrompt
		}
	}
	if job == nil {
		return "", model.PromptAuditCipherKindPrompt
	}
	original := strings.TrimSpace(string(job.PromptCiphertext))
	if original == "" {
		return "", model.PromptAuditCipherKindPrompt
	}
	// 任务负载通常包含 FullPrompt/ScanText。密钥仍可用时，重新封装为
	// 事件约定的“直接提示词密文”，避免详情接口把内部 JSON 负载暴露出来。
	if plain, err := DecryptPromptAuditSecret(original); err == nil {
		var payload promptAuditEncryptedPayload
		if err := common.UnmarshalJsonStr(plain, &payload); err == nil &&
			payload.Format == promptAuditJobPayloadFormat && payload.FullPrompt != "" {
			if ciphertext, encryptErr := EncryptPromptAuditSecret(payload.FullPrompt); encryptErr == nil && ciphertext != "" {
				return ciphertext, model.PromptAuditCipherKindPrompt
			}
		}
	}
	return original, model.PromptAuditCipherKindJobPayload
}

// PromptAuditEventDetail 是仅供敏感详情接口返回的临时解密视图。
type PromptAuditEventDetail struct {
	*model.PromptAuditEvent
	Categories        []string `json:"categories"`
	MatchedScanners   []string `json:"matched_scanners"`
	UnknownCategories []string `json:"unknown_categories"`
	FullPrompt        string   `json:"full_prompt"`
}

func GetPromptAuditEventDetail(id int64) (*PromptAuditEventDetail, error) {
	event, err := model.GetPromptAuditEvent(id)
	if err != nil {
		return nil, err
	}
	detail := &PromptAuditEventDetail{PromptAuditEvent: event, Categories: []string{}, MatchedScanners: []string{}, UnknownCategories: []string{}}
	if event.Categories != "" {
		if err := common.UnmarshalJsonStr(event.Categories, &detail.Categories); err != nil {
			return nil, err
		}
	}
	if event.MatchedScanners != "" {
		if err := common.UnmarshalJsonStr(event.MatchedScanners, &detail.MatchedScanners); err != nil {
			return nil, err
		}
	}
	if event.UnknownCategories != "" {
		if err := common.UnmarshalJsonStr(event.UnknownCategories, &detail.UnknownCategories); err != nil {
			return nil, err
		}
	}
	if event.PromptCiphertext != "" {
		detail.FullPrompt, err = DecryptPromptAuditSecret(string(event.PromptCiphertext))
		if err != nil {
			return nil, err
		}
		// 只有模型明确标记为任务负载时才解包。原始提示词即使恰好
		// 具有相同 JSON 字段，也必须逐字返回。
		if event.PromptCipherKind == model.PromptAuditCipherKindJobPayload {
			var payload promptAuditEncryptedPayload
			if payloadErr := common.UnmarshalJsonStr(detail.FullPrompt, &payload); payloadErr != nil ||
				payload.Format != promptAuditJobPayloadFormat || payload.FullPrompt == "" {
				return nil, errors.New("提示词审计任务密文负载无效")
			}
			detail.FullPrompt = payload.FullPrompt
		}
	}
	return detail, nil
}

type PromptAuditRuntimeSnapshot struct {
	Mode              string                         `json:"mode"`
	WorkerRunning     bool                           `json:"worker_running"`
	WorkerCount       int                            `json:"worker_count"`
	GeneratedAt       int64                          `json:"generated_at"`
	ProcessStatus     string                         `json:"process_status"`
	EffectiveMode     string                         `json:"effective_mode"`
	ConfigVersion     int64                          `json:"config_version"`
	ConfigLoadError   string                         `json:"config_load_error,omitempty"`
	CryptoReady       bool                           `json:"crypto_ready"`
	WorkerTotal       int                            `json:"worker_total"`
	WorkerActive      int64                          `json:"worker_active"`
	WorkerHeartbeatAt int64                          `json:"worker_heartbeat_at"`
	Queue             model.PromptAuditRuntimeCounts `json:"queue"`
	QueueDelayMs      int64                          `json:"queue_delay_ms"`
	Metrics           PromptAuditMetricsSnapshot     `json:"metrics"`
	LastProcessedAt   int64                          `json:"last_processed_at"`
	LastErrorCode     string                         `json:"last_error_code,omitempty"`
	Endpoints         []PromptAuditEndpointHealth    `json:"endpoints"`
}

type PromptAuditEndpointHealth struct {
	Id        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Healthy   bool   `json:"healthy"`
	Status    string `json:"status"`
	LatencyMs int64  `json:"latency_ms"`
	CheckedAt int64  `json:"checked_at"`
	ErrorCode string `json:"error_code,omitempty"`
}

type promptAuditRuntime struct {
	cancel context.CancelFunc
	done   chan struct{}
}

var (
	promptAuditRuntimeMu      sync.RWMutex
	promptAuditRuntimeCurrent *promptAuditRuntime
	promptAuditWorkerActive   atomic.Int64
	promptAuditHeartbeatAt    atomic.Int64
	promptAuditLastProcessed  atomic.Int64
	promptAuditLastError      atomic.Value
	promptAuditEndpointHealth sync.Map
)

// InitPromptAuditRuntime 启动数据库队列 Worker、租约回收和保留期清理。
func InitPromptAuditRuntime() error {
	promptAuditRuntimeMu.Lock()
	defer promptAuditRuntimeMu.Unlock()
	if promptAuditRuntimeCurrent != nil {
		return nil
	}
	if model.DB == nil {
		return errors.New("提示词审计数据库尚未初始化")
	}
	if err := model.EnsurePromptAuditDefaults(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	runtime := &promptAuditRuntime{cancel: cancel, done: make(chan struct{})}
	promptAuditRuntimeCurrent = runtime
	go runPromptAuditRuntime(ctx, runtime)
	return nil
}

func ShutdownPromptAuditRuntime() {
	promptAuditRuntimeMu.Lock()
	runtime := promptAuditRuntimeCurrent
	promptAuditRuntimeCurrent = nil
	promptAuditRuntimeMu.Unlock()
	if runtime == nil {
		return
	}
	runtime.cancel()
	select {
	case <-runtime.done:
	case <-time.After(6 * time.Second):
		common.SysError("prompt audit runtime shutdown timed out")
	}
}

func runPromptAuditRuntime(ctx context.Context, runtime *promptAuditRuntime) {
	defer close(runtime.done)
	var workers sync.WaitGroup
	for index := 0; index < 32; index++ {
		workers.Add(1)
		go func(workerIndex int) {
			defer workers.Done()
			runPromptAuditWorker(ctx, workerIndex)
		}(index)
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		runPromptAuditMaintenance(ctx)
	}()
	workers.Wait()
}

func runPromptAuditWorker(ctx context.Context, workerIndex int) {
	workerId := fmt.Sprintf("prompt-audit-%d", workerIndex+1)
	for {
		if ctx.Err() != nil {
			return
		}
		cfg, cfgErr := GetPromptAuditConfig(ctx)
		if cfgErr != nil || cfg == nil || !cfg.Enabled || workerIndex >= cfg.WorkerCount {
			if !waitPromptAuditContext(ctx, 2*time.Second) {
				return
			}
			continue
		}
		promptAuditWorkerActive.Add(1)
		promptAuditHeartbeatAt.Store(time.Now().Unix())
		processed, err := ProcessNextPromptAuditJob(ctx, workerId)
		promptAuditWorkerActive.Add(-1)
		if err != nil && ctx.Err() == nil {
			common.SysError("prompt audit worker failed: " + promptAuditGuardErrorCode(err))
		}
		delay := 100 * time.Millisecond
		if !processed {
			delay = 750 * time.Millisecond
		}
		if !waitPromptAuditContext(ctx, delay) {
			return
		}
	}
}

func runPromptAuditMaintenance(ctx context.Context) {
	recoverTicker := time.NewTicker(30 * time.Second)
	cleanupTicker := time.NewTicker(time.Hour)
	defer recoverTicker.Stop()
	defer cleanupTicker.Stop()
	for {
		select {
		case <-recoverTicker.C:
			if _, err := model.RecoverExpiredPromptAuditJobs(time.Now().Unix()); err != nil {
				common.SysError("prompt audit lease recovery failed")
			}
		case <-cleanupTicker.C:
			now := time.Now()
			retentionDays := 30
			if cfg, _ := GetPromptAuditConfig(ctx); cfg != nil && cfg.RetentionDays > 0 {
				retentionDays = cfg.RetentionDays
			}
			retentionCutoff := now.Add(-time.Duration(retentionDays) * 24 * time.Hour).Unix()
			for batch := 0; batch < 20; batch++ {
				removed, err := model.CleanupExpiredPromptAuditJobs(retentionCutoff, 500)
				if err != nil {
					common.SysError("prompt audit queued job cleanup failed")
					break
				}
				if removed == 0 {
					break
				}
			}
			for batch := 0; batch < 20; batch++ {
				removed, _, err := model.CleanupPromptAuditData(now.Unix(), 500)
				if err != nil {
					common.SysError("prompt audit retention cleanup failed")
					break
				}
				if removed < 500 {
					break
				}
			}
			for batch := 0; batch < 20; batch++ {
				removed, err := model.CleanupFinishedPromptAuditJobs(retentionCutoff, 500)
				if err != nil {
					common.SysError("prompt audit finished job cleanup failed")
					break
				}
				if removed < 500 {
					break
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func waitPromptAuditContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func markPromptAuditProcessed(errorCode string) {
	promptAuditLastProcessed.Store(time.Now().Unix())
	promptAuditLastError.Store(errorCode)
}

func GetPromptAuditRuntimeSnapshot(ctx context.Context) (PromptAuditRuntimeSnapshot, error) {
	cfg, cfgErr := GetPromptAuditConfig(ctx)
	capacity, workerTotal := 32768, 0
	if cfg != nil {
		capacity, workerTotal = cfg.QueueCapacity, cfg.WorkerCount
	}
	queue, err := model.GetPromptAuditRuntimeCounts(capacity)
	if err != nil {
		return PromptAuditRuntimeSnapshot{}, err
	}
	status := "stopped"
	promptAuditRuntimeMu.RLock()
	runtimeRunning := promptAuditRuntimeCurrent != nil
	if runtimeRunning {
		status = "running"
	}
	promptAuditRuntimeMu.RUnlock()
	// 配置解密或读取失败不应把管理页变成无信息的 500。保留队列和
	// 指标快照，并明确标记 degraded，让 Root 能够关闭功能或替换密钥。
	if cfgErr != nil {
		status = "degraded"
	}
	snapshot := PromptAuditRuntimeSnapshot{
		Mode: PromptAuditEffectiveMode(cfg), WorkerRunning: runtimeRunning, WorkerCount: workerTotal,
		GeneratedAt: time.Now().Unix(), ProcessStatus: status, EffectiveMode: PromptAuditEffectiveMode(cfg),
		CryptoReady: PromptAuditCryptoReady(),
		WorkerTotal: workerTotal, WorkerActive: promptAuditWorkerActive.Load(),
		WorkerHeartbeatAt: promptAuditHeartbeatAt.Load(), Queue: queue,
		Metrics: promptAuditStats.snapshot(), LastProcessedAt: promptAuditLastProcessed.Load(),
		Endpoints: []PromptAuditEndpointHealth{},
	}
	if cfg != nil {
		snapshot.ConfigVersion = cfg.ConfigVersion
		for _, endpoint := range cfg.Endpoints {
			health := PromptAuditEndpointHealth{
				Id: endpoint.Id, Name: endpoint.Name, Enabled: endpoint.Enabled, Status: "unprobed",
			}
			if value, ok := promptAuditEndpointHealth.Load(endpoint.Id); ok {
				if probe, valid := value.(PromptAuditProbeResult); valid {
					health.Healthy, health.Status = probe.Healthy, probe.Status
					health.LatencyMs, health.CheckedAt, health.ErrorCode = probe.LatencyMs, probe.CheckedAt, probe.ErrorCode
				}
			}
			snapshot.Endpoints = append(snapshot.Endpoints, health)
		}
	}
	if cfgErr != nil {
		snapshot.ConfigLoadError = "prompt_audit_config_unavailable"
	}
	if queue.OldestQueuedAt > 0 {
		snapshot.QueueDelayMs = (time.Now().Unix() - queue.OldestQueuedAt) * 1000
	}
	if value := promptAuditLastError.Load(); value != nil {
		snapshot.LastErrorCode, _ = value.(string)
	}
	return snapshot, nil
}
