package service

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
)

const (
	PromptAuditSourceGuard          = "prompt_guard"
	PromptAuditSourceSensitiveWord  = "sensitive_word"
	PromptAuditSourceUpstreamPolicy = "upstream_policy"

	securityAuditRequestSnapshotContextKey = "security_audit_request_snapshot"
	securityAuditEventDedupeContextKey     = "security_audit_event_dedupe"
	upstreamCyberPolicyCode                = "cyber_policy"
)

type securityAuditEventDedupe struct {
	mu   sync.Mutex
	keys map[string]struct{}
}

// SetSecurityAuditRequestSnapshot 保存当前请求的原始文本快照，供后续屏蔽词和
// 上游安全策略事件复用。快照只在请求生命周期内存在，不会把明文写入日志或缓存。
func SetSecurityAuditRequestSnapshot(c *gin.Context, snapshot PromptAuditSnapshot) {
	if c == nil || strings.TrimSpace(snapshot.PromptHash) == "" {
		return
	}
	copy := snapshot
	c.Set(securityAuditRequestSnapshotContextKey, &copy)
}

func getSecurityAuditRequestSnapshot(c *gin.Context) *PromptAuditSnapshot {
	if c == nil {
		return nil
	}
	value, exists := c.Get(securityAuditRequestSnapshotContextKey)
	if !exists {
		return nil
	}
	snapshot, _ := value.(*PromptAuditSnapshot)
	if snapshot == nil {
		return nil
	}
	copy := *snapshot
	return &copy
}

// CaptureSecurityAuditRequestSnapshot 从尚未改写的请求正文生成内存快照。
// 提取失败不会改变转发语义；Guard 门禁仍由调用方按其模式单独处理错误。
func CaptureSecurityAuditRequestSnapshot(c *gin.Context, relayFormat types.RelayFormat, body []byte) (*PromptAuditSnapshot, error) {
	if c == nil || len(body) == 0 {
		return nil, ErrPromptAuditNoText
	}
	protocol, provider := securityAuditProtocolForRelayFormat(relayFormat)
	req := securityAuditRequestMetadata(c, protocol, provider, "request")
	req.Body = body
	snapshot, err := ExtractPromptAuditSnapshot(req)
	if err != nil {
		return nil, err
	}
	SetSecurityAuditRequestSnapshot(c, snapshot)
	return &snapshot, nil
}

// CaptureSecurityAuditRealtimeSnapshot 保存最近一个包含文本的客户端 Realtime
// 控制帧。上游随后返回 cyber_policy 时，事件可以关联到实际触发的文本。
func CaptureSecurityAuditRealtimeSnapshot(c *gin.Context, req PromptAuditRequest) (*PromptAuditSnapshot, error) {
	snapshot, err := ExtractPromptAuditSnapshot(req)
	if err != nil {
		return nil, err
	}
	SetSecurityAuditRequestSnapshot(c, snapshot)
	return &snapshot, nil
}

// RecordSensitiveWordAuditEvent 记录屏蔽词规则命中。snapshot 为空时使用当前
// 请求的原始快照；响应过滤可传入只包含命中响应文本的专用快照。
func RecordSensitiveWordAuditEvent(c *gin.Context, stage string, matches []SensitiveFilterMatch, snapshot *PromptAuditSnapshot) {
	if c == nil || len(matches) == 0 || model.DB == nil {
		return
	}
	cfg, err := GetPromptAuditConfig(context.Background())
	if cfg == nil || !cfg.SensitiveWordAuditEnabled {
		return
	}
	if err != nil {
		// 可用旧快照仍允许记录；配置完全不可用时 cfg 已为 nil。
		logger.LogWarn(c, "安全审计配置使用缓存快照记录屏蔽词事件")
	}
	stage = normalizeSecurityAuditStage(stage, "request")
	matchIDs := securityAuditMatchIdentifiers(matches)
	dedupeKey := PromptAuditSourceSensitiveWord + ":" + stage + ":" + strings.Join(matchIDs, ",")
	if !claimSecurityAuditEvent(c, dedupeKey) {
		return
	}
	if snapshot == nil {
		snapshot = getSecurityAuditRequestSnapshot(c)
	}

	action := "Mask"
	decision, riskLevel, riskScore := "flag", "medium", 0.5
	for _, match := range matches {
		if strings.EqualFold(match.Action, "block") {
			action = "Block"
			decision, riskLevel, riskScore = "critical", "critical", 1
			break
		}
	}
	event := buildBuiltinSecurityAuditEvent(c, cfg, snapshot, PromptAuditSourceSensitiveWord, stage)
	event.Decision = decision
	event.RiskLevel = riskLevel
	event.RiskScore = riskScore
	event.Action = action
	event.Safety = "Unsafe"
	event.Categories = marshalSecurityAuditStrings([]string{"sensitive_word"})
	event.MatchedScanners = marshalSecurityAuditStrings(matchIDs)
	promptAuditStats.total.Add(1)
	if action == "Block" {
		promptAuditStats.blocked.Add(1)
	} else {
		promptAuditStats.flagged.Add(1)
	}
	persistBuiltinSecurityAuditEvent(c, event)
}

// RecordUpstreamPolicyPayload 只匹配结构化 JSON 的固定路径，不扫描错误文案。
func RecordUpstreamPolicyPayload(c *gin.Context, payload []byte, stage string) bool {
	if !IsUpstreamCyberPolicyPayload(payload) {
		return false
	}
	recordUpstreamPolicyEvent(c, stage)
	return true
}

// RecordUpstreamPolicyError 只接受由结构化上游错误转换出的 cyber_policy code。
func RecordUpstreamPolicyError(c *gin.Context, relayErr *types.NewAPIError, stage string) bool {
	if !IsUpstreamCyberPolicyError(relayErr) {
		return false
	}
	recordUpstreamPolicyEvent(c, stage)
	return true
}

// RecordUpstreamPolicyCode 用于任务类适配器已经结构化解析出的错误码。
func RecordUpstreamPolicyCode(c *gin.Context, code string, stage string) bool {
	if !strings.EqualFold(strings.TrimSpace(code), upstreamCyberPolicyCode) {
		return false
	}
	recordUpstreamPolicyEvent(c, stage)
	return true
}

func recordUpstreamPolicyEvent(c *gin.Context, stage string) {
	if c == nil || model.DB == nil {
		return
	}
	cfg, err := GetPromptAuditConfig(context.Background())
	if cfg == nil || !cfg.UpstreamPolicyEnabled {
		return
	}
	if err != nil {
		logger.LogWarn(c, "安全审计配置使用缓存快照记录上游策略事件")
	}
	stage = normalizeSecurityAuditStage(stage, "response")
	if !claimSecurityAuditEvent(c, PromptAuditSourceUpstreamPolicy+":"+stage) {
		return
	}
	event := buildBuiltinSecurityAuditEvent(c, cfg, getSecurityAuditRequestSnapshot(c), PromptAuditSourceUpstreamPolicy, stage)
	event.Decision = "critical"
	event.RiskLevel = "critical"
	event.RiskScore = 1
	event.Action = "Block"
	event.Safety = "Unsafe"
	event.Categories = marshalSecurityAuditStrings([]string{upstreamCyberPolicyCode})
	event.MatchedScanners = marshalSecurityAuditStrings([]string{PromptAuditSourceUpstreamPolicy})
	event.ErrorCode = upstreamCyberPolicyCode
	event.ErrorMessage = "上游安全策略拒绝请求"
	promptAuditStats.total.Add(1)
	promptAuditStats.blocked.Add(1)
	persistBuiltinSecurityAuditEvent(c, event)
}

// IsUpstreamCyberPolicyPayload 精确支持普通 OpenAI 错误和 Responses
// response.failed 两种结构，不递归扫描任意 code 字段。
func IsUpstreamCyberPolicyPayload(payload []byte) bool {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" || trimmed == "[DONE]" {
		return false
	}
	var root map[string]interface{}
	if err := common.Unmarshal([]byte(trimmed), &root); err != nil {
		return false
	}
	if securityAuditObjectErrorCode(root["error"]) == upstreamCyberPolicyCode {
		return true
	}
	response, ok := root["response"].(map[string]interface{})
	if !ok {
		return false
	}
	return securityAuditObjectErrorCode(response["error"]) == upstreamCyberPolicyCode
}

func IsUpstreamCyberPolicyError(relayErr *types.NewAPIError) bool {
	if relayErr == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(string(relayErr.GetErrorCode())), upstreamCyberPolicyCode) {
		return true
	}
	switch typed := relayErr.RelayError.(type) {
	case types.OpenAIError:
		return strings.EqualFold(strings.TrimSpace(fmt.Sprint(typed.Code)), upstreamCyberPolicyCode)
	case *types.OpenAIError:
		return typed != nil && strings.EqualFold(strings.TrimSpace(fmt.Sprint(typed.Code)), upstreamCyberPolicyCode)
	default:
		return false
	}
}

func securityAuditObjectErrorCode(value interface{}) string {
	object, ok := value.(map[string]interface{})
	if !ok {
		return ""
	}
	code, ok := object["code"].(string)
	if !ok {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(code))
}

func buildBuiltinSecurityAuditEvent(c *gin.Context, cfg *PromptAuditConfig, snapshot *PromptAuditSnapshot, source, stage string) *model.PromptAuditEvent {
	now := time.Now().Unix()
	retentionDays := 30
	configVersion := int64(0)
	if cfg != nil {
		if cfg.RetentionDays > 0 {
			retentionDays = cfg.RetentionDays
		}
		configVersion = cfg.ConfigVersion
	}
	event := &model.PromptAuditEvent{
		RequestId:         c.GetString(common.RequestIdKey),
		UserId:            common.GetContextKeyInt(c, constant.ContextKeyUserId),
		Username:          common.GetContextKeyString(c, constant.ContextKeyUserName),
		UserEmail:         common.GetContextKeyString(c, constant.ContextKeyUserEmail),
		TokenId:           common.GetContextKeyInt(c, constant.ContextKeyTokenId),
		TokenName:         c.GetString("token_name"),
		GroupId:           common.GetContextKeyInt(c, constant.ContextKeyUserGroupId),
		GroupName:         common.GetContextKeyString(c, constant.ContextKeyUsingGroup),
		Provider:          securityAuditProviderFromContext(c),
		Endpoint:          securityAuditEndpointFromContext(c),
		Protocol:          securityAuditProtocolFromContext(c),
		Model:             common.GetContextKeyString(c, constant.ContextKeyOriginalModel),
		PromptCipherKind:  model.PromptAuditCipherKindPrompt,
		PromptAvailable:   false,
		Source:            source,
		Stage:             normalizeSecurityAuditStage(stage, "request"),
		Categories:        "[]",
		MatchedScanners:   "[]",
		UnknownCategories: "[]",
		ConfigVersion:     configVersion,
		CreatedAt:         now,
		ExpiresAt:         now + int64(retentionDays)*24*60*60,
	}
	if snapshot != nil {
		event.RequestId = defaultSecurityAuditString(snapshot.RequestId, event.RequestId)
		event.UserId = defaultSecurityAuditInt(snapshot.UserId, event.UserId)
		event.Username = defaultSecurityAuditString(snapshot.Username, event.Username)
		event.UserEmail = defaultSecurityAuditString(snapshot.UserEmail, event.UserEmail)
		event.TokenId = defaultSecurityAuditInt(snapshot.TokenId, event.TokenId)
		event.TokenName = defaultSecurityAuditString(snapshot.TokenName, event.TokenName)
		event.GroupId = defaultSecurityAuditInt(snapshot.GroupId, event.GroupId)
		event.GroupName = defaultSecurityAuditString(snapshot.GroupName, event.GroupName)
		event.Provider = defaultSecurityAuditString(snapshot.Provider, event.Provider)
		event.Endpoint = defaultSecurityAuditString(snapshot.Endpoint, event.Endpoint)
		event.Protocol = defaultSecurityAuditString(snapshot.Protocol, event.Protocol)
		event.Model = defaultSecurityAuditString(snapshot.Model, event.Model)
		event.PromptHash = snapshot.PromptHash
		event.PromptLength = snapshot.PromptLength
		event.PromptTruncated = snapshot.PromptTruncated
		event.MessageCount = snapshot.MessageCount
		if PromptAuditCryptoReady() && strings.TrimSpace(snapshot.FullPrompt) != "" {
			if ciphertext, err := EncryptPromptAuditSecret(snapshot.FullPrompt); err == nil && ciphertext != "" {
				event.PromptCiphertext = model.PromptAuditLargeText(ciphertext)
				event.RedactedPreview = snapshot.RedactedPreview
				event.PromptAvailable = true
			}
		}
	}
	return event
}

func persistBuiltinSecurityAuditEvent(c *gin.Context, event *model.PromptAuditEvent) {
	if event == nil {
		return
	}
	if err := model.CreatePromptAuditEvent(event); err != nil {
		promptAuditStats.recordFailed.Add(1)
		logger.LogError(c, "写入安全审计事件失败: "+err.Error())
	}
}

func claimSecurityAuditEvent(c *gin.Context, key string) bool {
	if c == nil || strings.TrimSpace(key) == "" {
		return false
	}
	value, exists := c.Get(securityAuditEventDedupeContextKey)
	state, _ := value.(*securityAuditEventDedupe)
	if !exists || state == nil {
		state = &securityAuditEventDedupe{keys: make(map[string]struct{})}
		c.Set(securityAuditEventDedupeContextKey, state)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if _, duplicate := state.keys[key]; duplicate {
		return false
	}
	state.keys[key] = struct{}{}
	return true
}

func securityAuditMatchIdentifiers(matches []SensitiveFilterMatch) []string {
	seen := make(map[string]struct{}, len(matches))
	result := make([]string, 0, len(matches))
	for _, match := range matches {
		identifier := strings.TrimSpace(match.RuleID)
		if identifier == "" {
			identifier = strings.TrimSpace(match.RuleName)
		}
		if identifier == "" {
			identifier = "unnamed_rule"
		}
		identifier = "rule:" + trimSecurityAuditRunes(identifier, 128)
		if _, duplicate := seen[identifier]; duplicate {
			continue
		}
		seen[identifier] = struct{}{}
		result = append(result, identifier)
	}
	sort.Strings(result)
	return result
}

func marshalSecurityAuditStrings(values []string) string {
	encoded, err := common.Marshal(values)
	if err != nil {
		return "[]"
	}
	return string(encoded)
}

func securityAuditRequestMetadata(c *gin.Context, protocol, provider, stage string) PromptAuditRequest {
	req := PromptAuditRequest{Protocol: protocol, Provider: provider, Stage: stage}
	if c == nil {
		return req
	}
	req.RequestId = c.GetString(common.RequestIdKey)
	req.UserId = common.GetContextKeyInt(c, constant.ContextKeyUserId)
	req.Username = common.GetContextKeyString(c, constant.ContextKeyUserName)
	req.UserEmail = common.GetContextKeyString(c, constant.ContextKeyUserEmail)
	req.TokenId = common.GetContextKeyInt(c, constant.ContextKeyTokenId)
	req.TokenName = c.GetString("token_name")
	req.GroupId = common.GetContextKeyInt(c, constant.ContextKeyUserGroupId)
	req.GroupName = common.GetContextKeyString(c, constant.ContextKeyUsingGroup)
	req.Model = common.GetContextKeyString(c, constant.ContextKeyOriginalModel)
	if c.Request != nil && c.Request.URL != nil {
		req.Endpoint = c.Request.URL.Path
		if req.Model == "" {
			req.Model = c.Query("model")
		}
	}
	return req
}

func buildSecurityAuditResponseSnapshot(c *gin.Context, payload interface{}, stage string) *PromptAuditSnapshot {
	texts := collectResponseTextFields(payload)
	if len(texts) == 0 {
		return nil
	}
	protocol := securityAuditProtocolFromContext(c)
	provider := securityAuditProviderFromContext(c)
	req := securityAuditRequestMetadata(c, protocol, provider, stage)
	snapshot, err := BuildPromptAuditTextSnapshot(req, strings.Join(texts, "\n\n"))
	if err != nil {
		return nil
	}
	return &snapshot
}

func securityAuditProtocolForRelayFormat(relayFormat types.RelayFormat) (string, string) {
	switch relayFormat {
	case types.RelayFormatClaude:
		return "anthropic_messages", "anthropic"
	case types.RelayFormatGemini:
		return "gemini", "gemini"
	case types.RelayFormatOpenAIResponses, types.RelayFormatOpenAIResponsesCompaction:
		return "openai_responses", "openai"
	case types.RelayFormatOpenAIRealtime:
		return "openai_realtime", "openai"
	case types.RelayFormatEmbedding:
		return "embedding", "openai"
	case types.RelayFormatRerank:
		return "rerank", "openai"
	case types.RelayFormatOpenAIImage:
		return "openai_images", "openai"
	case types.RelayFormatOpenAIAudio:
		return "audio", "openai"
	case types.RelayFormatTask:
		return "task", "task"
	default:
		return "openai_chat_completions", "openai"
	}
}

func securityAuditProviderFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if channelName := common.GetContextKeyString(c, constant.ContextKeyChannelName); channelName != "" {
		return trimSecurityAuditRunes(channelName, 64)
	}
	return ""
}

func securityAuditEndpointFromContext(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return ""
	}
	return trimSecurityAuditRunes(c.Request.URL.Path, 255)
}

func securityAuditProtocolFromContext(c *gin.Context) string {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return ""
	}
	path := strings.ToLower(c.Request.URL.Path)
	switch {
	case strings.Contains(path, "/realtime"):
		return "openai_realtime"
	case strings.Contains(path, "/responses"):
		return "openai_responses"
	case strings.Contains(path, "/messages"):
		return "anthropic_messages"
	case strings.Contains(path, "/v1beta/models/") || strings.Contains(path, "/v1/models/"):
		return "gemini"
	default:
		return "openai_chat_completions"
	}
}

func normalizeSecurityAuditStage(value, fallback string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		value = fallback
	}
	return trimSecurityAuditRunes(value, 32)
}

func defaultSecurityAuditString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func defaultSecurityAuditInt(value, fallback int) int {
	if value == 0 {
		return fallback
	}
	return value
}

func trimSecurityAuditRunes(value string, limit int) string {
	runes := []rune(value)
	if limit <= 0 || len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
