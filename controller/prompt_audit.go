package controller

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type promptAuditEventFilterRequest struct {
	Source     string `json:"source"`
	Stage      string `json:"stage"`
	Decision   string `json:"decision"`
	RiskLevel  string `json:"risk_level"`
	Endpoint   string `json:"endpoint"`
	RequestId  string `json:"request_id"`
	PromptHash string `json:"prompt_hash"`
	Keyword    string `json:"keyword"`
	UserId     int    `json:"user_id"`
	TokenId    int    `json:"token_id"`
	GroupId    int    `json:"group_id"`
	StartAt    int64  `json:"start_at"`
	EndAt      int64  `json:"end_at"`
}

func (req promptAuditEventFilterRequest) toModel() model.PromptAuditEventFilter {
	return model.PromptAuditEventFilter{
		Source: strings.TrimSpace(req.Source), Stage: strings.TrimSpace(req.Stage),
		Decision: strings.TrimSpace(req.Decision), RiskLevel: strings.TrimSpace(req.RiskLevel),
		Endpoint: strings.TrimSpace(req.Endpoint), RequestId: strings.TrimSpace(req.RequestId),
		PromptHash: strings.TrimSpace(req.PromptHash), Keyword: strings.TrimSpace(req.Keyword),
		UserId: req.UserId, TokenId: req.TokenId, GroupId: req.GroupId,
		StartAt: req.StartAt, EndAt: req.EndAt,
	}
}

type promptAuditEventListItem struct {
	model.PromptAuditEvent
	Categories        []string `json:"categories"`
	MatchedScanners   []string `json:"matched_scanners"`
	UnknownCategories []string `json:"unknown_categories"`
}

type promptAuditProbeRequest struct {
	EndpointId  string `json:"endpoint_id"`
	Name        string `json:"name"`
	BaseUrl     string `json:"base_url"`
	Model       string `json:"model"`
	TokenAction string `json:"token_action"`
	Token       string `json:"token"`
	TimeoutMs   *int   `json:"timeout_ms"`
	InputLimit  *int   `json:"input_limit"`
}

type promptAuditBatchDeleteRequest struct {
	Ids []int64 `json:"ids"`
}

type promptAuditConfirmedDeleteRequest struct {
	Filter            promptAuditEventFilterRequest `json:"filter"`
	ConfirmationToken string                        `json:"confirmation_token"`
	Confirm           bool                          `json:"confirm"`
}

func GetPromptAuditConfig(c *gin.Context) {
	cfg, err := service.GetPublicPromptAuditConfig()
	if err != nil {
		writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_config_load_failed", "安全审计配置加载失败")
		return
	}
	common.ApiSuccess(c, cfg)
}

func UpdatePromptAuditConfig(c *gin.Context) {
	var req service.PromptAuditUpdateRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_request", "安全审计配置参数无效")
		return
	}
	cfg, err := service.SavePromptAuditConfig(req, c.GetInt("id"))
	if err != nil {
		if errors.Is(err, model.ErrPromptAuditConfigConflict) {
			writePromptAuditAdminError(c, http.StatusConflict, service.PromptAuditConfigConflictCode, "安全审计配置已被其他管理员更新，请刷新后重试")
			return
		}
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_config_invalid", err.Error())
		return
	}
	recordPromptAuditAdminLog(c, "更新了提示词安全审计配置", map[string]interface{}{
		"config_version": cfg.ConfigVersion,
		"effective_mode": cfg.EffectiveMode,
		"endpoint_count": len(cfg.Endpoints),
	})
	common.ApiSuccess(c, cfg)
}

func GetSecurityAuditBuiltinPolicy(c *gin.Context) {
	policy, err := service.GetSecurityAuditBuiltinPolicy()
	if err != nil {
		writePromptAuditAdminError(c, http.StatusInternalServerError, "security_audit_builtin_policy_load_failed", "内置安全策略加载失败")
		return
	}
	common.ApiSuccess(c, policy)
}

func UpdateSecurityAuditBuiltinPolicy(c *gin.Context) {
	var req service.SecurityAuditBuiltinPolicyUpdateRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "security_audit_builtin_policy_invalid_request", "内置安全策略参数无效")
		return
	}
	policy, err := service.SaveSecurityAuditBuiltinPolicy(req, c.GetInt("id"))
	if err != nil {
		if errors.Is(err, model.ErrPromptAuditConfigConflict) {
			writePromptAuditAdminError(c, http.StatusConflict, service.PromptAuditConfigConflictCode, "安全审计配置已被其他管理员更新，请刷新后重试")
			return
		}
		writePromptAuditAdminError(c, http.StatusBadRequest, "security_audit_builtin_policy_invalid", err.Error())
		return
	}
	recordPromptAuditAdminLog(c, "更新了内置安全策略", map[string]interface{}{
		"config_version":                    policy.ConfigVersion,
		"upstream_policy_enabled":           policy.UpstreamPolicyEnabled,
		"sensitive_word_audit_enabled":      policy.SensitiveWordAuditEnabled,
		"check_sensitive_enabled":           policy.CheckSensitiveEnabled,
		"check_sensitive_on_prompt_enabled": policy.CheckSensitiveOnPromptEnabled,
	})
	common.ApiSuccess(c, policy)
}

func ProbePromptAuditEndpoint(c *gin.Context) {
	var req promptAuditProbeRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_request", "Guard 节点探测参数无效")
		return
	}
	req.EndpointId = strings.TrimSpace(req.EndpointId)
	req.TokenAction = strings.ToLower(strings.TrimSpace(req.TokenAction))
	req.Token = strings.TrimSpace(req.Token)
	if req.EndpointId == "" {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_required", "Guard 节点 ID 不能为空")
		return
	}
	switch req.TokenAction {
	case service.PromptAuditTokenKeep, service.PromptAuditTokenClear:
		if req.Token != "" {
			writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_token_invalid", "Guard 节点令牌仅允许在 replace 操作中提交")
			return
		}
	case service.PromptAuditTokenReplace:
		if req.Token == "" {
			writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_token_required", "replace 操作必须提供 Guard 节点令牌")
			return
		}
	default:
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_token_action_invalid", "Guard 节点 token_action 仅支持 keep、replace 或 clear")
		return
	}
	cfg, _ := service.GetPromptAuditConfig(c.Request.Context())
	if cfg == nil {
		// 密钥轮换或丢失时，私密配置视图可能无法解密某个旧令牌。
		// Root 仍须能够替换或清除该令牌，因此探测接口退回到不含
		// 密文的公共配置视图；如果配置快照本身存在，即使其中另一个
		// 节点令牌不可读，也必须保留当前节点可解密的令牌。
		publicCfg, publicErr := service.GetPublicPromptAuditConfig()
		if publicErr != nil {
			writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_config_load_failed", "安全审计配置加载失败")
			return
		}
		cfg = publicCfg
	}
	endpoint := service.PromptAuditEndpoint{Id: req.EndpointId}
	storedBaseURL := ""
	for _, configured := range cfg.Endpoints {
		if configured.Id == req.EndpointId {
			endpoint = configured
			storedBaseURL = configured.BaseUrl
			break
		}
	}
	if req.TokenAction == service.PromptAuditTokenKeep && endpoint.TokenStatus == "unreadable" {
		writePromptAuditAdminError(c, http.StatusServiceUnavailable, "prompt_guard_unavailable", "Guard 节点令牌无法解密，请替换或清除令牌")
		return
	}
	if strings.TrimSpace(req.Name) != "" {
		endpoint.Name = strings.TrimSpace(req.Name)
	}
	baseURLChanged := false
	if strings.TrimSpace(req.BaseUrl) != "" {
		normalized, normalizeErr := service.NormalizePromptAuditBaseURL(req.BaseUrl)
		if normalizeErr != nil {
			writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", normalizeErr.Error())
			return
		}
		if storedBaseURL != "" {
			storedNormalized, storedErr := service.NormalizePromptAuditBaseURL(storedBaseURL)
			baseURLChanged = storedErr != nil || storedNormalized != normalized
		}
		endpoint.BaseUrl = normalized
	}
	if strings.TrimSpace(req.Model) != "" {
		endpoint.Model = strings.TrimSpace(req.Model)
	}
	// 探测请求允许省略已有节点的可选字段，但一旦显式提交数值，必须
	// 与配置保存使用同一组边界。此前负数会被静默当成默认值，既让管理
	// 页面和接口行为不一致，也可能让调用方误以为探测的是其提交参数。
	if req.TimeoutMs != nil && (*req.TimeoutMs < 100 || *req.TimeoutMs > 30000) {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", "Guard 节点超时必须在 100 到 30000 毫秒之间")
		return
	}
	if req.InputLimit != nil && (*req.InputLimit < 128 || *req.InputLimit > 100000) {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", "Guard 节点输入上限必须在 128 到 100000 字符之间")
		return
	}
	switch req.TokenAction {
	case service.PromptAuditTokenReplace:
		endpoint.Token = req.Token
	case service.PromptAuditTokenClear:
		endpoint.Token = ""
	case service.PromptAuditTokenKeep:
		// 令牌不能随着 keep 操作被转发到新地址；否则编辑节点地址时，
		// 恶意或误填的地址可能收到原节点的 Guard 凭据。存在旧令牌时
		// 直接拒绝，而不是悄悄改成匿名探测，避免产生节点可用的误判。
		if baseURLChanged && endpoint.HasToken {
			writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_token_action_required",
				"Guard 节点地址变化时必须显式替换或清除令牌")
			return
		}
	}
	if req.TimeoutMs != nil {
		endpoint.TimeoutMs = *req.TimeoutMs
	}
	if req.InputLimit != nil {
		endpoint.InputLimit = *req.InputLimit
	}
	if endpoint.BaseUrl == "" {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", "Guard 节点地址不能为空")
		return
	}
	if endpoint.Name == "" {
		endpoint.Name = req.EndpointId
	}
	if endpoint.Model == "" {
		endpoint.Model = service.PromptAuditDefaultModel
	}
	if endpoint.TimeoutMs == 0 {
		endpoint.TimeoutMs = service.PromptAuditDefaultTimeoutMs
	}
	if endpoint.InputLimit == 0 {
		endpoint.InputLimit = service.PromptAuditDefaultInputLimit
	}
	if len([]rune(endpoint.Name)) > 128 || len([]rune(endpoint.Model)) > 255 || len(endpoint.Token) > 8192 {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", "Guard 节点名称、模型或令牌长度超出限制")
		return
	}
	if endpoint.TimeoutMs < 100 || endpoint.TimeoutMs > 30000 {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", "Guard 节点超时必须在 100 到 30000 毫秒之间")
		return
	}
	if endpoint.InputLimit < 128 || endpoint.InputLimit > 100000 {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_endpoint_invalid", "Guard 节点输入上限必须在 128 到 100000 字符之间")
		return
	}
	endpoint.Enabled = true
	probeTimeout := time.Duration(endpoint.TimeoutMs+1000) * time.Millisecond
	if probeTimeout < 2*time.Second {
		probeTimeout = 2 * time.Second
	}
	if probeTimeout > 35*time.Second {
		probeTimeout = 35 * time.Second
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), probeTimeout)
	defer cancel()
	result := service.ProbePromptAuditEndpoint(ctx, endpoint)
	recordPromptAuditAdminLog(c, "探测了提示词安全审计 Guard 节点", map[string]interface{}{
		"endpoint_id": req.EndpointId,
		"status":      result.Status,
		"error_code":  result.ErrorCode,
	})
	common.ApiSuccess(c, result)
}

func GetPromptAuditRuntime(c *gin.Context) {
	runtime, err := service.GetPromptAuditRuntimeSnapshot(c.Request.Context())
	if err != nil {
		writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_runtime_failed", "安全审计运行状态加载失败")
		return
	}
	common.ApiSuccess(c, runtime)
}

func ListPromptAuditEvents(c *gin.Context) {
	page, err := promptAuditQueryInt(c, "page", 1, 0)
	if err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_pagination", "分页参数无效")
		return
	}
	pageSize, err := promptAuditQueryInt(c, "page_size", 20, 100)
	if err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_pagination", "分页参数无效")
		return
	}
	filter, err := promptAuditFilterFromQuery(c)
	if err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_filter", "筛选参数无效")
		return
	}
	events, total, err := model.ListPromptAuditEvents(filter, page, pageSize)
	if err != nil {
		writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_events_load_failed", "安全审计事件加载失败")
		return
	}
	items := make([]promptAuditEventListItem, 0, len(events))
	for _, event := range events {
		item := promptAuditEventListItem{PromptAuditEvent: event, Categories: []string{}, MatchedScanners: []string{}, UnknownCategories: []string{}}
		if event.Categories != "" {
			if err := common.UnmarshalJsonStr(event.Categories, &item.Categories); err != nil {
				writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_event_invalid", "安全审计事件分类数据无效")
				return
			}
		}
		if event.MatchedScanners != "" {
			if err := common.UnmarshalJsonStr(event.MatchedScanners, &item.MatchedScanners); err != nil {
				writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_event_invalid", "安全审计事件扫描器数据无效")
				return
			}
		}
		if event.UnknownCategories != "" {
			if err := common.UnmarshalJsonStr(event.UnknownCategories, &item.UnknownCategories); err != nil {
				writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_event_invalid", "安全审计事件未知分类数据无效")
				return
			}
		}
		items = append(items, item)
	}
	common.ApiSuccess(c, gin.H{"items": items, "total": total, "page": page, "page_size": pageSize})
}

func GetPromptAuditEvent(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	id, ok := promptAuditEventId(c)
	if !ok {
		return
	}
	detail, err := service.GetPromptAuditEventDetail(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writePromptAuditAdminError(c, http.StatusNotFound, "prompt_audit_event_not_found", "安全审计事件不存在")
			return
		}
		writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_event_detail_failed", "安全审计事件详情加载失败")
		return
	}
	recordPromptAuditAdminLog(c, "查看了提示词安全审计事件详情", map[string]interface{}{
		"event_id": id,
	})
	common.ApiSuccess(c, detail)
}

func DeletePromptAuditEvent(c *gin.Context) {
	id, ok := promptAuditEventId(c)
	if !ok {
		return
	}
	deletedEvents, deletedJobs, err := model.DeletePromptAuditEvent(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			writePromptAuditAdminError(c, http.StatusNotFound, "prompt_audit_event_not_found", "安全审计事件不存在")
			return
		}
		writePromptAuditAdminError(c, http.StatusInternalServerError, "prompt_audit_event_delete_failed", "安全审计事件删除失败")
		return
	}
	result := service.PromptAuditDeleteResult{DeletedEvents: deletedEvents, DeletedJobs: deletedJobs}
	recordPromptAuditDeleteLog(c, "删除了提示词安全审计事件", result)
	common.ApiSuccess(c, result)
}

func BatchDeletePromptAuditEvents(c *gin.Context) {
	var req promptAuditBatchDeleteRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_request", "批量删除参数无效")
		return
	}
	result, err := service.DeletePromptAuditByIDs(req.Ids)
	if err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_batch_delete_failed", err.Error())
		return
	}
	recordPromptAuditDeleteLog(c, "批量删除了提示词安全审计事件", *result)
	common.ApiSuccess(c, result)
}

func PreviewDeletePromptAuditEvents(c *gin.Context) {
	var req promptAuditEventFilterRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_request", "删除预览参数无效")
		return
	}
	preview, err := service.PreviewPromptAuditDeleteForActor(req.toModel(), c.GetInt("id"))
	if err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_delete_preview_failed", err.Error())
		return
	}
	common.ApiSuccess(c, preview)
}

func DeletePromptAuditEventsByFilter(c *gin.Context) {
	var req promptAuditConfirmedDeleteRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_invalid_request", "按筛选删除参数无效")
		return
	}
	if !req.Confirm {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_delete_not_confirmed", "必须明确确认按筛选删除")
		return
	}
	result, err := service.DeletePromptAuditByConfirmedFilterForActor(req.Filter.toModel(), req.ConfirmationToken, c.GetInt("id"))
	if err != nil {
		writePromptAuditAdminError(c, http.StatusConflict, "prompt_audit_delete_confirmation_invalid", err.Error())
		return
	}
	recordPromptAuditDeleteLog(c, "按筛选删除了提示词安全审计事件", *result)
	common.ApiSuccess(c, result)
}

func promptAuditFilterFromQuery(c *gin.Context) (model.PromptAuditEventFilter, error) {
	userId, err := promptAuditQueryInt(c, "user_id", 0, 0)
	if err != nil {
		return model.PromptAuditEventFilter{}, err
	}
	tokenId, err := promptAuditQueryInt(c, "token_id", 0, 0)
	if err != nil {
		return model.PromptAuditEventFilter{}, err
	}
	groupId, err := promptAuditQueryInt(c, "group_id", 0, 0)
	if err != nil {
		return model.PromptAuditEventFilter{}, err
	}
	startAt, err := promptAuditQueryInt64(c, "start_at", 0)
	if err != nil {
		return model.PromptAuditEventFilter{}, err
	}
	endAt, err := promptAuditQueryInt64(c, "end_at", 0)
	if err != nil {
		return model.PromptAuditEventFilter{}, err
	}
	if startAt > 0 && endAt > 0 && startAt > endAt {
		return model.PromptAuditEventFilter{}, errors.New("开始时间不能晚于结束时间")
	}
	return model.PromptAuditEventFilter{
		Source: c.Query("source"), Stage: c.Query("stage"),
		Decision: c.Query("decision"), RiskLevel: c.Query("risk_level"), Endpoint: c.Query("endpoint"),
		RequestId: c.Query("request_id"), PromptHash: c.Query("prompt_hash"), Keyword: c.Query("keyword"),
		UserId: userId, TokenId: tokenId, GroupId: groupId, StartAt: startAt, EndAt: endAt,
	}, nil
}

func promptAuditEventId(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		writePromptAuditAdminError(c, http.StatusBadRequest, "prompt_audit_event_id_invalid", "安全审计事件 ID 无效")
		return 0, false
	}
	return id, true
}

func promptAuditQueryInt(c *gin.Context, key string, fallback, max int) (int, error) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 || (max > 0 && value > max) {
		return 0, errors.New("安全审计查询整数参数无效")
	}
	return value, nil
}

func promptAuditQueryInt64(c *gin.Context, key string, fallback int64) (int64, error) {
	raw := strings.TrimSpace(c.Query(key))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("安全审计查询时间参数无效")
	}
	return value, nil
}

func writePromptAuditAdminError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"success": false, "message": message, "code": code})
}

func recordPromptAuditAdminLog(c *gin.Context, content string, details map[string]interface{}) {
	actorId := c.GetInt("id")
	adminInfo := map[string]interface{}{
		"admin_id": actorId, "admin_username": c.GetString("username"),
	}
	for key, value := range details {
		adminInfo[key] = value
	}
	model.RecordLogWithAdminInfo(actorId, model.LogTypeManage, content, adminInfo)
}

func recordPromptAuditDeleteLog(c *gin.Context, content string, result service.PromptAuditDeleteResult) {
	recordPromptAuditAdminLog(c, content, map[string]interface{}{
		"deleted_events": result.DeletedEvents,
		"deleted_jobs":   result.DeletedJobs,
	})
}
