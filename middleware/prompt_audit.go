package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
)

const promptAuditCheckedContextKey = "prompt_security_audit_checked"

// PromptAudit 在渠道分配前完成提示词审计，因此同步阻断不会占用渠道并发、
// 触发预扣费或建立上游连接。无文本请求和关闭模式保持原行为。
func PromptAudit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil {
			return
		}
		if c.Request == nil || !promptAuditRequestMayContainText(c.Request.Method) {
			c.Next()
			return
		}
		if checked, ok := c.Get(promptAuditCheckedContextKey); ok && checked == true {
			c.Next()
			return
		}
		cfg, cfgErr := service.GetPromptAuditConfig(c.Request.Context())
		mode := service.PromptAuditEffectiveMode(cfg)
		// 配置读取失败且没有可用的旧快照时无法判断当前模式；按同步门禁
		// 的 fail-closed 语义拒绝请求，避免数据库短暂故障把已启用的阻断
		// 策略退化成放行。若仍有旧快照，则下面按其模式处理：async 继续
		// 放行并记录丢弃，blocking 继续拒绝，off 保持关闭语义。
		if cfg == nil && cfgErr != nil {
			writePromptAuditRelayError(c, service.PromptAuditDecision{
				Allow: false, ErrorCode: service.PromptGuardUnavailableCode,
				HTTPStatus: http.StatusServiceUnavailable,
				Message:    "提示词安全审计配置暂时不可用",
			})
			return
		}
		if cfgErr != nil && mode == service.PromptAuditModeBlocking {
			writePromptAuditRelayError(c, service.PromptAuditDecision{
				Allow: false, ErrorCode: service.PromptGuardUnavailableCode,
				HTTPStatus: http.StatusServiceUnavailable,
				Message:    "提示词安全审计配置暂时不可用",
			})
			return
		}
		sensitiveActive := service.ShouldCheckSensitiveBeforeDistribution(c)
		// 先保存客户端进入系统时的文本快照。后续敏感词 mask 可以继续修改
		// 实际转发正文，但 Guard、哈希和加密事件必须基于修改前的原始文本。
		body, modelName, requestedGroup, bodyErr := promptAuditBodySnapshot(c)
		if bodyErr != nil {
			// 未启用前置屏蔽词时，快照失败仍按 Guard 模式处理。只要前置
			// 屏蔽词已启用，就必须在渠道分配前返回请求错误，不能退回到
			// 渠道分配后的旧检查路径。
			if !sensitiveActive && mode == service.PromptAuditModeOff {
				c.Next()
				return
			}
			if !sensitiveActive && service.PromptAuditEffectiveMode(cfg) == service.PromptAuditModeAsync {
				service.RecordPromptAuditDropped()
				c.Next()
				return
			}
			status := http.StatusBadRequest
			if common.IsRequestBodyTooLargeError(bodyErr) || errors.Is(bodyErr, common.ErrRequestBodyTooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			c.AbortWithStatusJSON(status, gin.H{"error": types.OpenAIError{
				Message: "提示词安全审计无法读取请求正文", Type: string(types.ErrorTypeNewAPIError),
				Param: "", Code: types.ErrorCodeInvalidRequest,
			}})
			return
		}
		// 无论 Guard 是否启用，都先保留请求生命周期内的原始文本快照。
		// 屏蔽词 mask 后的正文和上游 cyber_policy 事件均复用这份快照。
		protocol, provider := inferPromptAuditProtocol(c.Request.URL.Path)
		baseSnapshot, baseSnapshotErr := service.ExtractPromptAuditSnapshot(service.PromptAuditRequest{
			RequestId: c.GetString(common.RequestIdKey),
			UserId:    common.GetContextKeyInt(c, constant.ContextKeyUserId),
			Username:  common.GetContextKeyString(c, constant.ContextKeyUserName),
			UserEmail: common.GetContextKeyString(c, constant.ContextKeyUserEmail),
			TokenId:   common.GetContextKeyInt(c, constant.ContextKeyTokenId),
			TokenName: c.GetString("token_name"),
			GroupId:   common.GetContextKeyInt(c, constant.ContextKeyUserGroupId),
			GroupName: common.GetContextKeyString(c, constant.ContextKeyUsingGroup),
			Provider:  provider,
			Endpoint:  c.Request.URL.Path,
			Protocol:  protocol,
			Model:     modelName,
			Body:      body,
			Stage:     "request",
		})
		if baseSnapshotErr == nil {
			service.SetSecurityAuditRequestSnapshot(c, baseSnapshot)
		}
		filterResult, filterErr := service.ApplySensitiveFilterToRequestBodyBeforeDistribution(
			c, inferPromptAuditRelayFormat(c.Request.URL.Path),
		)
		if filterErr != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": types.OpenAIError{
				Message: filterErr.Error(), Type: string(types.ErrorTypeNewAPIError),
				Param: "", Code: types.ErrorCodeInvalidRequest,
			}})
			return
		}
		if filterResult.Blocked {
			// 前置门禁日志只保留命中数量。规则命中值来自客户端提示词，
			// 不能因为安全审计提前执行现有敏感词规则而写入运行日志。
			logger.LogWarn(c, fmt.Sprintf("user sensitive request blocked before prompt guard: %d rule(s) matched",
				len(filterResult.Matches)))
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": service.NewSensitiveFilterAPIError(c).ToOpenAIError(),
			})
			return
		}
		if mode == service.PromptAuditModeOff {
			// Guard 关闭不影响内置屏蔽词和上游策略事件；屏蔽词已经在
			// 渠道分配前执行，后续 Relay 会通过上下文标记避免重复过滤。
			c.Next()
			return
		}

		shouldAudit, groupId, groupName := promptAuditResolveGroupScope(c, cfg, requestedGroup)
		if !shouldAudit {
			c.Next()
			return
		}
		protocol, provider = inferPromptAuditProtocol(c.Request.URL.Path)
		snapshot, snapshotErr := service.ExtractPromptAuditSnapshot(service.PromptAuditRequest{
			RequestId: c.GetString(common.RequestIdKey),
			UserId:    common.GetContextKeyInt(c, constant.ContextKeyUserId),
			Username:  common.GetContextKeyString(c, constant.ContextKeyUserName),
			UserEmail: common.GetContextKeyString(c, constant.ContextKeyUserEmail),
			TokenId:   common.GetContextKeyInt(c, constant.ContextKeyTokenId),
			TokenName: c.GetString("token_name"),
			GroupId:   groupId,
			GroupName: groupName,
			Provider:  provider,
			Endpoint:  c.Request.URL.Path,
			Protocol:  protocol,
			Model:     modelName,
			Body:      body,
			Stage:     "http",
		})
		if errors.Is(snapshotErr, service.ErrPromptAuditNoText) {
			c.Set(promptAuditCheckedContextKey, true)
			c.Next()
			return
		}
		if snapshotErr != nil {
			if service.PromptAuditEffectiveMode(cfg) == service.PromptAuditModeAsync {
				service.RecordPromptAuditDropped()
				c.Next()
				return
			}
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": types.OpenAIError{
				Message: "提示词安全审计请求格式无效", Type: string(types.ErrorTypeNewAPIError),
				Param: "", Code: types.ErrorCodeInvalidRequest,
			}})
			return
		}

		decision := service.AuditPromptSnapshot(c.Request.Context(), snapshot)
		if !decision.Allow {
			writePromptAuditRelayError(c, decision)
			return
		}
		c.Set(promptAuditCheckedContextKey, true)
		c.Next()
	}
}

func promptAuditRequestMayContainText(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

func promptAuditConfigIncludesGroup(cfg *service.PromptAuditConfig, groupId int) bool {
	if cfg == nil || cfg.AllGroups {
		return true
	}
	for _, configured := range cfg.GroupIds {
		if configured == groupId {
			return true
		}
	}
	return false
}

// promptAuditResolveGroupScope 在渠道分配前根据令牌的候选分组决定是否审计。
// 显式多分组只要任一候选分组命中策略就必须审计；auto 或无法可靠解析的
// 分组采用安全默认值直接审计，避免退回用户默认分组后产生绕过。
func promptAuditResolveGroupScope(c *gin.Context, cfg *service.PromptAuditConfig, requestedGroups ...string) (bool, int, string) {
	if c == nil || cfg == nil {
		return true, 0, "pre_allocation:unknown"
	}
	requestedGroup := ""
	if len(requestedGroups) > 0 {
		requestedGroup = strings.TrimSpace(requestedGroups[0])
	}
	if requestedGroup != "" {
		if strings.EqualFold(requestedGroup, "auto") {
			return true, 0, promptAuditPreallocationGroupName("auto")
		}
		group, err := model.GetGroupByCodeOrAlias(requestedGroup)
		if err != nil || group == nil {
			// 分组参数稍后仍由渠道分配流程做权限校验；这里不能因为解析失败而跳过审计。
			return true, 0, promptAuditPreallocationGroupName(requestedGroup)
		}
		if cfg.AllGroups || promptAuditConfigIncludesGroup(cfg, group.Id) {
			return true, group.Id, promptAuditPreallocationGroupName(group.Code)
		}
		return false, 0, ""
	}
	userGroupId := common.GetContextKeyInt(c, constant.ContextKeyUserGroupId)
	userGroup := strings.TrimSpace(common.GetContextKeyString(c, constant.ContextKeyUserGroup))
	usingGroup := strings.TrimSpace(common.GetContextKeyString(c, constant.ContextKeyUsingGroup))
	tokenGroup := strings.TrimSpace(common.GetContextKeyString(c, constant.ContextKeyTokenGroup))
	mode := strings.ToLower(strings.TrimSpace(common.GetContextKeyString(c, constant.ContextKeyTokenGroupMode)))
	candidateIds, _ := common.GetContextKeyType[[]int](c, constant.ContextKeyTokenGroupIds)
	candidateIds = append([]int(nil), candidateIds...)

	if usingGroup == "" {
		usingGroup = userGroup
	}
	if tokenGroup == "" {
		tokenGroup = usingGroup
	}
	if strings.EqualFold(usingGroup, "auto") || strings.EqualFold(tokenGroup, "auto") || mode == "auto" {
		return true, 0, promptAuditPreallocationGroupName("auto")
	}

	codes := promptAuditGroupCodes(tokenGroup)
	if len(candidateIds) > 0 {
		if cfg.AllGroups {
			if len(candidateIds) == 1 {
				return true, candidateIds[0], promptAuditPreallocationGroupName(promptAuditGroupCodeAt(codes, 0))
			}
			return true, 0, promptAuditPreallocationGroupName(strings.Join(codes, ","))
		}
		for index, candidateId := range candidateIds {
			if promptAuditConfigIncludesGroup(cfg, candidateId) {
				return true, candidateId, promptAuditPreallocationGroupName(promptAuditGroupCodeAt(codes, index))
			}
		}
		return false, 0, ""
	}

	// Canvas 和部分旧版令牌只携带可读分组 code，没有稳定的 group_id。
	// 对单分组或可完整解析的多分组先解析真实 ID，避免把明确不在策略
	// 范围内的 Canvas 请求过度审计；解析失败仍保持 fail-safe。
	lookupValue := tokenGroup
	if lookupValue == "" {
		lookupValue = usingGroup
	}
	lookupCodes := promptAuditGroupCodes(lookupValue)
	// 没有令牌上下文时（旧版 Playground/Canvas 会如此），usingGroup
	// 就是鉴权阶段写入的用户默认分组。此时优先使用稳定的 user_group_id，
	// 不要为了把旧 code 解析成实体而依赖 groups 表；否则仅有用户表的
	// 兼容数据库会被误判成“无法解析”，进而丢失稳定分组 ID。
	isInheritedUserGroup := (mode == "" || mode == "inherit") &&
		strings.EqualFold(usingGroup, userGroup) &&
		(strings.TrimSpace(tokenGroup) == "" || strings.EqualFold(tokenGroup, usingGroup))
	canResolveExplicit := len(lookupCodes) > 0 && !isInheritedUserGroup
	if canResolveExplicit && model.DB != nil {
		var unresolved bool
		for index, code := range lookupCodes {
			group, err := model.GetGroupByCodeOrAlias(code)
			if err != nil || group == nil {
				unresolved = true
				continue
			}
			if cfg.AllGroups || promptAuditConfigIncludesGroup(cfg, group.Id) {
				return true, group.Id, promptAuditPreallocationGroupName(promptAuditGroupCodeAt(lookupCodes, index))
			}
		}
		if !unresolved {
			return false, 0, ""
		}
		return true, 0, promptAuditPreallocationGroupName(lookupValue)
	}

	// inherit 模式可稳定使用用户默认分组。旧数据或未知模式若已改变
	// usingGroup 却没有稳定 ID，则按 fail-safe 审计并明确标记为预分配值。
	if mode == "" || mode == "inherit" {
		// tokenGroup 可能仍携带旧版多分组字符串；没有稳定候选 ID 时，
		// 不能把它误当成用户默认分组，否则会跳过实际命中的策略范围。
		if usingGroup == "" || (strings.EqualFold(usingGroup, userGroup) &&
			(tokenGroup == "" || strings.EqualFold(tokenGroup, usingGroup))) {
			// 滚动升级期间旧 Redis 用户缓存可能尚无 group_id。此时
			// 不能用零值判断为“不在审计范围”，必须按 fail-safe 审计。
			if userGroupId <= 0 {
				return true, 0, promptAuditPreallocationGroupName(userGroup)
			}
			return cfg.AllGroups || promptAuditConfigIncludesGroup(cfg, userGroupId), userGroupId, userGroup
		}
	}
	preallocationGroup := usingGroup
	if tokenGroup != "" && !strings.EqualFold(tokenGroup, usingGroup) {
		preallocationGroup = tokenGroup
	}
	return true, 0, promptAuditPreallocationGroupName(preallocationGroup)
}

func promptAuditGroupCodes(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func promptAuditGroupCodeAt(codes []string, index int) string {
	if index >= 0 && index < len(codes) {
		return codes[index]
	}
	return "unknown"
}

func promptAuditPreallocationGroupName(value string) string {
	runes := []rune("pre_allocation:" + strings.TrimSpace(value))
	if len(runes) > 128 {
		runes = runes[:128]
	}
	return string(runes)
}

func promptAuditBodySnapshot(c *gin.Context) ([]byte, string, string, error) {
	var document interface{}
	contentType := c.Request.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(contentType)
	mediaType = strings.ToLower(strings.TrimSpace(mediaType))
	switch {
	case mediaType == "application/x-www-form-urlencoded", mediaType == "multipart/form-data":
		form := map[string]interface{}{}
		if err := common.UnmarshalBodyReusable(c, &form); err != nil {
			return nil, "", "", err
		}
		document = form
	default:
		storage, err := common.GetBodyStorage(c)
		if err != nil {
			return nil, "", "", err
		}
		raw, err := storage.Bytes()
		if err != nil {
			return nil, "", "", err
		}
		// 无论正文是否需要解析，都要把共享正文游标复位，保证后续
		// Relay/渠道适配器仍能读取原始请求体。
		restoreBody := func() error {
			if _, seekErr := storage.Seek(0, io.SeekStart); seekErr != nil {
				return seekErr
			}
			c.Request.Body = io.NopCloser(storage)
			return nil
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			if err := restoreBody(); err != nil {
				return nil, "", "", err
			}
			return []byte("{}"), "", "", nil
		}
		isJSON := mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
		switch {
		case isJSON:
			// 明确声明 JSON 时保持严格语义：畸形 JSON 在 blocking 模式
			// 下应返回请求错误，而不是把未解析正文静默放行。
			if err := common.Unmarshal(raw, &document); err != nil {
				if restoreErr := restoreBody(); restoreErr != nil {
					return nil, "", "", restoreErr
				}
				return nil, "", "", err
			}
		case strings.HasPrefix(mediaType, "text/"):
			// 纯文本接口没有统一的 JSON 外壳，包装成 prompt 供 Guard
			// 审计；原始正文仍保持不变并交给后续上游处理。
			document = map[string]interface{}{"prompt": string(raw)}
		case mediaType == "":
			// 缺少 Content-Type 时，先兼容可识别的 JSON；其余正文只
			// 在确实像文本时审计。这样不会把无类型的音频/图片/压缩
			// 数据误判成 JSON 错误或阻断请求。
			if err := common.Unmarshal(raw, &document); err != nil {
				if promptAuditLikelyText(raw) {
					document = map[string]interface{}{"prompt": string(raw)}
				} else {
					document = map[string]interface{}{}
				}
			}
		default:
			// 音频、图片、视频和其他二进制媒体本身不属于文本 Guard
			// 范围。只返回空审计文档，不尝试 JSON 解码。
			document = map[string]interface{}{}
		}
		if err := restoreBody(); err != nil {
			return nil, "", "", err
		}
	}
	modelName, requestedGroup := "", ""
	if root, ok := document.(map[string]interface{}); ok {
		modelName, _ = root["model"].(string)
		// 只有 Playground 会在渠道分配阶段接受正文中的 group 覆盖。
		// 其余协议即使出现同名业务字段，也不能改变审计分组范围。
		if strings.HasPrefix(strings.ToLower(c.Request.URL.Path), "/pg/") {
			requestedGroup, _ = root["group"].(string)
		}
	}
	if modelName == "" {
		modelName = c.Query("model")
	}
	if modelName == "" && c.Request.URL != nil {
		modelName = promptAuditModelFromPath(c.Request.URL.Path)
	}
	encoded, err := common.Marshal(document)
	return encoded, modelName, requestedGroup, err
}

// promptAuditLikelyText 判断未声明媒体类型的正文是否适合按文本审计。
// 需要拒绝 NUL 和其他控制字符，避免压缩/音频等二进制偶然通过 UTF-8
// 校验后被转换成巨大、无意义的提示词。
func promptAuditLikelyText(raw []byte) bool {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return false
	}
	return bytes.IndexFunc(raw, func(r rune) bool {
		return (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f
	}) < 0
}

func promptAuditModelFromPath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for index, part := range parts {
		lower := strings.ToLower(part)
		if lower != "models" && lower != "engines" {
			continue
		}
		if index+1 >= len(parts) || strings.TrimSpace(parts[index+1]) == "" {
			continue
		}
		modelName := parts[index+1]
		if colon := strings.IndexByte(modelName, ':'); colon >= 0 {
			modelName = modelName[:colon]
		}
		if decoded, err := url.PathUnescape(modelName); err == nil {
			modelName = decoded
		}
		return strings.TrimSpace(modelName)
	}
	return ""
}

func inferPromptAuditProtocol(path string) (string, string) {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/messages"):
		return "anthropic_messages", "anthropic"
	case strings.Contains(lower, "/responses"):
		return "openai_responses", "openai"
	case strings.Contains(lower, "/v1beta/models/") ||
		strings.Contains(lower, "/v1/models/") || strings.Contains(lower, "/engines/"):
		return "gemini", "gemini"
	case strings.Contains(lower, "/chat/completions"):
		return "openai_chat_completions", "openai"
	case strings.HasSuffix(lower, "/completions"):
		return "openai_completions", "openai"
	case strings.Contains(lower, "/embeddings"):
		return "embeddings", "openai"
	case strings.Contains(lower, "/rerank"):
		return "rerank", "openai"
	case strings.Contains(lower, "/moderations"):
		return "embedding", "openai"
	case strings.Contains(lower, "/images/") || strings.HasSuffix(lower, "/edits"):
		return "openai_images", "openai"
	case strings.Contains(lower, "/audio/"):
		return "audio", "openai"
	case strings.Contains(lower, "/suno/"):
		return "task", "suno"
	case strings.Contains(lower, "/mj/"):
		return "task", "midjourney"
	case strings.Contains(lower, "/video") || strings.Contains(lower, "/kling/") || strings.Contains(lower, "/jimeng"):
		return "video", "video"
	default:
		return "openai_chat_completions", "openai"
	}
}

func inferPromptAuditRelayFormat(path string) types.RelayFormat {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/messages"):
		return types.RelayFormatClaude
	case strings.Contains(lower, "/responses/compact"):
		return types.RelayFormatOpenAIResponsesCompaction
	case strings.Contains(lower, "/responses"):
		return types.RelayFormatOpenAIResponses
	case strings.Contains(lower, "/v1beta/models/") ||
		strings.Contains(lower, "/v1/models/") || strings.Contains(lower, "/engines/"):
		return types.RelayFormatGemini
	case strings.Contains(lower, "/embeddings"):
		return types.RelayFormatEmbedding
	case strings.Contains(lower, "/rerank"):
		return types.RelayFormatRerank
	case strings.Contains(lower, "/images/") || strings.HasSuffix(lower, "/edits"):
		return types.RelayFormatOpenAIImage
	case strings.Contains(lower, "/audio/"):
		return types.RelayFormatOpenAIAudio
	case strings.Contains(lower, "/suno/") || strings.Contains(lower, "/mj/") ||
		strings.Contains(lower, "/video") || strings.Contains(lower, "/kling/") ||
		strings.Contains(lower, "/jimeng"):
		return types.RelayFormatTask
	default:
		return types.RelayFormatOpenAI
	}
}

func writePromptAuditRelayError(c *gin.Context, decision service.PromptAuditDecision) {
	status := decision.HTTPStatus
	if status == 0 {
		status = http.StatusServiceUnavailable
	}
	message := strings.TrimSpace(decision.Message)
	if message == "" {
		message = "提示词安全审计服务暂时不可用"
	}
	c.AbortWithStatusJSON(status, gin.H{"error": types.OpenAIError{
		Message: message, Type: string(types.ErrorTypeNewAPIError), Param: "", Code: decision.ErrorCode,
	}})
}
