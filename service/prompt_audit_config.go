package service

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

func GetPublicPromptAuditConfig() (*PromptAuditConfig, error) {
	row, endpoints, err := model.LoadPromptAuditConfig()
	if err != nil {
		return nil, err
	}
	cfg, err := promptAuditConfigFromModels(row, endpoints, false)
	if cfg == nil {
		return nil, err
	}
	// 公共管理视图不需要解密节点令牌。密钥缺失或已轮换时仍应允许
	// Root 打开页面并看到 unreadable 状态，以便关闭审计或清除旧令牌；
	// 请求热路径仍会保留该解密错误并在 blocking 模式下 fail-closed。
	return PublicPromptAuditConfig(cfg), nil
}

func SavePromptAuditConfig(req PromptAuditUpdateRequest, actorId int) (*PromptAuditConfig, error) {
	if strings.TrimSpace(req.Mode) != "" {
		switch strings.ToLower(strings.TrimSpace(req.Mode)) {
		case PromptAuditModeOff:
			req.Enabled, req.BlockingEnabled = false, false
		case PromptAuditModeAsync:
			req.Enabled, req.BlockingEnabled = true, false
		case PromptAuditModeBlocking:
			req.Enabled, req.BlockingEnabled = true, true
		default:
			return nil, errors.New("安全审计 mode 仅支持 off、async_audit 或 blocking")
		}
	}
	if err := validatePromptAuditUpdate(req); err != nil {
		return nil, err
	}
	currentRow, currentEndpoints, err := model.LoadPromptAuditConfig()
	if err != nil {
		return nil, err
	}
	if currentRow.ConfigVersion != req.ExpectedConfigVersion {
		return nil, model.ErrPromptAuditConfigConflict
	}
	upstreamPolicyEnabled := currentRow.UpstreamPolicyEnabled
	if req.UpstreamPolicyEnabled != nil {
		upstreamPolicyEnabled = *req.UpstreamPolicyEnabled
	}
	sensitiveWordAuditEnabled := currentRow.SensitiveWordAuditEnabled
	if req.SensitiveWordAuditEnabled != nil {
		sensitiveWordAuditEnabled = *req.SensitiveWordAuditEnabled
	}
	currentById := make(map[string]model.PromptAuditEndpoint, len(currentEndpoints))
	for _, endpoint := range currentEndpoints {
		currentById[endpoint.Id] = endpoint
	}

	scanners := canonicalPromptAuditScanners(req.Scanners)
	groups := canonicalPromptAuditGroupIds(req.GroupIds)
	scannerJson, err := common.Marshal(scanners)
	if err != nil {
		return nil, err
	}
	groupJson, err := common.Marshal(groups)
	if err != nil {
		return nil, err
	}
	summaryJson, err := common.Marshal(map[string]interface{}{
		"enabled": req.Enabled, "blocking_enabled": req.BlockingEnabled,
		"store_pass_events":            req.StorePassEvents,
		"upstream_policy_enabled":      upstreamPolicyEnabled,
		"sensitive_word_audit_enabled": sensitiveWordAuditEnabled,
		"endpoint_count":               len(req.Endpoints),
		"scanner_count":                len(scanners), "all_groups": req.AllGroups, "group_count": len(groups),
	})
	if err != nil {
		return nil, err
	}
	row := &model.PromptAuditConfig{
		Id: model.PromptAuditConfigID, Enabled: req.Enabled, BlockingEnabled: req.BlockingEnabled,
		StorePassEvents: req.StorePassEvents, UpstreamPolicyEnabled: upstreamPolicyEnabled,
		SensitiveWordAuditEnabled: sensitiveWordAuditEnabled,
		Strategy:                  "priority", WorkerCount: req.WorkerCount,
		QueueCapacity: req.QueueCapacity, RetentionDays: req.RetentionDays,
		Scanners: string(scannerJson), AllGroups: req.AllGroups, GroupIds: string(groupJson),
		UpdatedBy: actorId, ChangeSummary: string(summaryJson),
	}
	now := time.Now().Unix()
	endpointRows := make([]model.PromptAuditEndpoint, 0, len(req.Endpoints))
	for priority, input := range req.Endpoints {
		input.Id = strings.TrimSpace(input.Id)
		input.Name = strings.TrimSpace(input.Name)
		input.Model = strings.TrimSpace(input.Model)
		input.TokenAction = strings.ToLower(strings.TrimSpace(input.TokenAction))
		normalizedUrl, normalizeErr := NormalizePromptAuditBaseURL(input.BaseUrl)
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		existing := currentById[input.Id]
		tokenCiphertext := existing.TokenCiphertext
		switch input.TokenAction {
		case PromptAuditTokenKeep:
			// 已保存的令牌只允许绑定到原节点地址。否则持有 Root 会话但
			// 不知道令牌明文的一方，可以把地址改到受控服务并借 keep
			// 操作外带旧令牌。地址变化时必须显式替换或清除令牌。
			if tokenCiphertext != "" {
				existingURL, existingErr := NormalizePromptAuditBaseURL(existing.BaseUrl)
				if existingErr != nil || existingURL != normalizedUrl {
					return nil, errors.New("Guard 节点地址变化时必须显式替换或清除令牌")
				}
			}
		case PromptAuditTokenClear:
			tokenCiphertext = ""
		case PromptAuditTokenReplace:
			if !PromptAuditCryptoReady() {
				return nil, errors.New("保存 Guard 节点令牌前必须显式配置 CRYPTO_SECRET")
			}
			tokenCiphertext, err = EncryptPromptAuditSecret(strings.TrimSpace(input.Token))
			if err != nil {
				return nil, err
			}
		}
		createdAt := existing.CreatedAt
		if createdAt == 0 {
			createdAt = now
		}
		endpointRows = append(endpointRows, model.PromptAuditEndpoint{
			Id: input.Id, Name: input.Name, Protocol: "openai_compatible",
			BaseUrl: normalizedUrl, Model: defaultPromptAuditString(input.Model, PromptAuditDefaultModel),
			TokenCiphertext: tokenCiphertext, TimeoutMs: input.TimeoutMs, InputLimit: input.InputLimit,
			Enabled: input.Enabled, Priority: priority, CreatedAt: createdAt, UpdatedAt: now,
		})
	}
	if req.Enabled {
		for _, endpoint := range endpointRows {
			if !endpoint.Enabled || endpoint.TokenCiphertext == "" {
				continue
			}
			if _, err := DecryptPromptAuditSecret(endpoint.TokenCiphertext); err != nil {
				return nil, errors.New("启用提示词安全审计前必须确认现有 Guard 节点令牌可解密")
			}
		}
	}
	if err := model.SavePromptAuditConfig(req.ExpectedConfigVersion, row, endpointRows); err != nil {
		return nil, err
	}
	InvalidatePromptAuditConfig()
	return GetPublicPromptAuditConfig()
}

func validatePromptAuditUpdate(req PromptAuditUpdateRequest) error {
	if req.ExpectedConfigVersion < 1 {
		return errors.New("expected_version 必须大于 0")
	}
	if req.BlockingEnabled && !req.Enabled {
		return errors.New("开启同步阻断前必须先启用提示词安全审计")
	}
	if req.Strategy != "" && req.Strategy != "priority" {
		return errors.New("安全审计节点策略仅支持 priority")
	}
	if req.WorkerCount < 1 || req.WorkerCount > 32 {
		return errors.New("Worker 数量必须在 1 到 32 之间")
	}
	if req.QueueCapacity < 1 || req.QueueCapacity > 100000 {
		return errors.New("队列容量必须在 1 到 100000 之间")
	}
	if req.RetentionDays < 1 || req.RetentionDays > 365 {
		return errors.New("事件保留天数必须在 1 到 365 之间")
	}
	if len(canonicalPromptAuditScanners(req.Scanners)) == 0 {
		return errors.New("至少需要启用一个风险分类")
	}
	if !req.AllGroups {
		groups := canonicalPromptAuditGroupIds(req.GroupIds)
		if len(groups) == 0 {
			return errors.New("指定分组模式至少需要选择一个分组")
		}
		found, err := model.GetGroupsByIds(groups)
		if err != nil {
			return err
		}
		if len(found) != len(groups) {
			return errors.New("安全审计分组包含不存在的 ID")
		}
	}
	seen := make(map[string]struct{}, len(req.Endpoints))
	enabled := 0
	for _, endpoint := range req.Endpoints {
		endpoint.Id = strings.TrimSpace(endpoint.Id)
		endpoint.Name = strings.TrimSpace(endpoint.Name)
		endpoint.Model = strings.TrimSpace(endpoint.Model)
		endpoint.TokenAction = strings.ToLower(strings.TrimSpace(endpoint.TokenAction))
		if endpoint.Id == "" || len(endpoint.Id) > 64 || endpoint.Name == "" || utf8.RuneCountInString(endpoint.Name) > 128 {
			return errors.New("Guard 节点 ID 和名称不能为空")
		}
		if utf8.RuneCountInString(endpoint.Model) > 255 {
			return errors.New("Guard 节点模型名称不能超过 255 个字符")
		}
		if len(endpoint.Token) > 8192 {
			return errors.New("Guard 节点令牌长度不能超过 8192 个字符")
		}
		token := strings.TrimSpace(endpoint.Token)
		switch endpoint.TokenAction {
		case PromptAuditTokenKeep, PromptAuditTokenClear:
			if token != "" {
				return errors.New("Guard 节点令牌仅允许在 replace 操作中提交")
			}
		case PromptAuditTokenReplace:
			if token == "" {
				return errors.New("replace 操作必须提供 Guard 节点令牌")
			}
		default:
			return errors.New("Guard 节点 token_action 仅支持 keep、replace 或 clear")
		}
		if _, exists := seen[endpoint.Id]; exists {
			return errors.New("Guard 节点 ID 不能重复")
		}
		seen[endpoint.Id] = struct{}{}
		if endpoint.Protocol != "" && endpoint.Protocol != "openai_compatible" {
			return errors.New("Guard 节点仅支持 openai_compatible 协议")
		}
		if _, err := NormalizePromptAuditBaseURL(endpoint.BaseUrl); err != nil {
			return err
		}
		if endpoint.TimeoutMs < 100 || endpoint.TimeoutMs > 30000 {
			return errors.New("Guard 节点超时必须在 100 到 30000 毫秒之间")
		}
		if endpoint.InputLimit < 128 || endpoint.InputLimit > 100000 {
			return errors.New("Guard 节点输入上限必须在 128 到 100000 字符之间")
		}
		if endpoint.Enabled {
			enabled++
		}
	}
	if req.Enabled {
		if !PromptAuditCryptoReady() {
			return errors.New("启用提示词安全审计前必须显式配置 CRYPTO_SECRET")
		}
		if enabled == 0 {
			return errors.New("启用提示词安全审计前至少需要一个启用的 Guard 节点")
		}
	}
	return nil
}

func canonicalPromptAuditScanners(values []string) []string {
	allowed := make(map[string]struct{}, len(PromptAuditScannerIDs))
	for _, scanner := range PromptAuditScannerIDs {
		allowed[scanner] = struct{}{}
	}
	selected := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized := NormalizePromptAuditCategory(value)
		if _, ok := allowed[normalized]; ok {
			selected[normalized] = struct{}{}
		}
	}
	result := make([]string, 0, len(selected))
	for _, scanner := range PromptAuditScannerIDs {
		if _, ok := selected[scanner]; ok {
			result = append(result, scanner)
		}
	}
	return result
}

func canonicalPromptAuditGroupIds(values []int) []int {
	seen := make(map[int]struct{}, len(values))
	result := make([]int, 0, len(values))
	for _, value := range values {
		if value <= 0 {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Ints(result)
	return result
}

func defaultPromptAuditString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}

func NormalizePromptAuditBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", errors.New("Guard 节点地址无效")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("Guard 节点仅支持 HTTP(S)")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("Guard 节点地址不能包含凭据、查询参数或片段")
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return "", errors.New("Guard 节点地址缺少主机名")
	}
	if isForbiddenPromptAuditHostname(host) {
		return "", errors.New("Guard 节点不能指向云元数据或 link-local 地址")
	}
	// url.Parse 已将 Path 解码为语义路径；把 EscapedPath 直接写回
	// parsed.Path 会让 url.URL.String 再次转义百分号，导致例如
	// `/guard%20node` 被错误规范化为 `/guard%2520node`。使用解码后的
	// Path，并清空 RawPath，让 String 只执行一次规范转义。
	path := strings.TrimRight(parsed.Path, "/")
	if strings.EqualFold(path, "/v1") {
		path = ""
	}
	parsed.Path = path
	parsed.RawPath = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func PromptAuditChatCompletionsURL(baseUrl string) (string, error) {
	normalized, err := NormalizePromptAuditBaseURL(baseUrl)
	if err != nil {
		return "", err
	}
	return normalized + "/v1/chat/completions", nil
}

// PromptAuditModelsURL 返回节点能力探测使用的 OpenAI 兼容模型列表地址。
// 与聊天地址共用同一套规范化和 SSRF 校验，避免探测路径绕过节点安全边界。
func PromptAuditModelsURL(baseUrl string) (string, error) {
	normalized, err := NormalizePromptAuditBaseURL(baseUrl)
	if err != nil {
		return "", err
	}
	return normalized + "/v1/models", nil
}

func isForbiddenPromptAuditHostname(host string) bool {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	switch lower {
	case "metadata", "metadata.google.internal", "metadata.azure.internal", "instance-data", "instance-data.ec2.internal":
		return true
	}
	ip := net.ParseIP(lower)
	return ip != nil && isForbiddenPromptAuditIP(ip)
}

func isForbiddenPromptAuditIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		value := v4.String()
		return v4[0] == 169 && v4[1] == 254 || value == "100.100.100.200" || value == "168.63.129.16"
	}
	// AWS IMDS 的 IPv6 地址。
	if strings.EqualFold(ip.String(), "fd00:ec2::254") {
		return true
	}
	return false
}

func promptAuditConfigConflictError(err error) error {
	if errors.Is(err, model.ErrPromptAuditConfigConflict) {
		return fmt.Errorf("%s: 配置已被其他管理员更新", PromptAuditConfigConflictCode)
	}
	return err
}
