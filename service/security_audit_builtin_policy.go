package service

import (
	"errors"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
)

// SecurityAuditBuiltinPolicy 是无需 Guard 节点即可运行的安全策略管理视图。
// JSON 字符串字段保持与既有屏蔽词编辑器一致，便于无损迁移现有配置。
type SecurityAuditBuiltinPolicy struct {
	ConfigVersion                 int64  `json:"config_version"`
	UpstreamPolicyEnabled         bool   `json:"upstream_policy_enabled"`
	SensitiveWordAuditEnabled     bool   `json:"sensitive_word_audit_enabled"`
	CheckSensitiveEnabled         bool   `json:"check_sensitive_enabled"`
	CheckSensitiveOnPromptEnabled bool   `json:"check_sensitive_on_prompt_enabled"`
	SensitiveWords                string `json:"sensitive_words"`
	SensitiveRules                string `json:"sensitive_rules"`
	SensitiveRuleChannelIds       string `json:"sensitive_rule_channel_ids"`
	UsesLegacySensitiveWords      bool   `json:"uses_legacy_sensitive_words"`
	UpdatedAt                     int64  `json:"updated_at"`
	UpdatedBy                     int    `json:"updated_by"`
}

type SecurityAuditBuiltinPolicyUpdateRequest struct {
	ExpectedConfigVersion         int64   `json:"expected_version"`
	UpstreamPolicyEnabled         *bool   `json:"upstream_policy_enabled"`
	SensitiveWordAuditEnabled     *bool   `json:"sensitive_word_audit_enabled"`
	CheckSensitiveEnabled         *bool   `json:"check_sensitive_enabled"`
	CheckSensitiveOnPromptEnabled *bool   `json:"check_sensitive_on_prompt_enabled"`
	SensitiveRules                *string `json:"sensitive_rules"`
	SensitiveRuleChannelIds       *string `json:"sensitive_rule_channel_ids"`
}

func GetSecurityAuditBuiltinPolicy() (*SecurityAuditBuiltinPolicy, error) {
	row, _, err := model.LoadPromptAuditConfig()
	if err != nil {
		return nil, err
	}
	rulesJSON, _, err := canonicalSecurityAuditSensitiveRules(nil)
	if err != nil {
		return nil, err
	}
	channelIdsJSON, _, err := canonicalSecurityAuditChannelIds(nil)
	if err != nil {
		return nil, err
	}
	return &SecurityAuditBuiltinPolicy{
		ConfigVersion:                 row.ConfigVersion,
		UpstreamPolicyEnabled:         row.UpstreamPolicyEnabled,
		SensitiveWordAuditEnabled:     row.SensitiveWordAuditEnabled,
		CheckSensitiveEnabled:         setting.CheckSensitiveEnabled,
		CheckSensitiveOnPromptEnabled: setting.CheckSensitiveOnPromptEnabled,
		SensitiveWords:                setting.SensitiveWordsToString(),
		SensitiveRules:                rulesJSON,
		SensitiveRuleChannelIds:       channelIdsJSON,
		UsesLegacySensitiveWords:      !setting.SensitiveRulesConfigured && len(setting.SensitiveWords) > 0,
		UpdatedAt:                     row.UpdatedAt,
		UpdatedBy:                     row.UpdatedBy,
	}, nil
}

func SaveSecurityAuditBuiltinPolicy(req SecurityAuditBuiltinPolicyUpdateRequest, actorId int) (*SecurityAuditBuiltinPolicy, error) {
	if req.ExpectedConfigVersion < 1 {
		return nil, errors.New("expected_version 必须大于 0")
	}
	row, _, err := model.LoadPromptAuditConfig()
	if err != nil {
		return nil, err
	}
	if row.ConfigVersion != req.ExpectedConfigVersion {
		return nil, model.ErrPromptAuditConfigConflict
	}

	upstreamPolicyEnabled := row.UpstreamPolicyEnabled
	if req.UpstreamPolicyEnabled != nil {
		upstreamPolicyEnabled = *req.UpstreamPolicyEnabled
	}
	sensitiveWordAuditEnabled := row.SensitiveWordAuditEnabled
	if req.SensitiveWordAuditEnabled != nil {
		sensitiveWordAuditEnabled = *req.SensitiveWordAuditEnabled
	}
	checkSensitiveEnabled := setting.CheckSensitiveEnabled
	if req.CheckSensitiveEnabled != nil {
		checkSensitiveEnabled = *req.CheckSensitiveEnabled
	}
	checkSensitiveOnPromptEnabled := setting.CheckSensitiveOnPromptEnabled
	if req.CheckSensitiveOnPromptEnabled != nil {
		checkSensitiveOnPromptEnabled = *req.CheckSensitiveOnPromptEnabled
	}

	rulesJSON, rules, err := canonicalSecurityAuditSensitiveRules(req.SensitiveRules)
	if err != nil {
		return nil, errors.New("屏蔽词规则格式无效")
	}
	channelIdsJSON, channelIds, err := canonicalSecurityAuditChannelIds(req.SensitiveRuleChannelIds)
	if err != nil {
		return nil, errors.New("屏蔽词渠道范围格式无效")
	}
	summaryJSON, err := common.Marshal(map[string]interface{}{
		"upstream_policy_enabled":           upstreamPolicyEnabled,
		"sensitive_word_audit_enabled":      sensitiveWordAuditEnabled,
		"check_sensitive_enabled":           checkSensitiveEnabled,
		"check_sensitive_on_prompt_enabled": checkSensitiveOnPromptEnabled,
		"sensitive_rule_count":              len(rules),
		"sensitive_rule_channel_count":      len(channelIds),
	})
	if err != nil {
		return nil, err
	}
	if err := model.SavePromptAuditBuiltinPolicy(model.PromptAuditBuiltinPolicyUpdate{
		ExpectedVersion:               req.ExpectedConfigVersion,
		UpstreamPolicyEnabled:         upstreamPolicyEnabled,
		SensitiveWordAuditEnabled:     sensitiveWordAuditEnabled,
		CheckSensitiveEnabled:         checkSensitiveEnabled,
		CheckSensitiveOnPromptEnabled: checkSensitiveOnPromptEnabled,
		SensitiveRules:                rulesJSON,
		SensitiveRuleChannelIds:       channelIdsJSON,
		UpdatedBy:                     actorId,
		ChangeSummary:                 string(summaryJSON),
	}); err != nil {
		return nil, err
	}
	InvalidatePromptAuditConfig()
	return GetSecurityAuditBuiltinPolicy()
}

func canonicalSecurityAuditSensitiveRules(raw *string) (string, []setting.SensitiveRule, error) {
	rules := setting.GetEffectiveSensitiveRules()
	if raw != nil {
		var err error
		rules, err = setting.ParseSensitiveRulesJSONString(*raw)
		if err != nil {
			return "", nil, err
		}
	}
	rules = setting.NormalizeSensitiveRules(rules)
	if rules == nil {
		rules = make([]setting.SensitiveRule, 0)
	}
	encoded, err := common.Marshal(setting.SensitiveRuleConfig{Rules: rules})
	if err != nil {
		return "", nil, err
	}
	return string(encoded), rules, nil
}

func canonicalSecurityAuditChannelIds(raw *string) (string, []int, error) {
	channelIds := setting.NormalizeSensitiveRuleChannelIds(setting.SensitiveRuleChannelIds)
	if raw != nil {
		var err error
		channelIds, err = setting.ParseSensitiveRuleChannelIdsJSONString(*raw)
		if err != nil {
			return "", nil, err
		}
	}
	if channelIds == nil {
		channelIds = make([]int, 0)
	}
	encoded, err := common.Marshal(channelIds)
	if err != nil {
		return "", nil, err
	}
	return string(encoded), channelIds, nil
}
