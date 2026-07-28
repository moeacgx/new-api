package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	PromptAuditOptionCheckSensitiveEnabled         = "CheckSensitiveEnabled"
	PromptAuditOptionCheckSensitiveOnPromptEnabled = "CheckSensitiveOnPromptEnabled"
	PromptAuditOptionSensitiveRules                = "SensitiveRules"
	PromptAuditOptionSensitiveRuleChannelIds       = "SensitiveRuleChannelIds"
)

// PromptAuditBuiltinPolicyUpdate 把无需 Guard 的审计开关与既有屏蔽词
// Option 作为一个版本化配置快照提交。SensitiveWords 属于只读旧配置，
// 迁移为规则后仍保留原值，避免保存页面时隐式删除用户数据。
type PromptAuditBuiltinPolicyUpdate struct {
	ExpectedVersion               int64
	UpstreamPolicyEnabled         bool
	SensitiveWordAuditEnabled     bool
	CheckSensitiveEnabled         bool
	CheckSensitiveOnPromptEnabled bool
	SensitiveRules                string
	SensitiveRuleChannelIds       string
	UpdatedBy                     int
	ChangeSummary                 string
}

// SavePromptAuditBuiltinPolicy 使用 prompt_audit_configs.config_version 做
// CAS，并在同一个数据库事务中保存审计开关和屏蔽词 Option。这样前端不会
// 看到“开关已更新但规则仍是旧值”的半提交状态。
func SavePromptAuditBuiltinPolicy(update PromptAuditBuiltinPolicyUpdate) error {
	if update.ExpectedVersion < 1 {
		return errors.New("prompt audit builtin policy version is invalid")
	}
	if err := EnsurePromptAuditDefaults(); err != nil {
		return err
	}
	values := map[string]string{
		PromptAuditOptionCheckSensitiveEnabled:         boolOptionValue(update.CheckSensitiveEnabled),
		PromptAuditOptionCheckSensitiveOnPromptEnabled: boolOptionValue(update.CheckSensitiveOnPromptEnabled),
		PromptAuditOptionSensitiveRules:                update.SensitiveRules,
		PromptAuditOptionSensitiveRuleChannelIds:       update.SensitiveRuleChannelIds,
	}
	for key, value := range values {
		if err := validateOptionValue(key, value); err != nil {
			return err
		}
	}

	optionWriteMutex.Lock()
	defer optionWriteMutex.Unlock()
	if err := DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now().Unix()
		result := tx.Model(&PromptAuditConfig{}).
			Where("id = ? AND config_version = ?", PromptAuditConfigID, update.ExpectedVersion).
			Updates(map[string]interface{}{
				"config_version":               update.ExpectedVersion + 1,
				"upstream_policy_enabled":      update.UpstreamPolicyEnabled,
				"sensitive_word_audit_enabled": update.SensitiveWordAuditEnabled,
				"updated_at":                   now,
				"updated_by":                   update.UpdatedBy,
				"change_summary":               update.ChangeSummary,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrPromptAuditConfigConflict
		}

		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		keys = sortedUniqueOptionKeys(keys)
		if err := lockPromptAuditBuiltinOptionRows(tx, keys); err != nil {
			return err
		}
		for _, key := range keys {
			option := Option{Key: key}
			if err := tx.FirstOrCreate(&option, Option{Key: key}).Error; err != nil {
				return err
			}
			option.Value = values[key]
			if err := tx.Save(&option).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}

	for _, key := range sortedUniqueOptionKeys([]string{
		PromptAuditOptionCheckSensitiveEnabled,
		PromptAuditOptionCheckSensitiveOnPromptEnabled,
		PromptAuditOptionSensitiveRules,
		PromptAuditOptionSensitiveRuleChannelIds,
	}) {
		if err := updateOptionMap(key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func lockPromptAuditBuiltinOptionRows(tx *gorm.DB, keys []string) error {
	keys = sortedUniqueOptionKeys(keys)
	if len(keys) == 0 {
		return nil
	}
	var options []Option
	return lockForUpdate(tx.Model(&Option{})).
		Where(map[string]interface{}{"key": keys}).
		Order(clause.OrderByColumn{Column: clause.Column{Name: "key"}}).
		Find(&options).Error
}

func boolOptionValue(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
