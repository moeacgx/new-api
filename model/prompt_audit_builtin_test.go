package model

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting"
	"github.com/stretchr/testify/require"
)

func TestSavePromptAuditBuiltinPolicyUsesCASAndKeepsOptionsAtomic(t *testing.T) {
	db := setupPromptAuditTestDB(t)
	require.NoError(t, db.AutoMigrate(&Option{}))
	oldOptionMap := common.OptionMap
	oldCheckEnabled := setting.CheckSensitiveEnabled
	oldPromptEnabled := setting.CheckSensitiveOnPromptEnabled
	oldRules := append([]setting.SensitiveRule(nil), setting.SensitiveRules...)
	oldRulesConfigured := setting.SensitiveRulesConfigured
	oldChannelIds := append([]int(nil), setting.SensitiveRuleChannelIds...)
	common.OptionMap = make(map[string]string)
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
		setting.CheckSensitiveEnabled = oldCheckEnabled
		setting.CheckSensitiveOnPromptEnabled = oldPromptEnabled
		setting.SensitiveRules = oldRules
		setting.SensitiveRulesConfigured = oldRulesConfigured
		setting.SensitiveRuleChannelIds = oldChannelIds
	})

	update := PromptAuditBuiltinPolicyUpdate{
		ExpectedVersion:               1,
		UpstreamPolicyEnabled:         false,
		SensitiveWordAuditEnabled:     true,
		CheckSensitiveEnabled:         true,
		CheckSensitiveOnPromptEnabled: false,
		SensitiveRules:                `{"rules":[{"id":"rule-1","name":"Rule 1","enabled":true,"action":"block","scope":"request","keywords":["blocked"]}]}`,
		SensitiveRuleChannelIds:       `[7,3,7]`,
		UpdatedBy:                     11,
		ChangeSummary:                 `{"kind":"builtin_policy"}`,
	}
	require.NoError(t, SavePromptAuditBuiltinPolicy(update))

	row, _, err := LoadPromptAuditConfig()
	require.NoError(t, err)
	require.EqualValues(t, 2, row.ConfigVersion)
	require.False(t, row.UpstreamPolicyEnabled)
	require.True(t, row.SensitiveWordAuditEnabled)
	require.Equal(t, 11, row.UpdatedBy)
	require.False(t, setting.CheckSensitiveOnPromptEnabled)
	require.Equal(t, []int{3, 7}, setting.SensitiveRuleChannelIds)

	update.ExpectedVersion = 1
	update.CheckSensitiveEnabled = false
	update.SensitiveRules = `{"rules":[]}`
	require.ErrorIs(t, SavePromptAuditBuiltinPolicy(update), ErrPromptAuditConfigConflict)

	var enabledOption Option
	require.NoError(t, db.First(&enabledOption, commonKeyCol+" = ?", PromptAuditOptionCheckSensitiveEnabled).Error)
	require.Equal(t, "true", enabledOption.Value)
	var rulesOption Option
	require.NoError(t, db.First(&rulesOption, commonKeyCol+" = ?", PromptAuditOptionSensitiveRules).Error)
	require.Contains(t, rulesOption.Value, "blocked")
}
