package service

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/stretchr/testify/require"
)

func TestSecurityAuditBuiltinPolicyMigratesLegacyWordsWithoutDeletingThem(t *testing.T) {
	db := setupPromptAuditServiceTest(t, false, false, nil)
	require.NoError(t, db.AutoMigrate(&model.Option{}))

	oldOptionMap := common.OptionMap
	oldCheckEnabled := setting.CheckSensitiveEnabled
	oldPromptEnabled := setting.CheckSensitiveOnPromptEnabled
	oldWords := append([]string(nil), setting.SensitiveWords...)
	oldRules := append([]setting.SensitiveRule(nil), setting.SensitiveRules...)
	oldRulesConfigured := setting.SensitiveRulesConfigured
	oldChannelIds := append([]int(nil), setting.SensitiveRuleChannelIds...)
	common.OptionMap = make(map[string]string)
	setting.SensitiveRules = nil
	setting.SensitiveRulesConfigured = false
	setting.SensitiveRuleChannelIds = []int{9}
	t.Cleanup(func() {
		common.OptionMap = oldOptionMap
		setting.CheckSensitiveEnabled = oldCheckEnabled
		setting.CheckSensitiveOnPromptEnabled = oldPromptEnabled
		setting.SensitiveWords = oldWords
		setting.SensitiveRules = oldRules
		setting.SensitiveRulesConfigured = oldRulesConfigured
		setting.SensitiveRuleChannelIds = oldChannelIds
	})
	require.NoError(t, db.Create(&model.Option{Key: "SensitiveWords", Value: "legacy-word\n旧词"}).Error)
	setting.SensitiveWordsFromString("legacy-word\n旧词")
	common.OptionMap["SensitiveWords"] = "legacy-word\n旧词"
	setting.SensitiveRulesConfigured = false

	policy, err := GetSecurityAuditBuiltinPolicy()
	require.NoError(t, err)
	require.True(t, policy.UsesLegacySensitiveWords)
	require.Contains(t, policy.SensitiveRules, "legacy-word")
	require.Contains(t, policy.SensitiveRules, "旧词")

	disabled := false
	updated, err := SaveSecurityAuditBuiltinPolicy(SecurityAuditBuiltinPolicyUpdateRequest{
		ExpectedConfigVersion: policy.ConfigVersion,
		CheckSensitiveEnabled: &disabled,
	}, 23)
	require.NoError(t, err)
	require.EqualValues(t, policy.ConfigVersion+1, updated.ConfigVersion)
	require.False(t, updated.CheckSensitiveEnabled)
	require.False(t, updated.UsesLegacySensitiveWords)
	require.Equal(t, "legacy-word\n旧词", updated.SensitiveWords)
	require.Contains(t, updated.SensitiveRules, "legacy-word")

	var legacy model.Option
	require.NoError(t, db.First(&legacy, "`key` = ?", "SensitiveWords").Error)
	require.Equal(t, "legacy-word\n旧词", legacy.Value)

	_, err = SaveSecurityAuditBuiltinPolicy(SecurityAuditBuiltinPolicyUpdateRequest{
		ExpectedConfigVersion: policy.ConfigVersion,
		CheckSensitiveEnabled: &disabled,
	}, 23)
	require.ErrorIs(t, err, model.ErrPromptAuditConfigConflict)
}

func TestSavePromptAuditConfigPreservesBuiltinPolicyWhenFieldsAreOmitted(t *testing.T) {
	setupPromptAuditServiceTest(t, false, false, nil)
	row, endpoints, err := model.LoadPromptAuditConfig()
	require.NoError(t, err)
	row.UpstreamPolicyEnabled = false
	row.SensitiveWordAuditEnabled = true
	require.NoError(t, model.SavePromptAuditConfig(row.ConfigVersion, row, endpoints))
	InvalidatePromptAuditConfig()

	current, err := GetPublicPromptAuditConfig()
	require.NoError(t, err)
	req := promptAuditUpdateRequestFromConfig(current)
	req.UpstreamPolicyEnabled = nil
	req.SensitiveWordAuditEnabled = nil
	for i := range req.Endpoints {
		req.Endpoints[i].TokenAction = PromptAuditTokenKeep
	}
	updated, err := SavePromptAuditConfig(req, 31)
	require.NoError(t, err)
	require.False(t, updated.UpstreamPolicyEnabled)
	require.True(t, updated.SensitiveWordAuditEnabled)
}
