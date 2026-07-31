package service

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestResolveOrProvisionUserDoesNotMergeByEmail(t *testing.T) {
	setupEcosystemServiceTestDB(t)
	restore := configureEcosystemServiceSettings(t)
	defer restore()

	require.NoError(t, model.DB.Create(&model.User{
		Username: "existing",
		Email:    "same@example.com",
		AffCode:  "aff-existing",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    "default",
	}).Error)

	user, created, err := ResolveOrProvisionUser("logto-sub-1", "same@example.com", "", "")
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, "existing", user.Username)
	require.Equal(t, "logto-sub-1", user.OidcId)
	require.Equal(t, "same@example.com", user.Email)
}

func TestResolveOrProvisionUserExistingAndDisabled(t *testing.T) {
	setupEcosystemServiceTestDB(t)
	restore := configureEcosystemServiceSettings(t)
	defer restore()

	require.NoError(t, model.DB.Create(&model.User{
		Username: "bound",
		OidcId:   "logto-bound",
		AffCode:  "aff-bound",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    "default",
	}).Error)

	user, created, err := ResolveOrProvisionUser("logto-bound", "bound@example.com", "", "")
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, "bound", user.Username)

	require.NoError(t, model.DB.Create(&model.User{
		Username: "disabled",
		OidcId:   "logto-disabled",
		AffCode:  "aff-disabled",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusDisabled,
		Group:    "default",
	}).Error)

	_, _, err = ResolveOrProvisionUser("logto-disabled", "disabled@example.com", "", "")
	require.ErrorIs(t, err, ErrEcosystemUserDisabled)
}

func TestListEcosystemTokensReadsAllEnabledUserTokens(t *testing.T) {
	setupEcosystemServiceTestDB(t)
	restore := configureEcosystemServiceSettings(t)
	defer restore()

	user := &model.User{
		Username: "token-user",
		AffCode:  "aff-token",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    "default",
	}
	require.NoError(t, model.DB.Create(user).Error)

	otherUser := &model.User{
		Username: "other-token-user",
		AffCode:  "aff-other-token",
		Role:     common.RoleCommonUser,
		Status:   common.UserStatusEnabled,
		Group:    "default",
	}
	require.NoError(t, model.DB.Create(otherUser).Error)

	require.NoError(t, model.DB.Create(&model.Token{
		UserId:         user.Id,
		Name:           "聊天网站令牌",
		Key:            "manual-image-key",
		Status:         common.TokenStatusEnabled,
		CreatedTime:    common.GetTimestamp(),
		AccessedTime:   common.GetTimestamp(),
		ExpiredTime:    -1,
		UnlimitedQuota: true,
		Group:          "default",
	}).Error)
	require.NoError(t, model.DB.Create(&model.Token{
		UserId:         user.Id,
		Name:           "custom-token",
		Key:            "manual-default-key",
		Status:         common.TokenStatusEnabled,
		CreatedTime:    common.GetTimestamp(),
		AccessedTime:   common.GetTimestamp(),
		ExpiredTime:    -1,
		UnlimitedQuota: true,
		Group:          "default",
	}).Error)
	require.NoError(t, model.DB.Create(&model.Token{
		UserId:         user.Id,
		Name:           "disabled-token",
		Key:            "ordinary-key",
		Status:         common.TokenStatusDisabled,
		CreatedTime:    common.GetTimestamp(),
		AccessedTime:   common.GetTimestamp(),
		ExpiredTime:    -1,
		UnlimitedQuota: true,
		Group:          "default",
	}).Error)
	require.NoError(t, model.DB.Create(&model.Token{
		UserId:         otherUser.Id,
		Name:           "other-user-token",
		Key:            "other-key",
		Status:         common.TokenStatusEnabled,
		CreatedTime:    common.GetTimestamp(),
		AccessedTime:   common.GetTimestamp(),
		ExpiredTime:    -1,
		UnlimitedQuota: true,
		Group:          "default",
	}).Error)

	tokens, err := ListEcosystemTokens(user)
	require.NoError(t, err)
	require.Len(t, tokens, 2)
	require.Equal(t, "聊天网站令牌", tokens[0].TokenName)
	require.Equal(t, "sk-manual-image-key", tokens[0].APIKey)
	require.Equal(t, "https://newapi.example/v1", tokens[0].BaseURL)
	require.Equal(t, "custom-token", tokens[1].TokenName)
	require.Equal(t, "sk-manual-default-key", tokens[1].APIKey)
}

func setupEcosystemServiceTestDB(t *testing.T) {
	t.Helper()
	oldDB := model.DB
	oldLogDB := model.LOG_DB
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	model.DB = db
	model.LOG_DB = db
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.Log{}))
	t.Cleanup(func() {
		model.DB = oldDB
		model.LOG_DB = oldLogDB
	})
}

func configureEcosystemServiceSettings(t *testing.T) func() {
	t.Helper()
	settings := system_setting.GetLogtoEcosystemSettings()
	originalSettings := *settings
	originalRegisterEnabled := common.RegisterEnabled
	*settings = system_setting.LogtoEcosystemSettings{
		Enabled:  true,
		Issuer:   "http://logto.example/oidc",
		Audience: "https://newapi.example",
		JWKSURI:  "http://logto.example/oidc/jwks",
		BaseURL:  "https://newapi.example",
	}
	common.RegisterEnabled = true
	return func() {
		*settings = originalSettings
		common.RegisterEnabled = originalRegisterEnabled
	}
}
