package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"gorm.io/gorm"
)

var ErrEcosystemUserDisabled = errors.New("user_disabled")
var ErrEcosystemInvalidToken = errors.New("invalid_ecosystem_token")

type EcosystemUserInfo struct {
	LogtoSub     string `json:"logto_sub"`
	NewAPIUserID int    `json:"newapi_user_id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	Group        string `json:"group"`
	Provisioned  bool   `json:"provisioned"`
}

type EcosystemTokenInfo struct {
	TokenID   int    `json:"token_id"`
	TokenName string `json:"token_name"`
	APIKey    string `json:"api_key,omitempty"`
	BaseURL   string `json:"base_url"`
	Group     string `json:"group"`
}

func ResolveOrProvisionUser(logtoSub string, email string, profileName string, profileUsername string) (*model.User, bool, error) {
	logtoSub = strings.TrimSpace(logtoSub)
	if logtoSub == "" {
		return nil, false, errors.New("logto sub 为空！")
	}

	user := &model.User{}
	if err := model.DB.Where("oidc_id = ?", logtoSub).First(user).Error; err == nil {
		if user.Status != common.UserStatusEnabled {
			return nil, false, ErrEcosystemUserDisabled
		}
		return user, false, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, fmt.Errorf("resolve user by oidc id failed: %w", err)
	}

	if !common.RegisterEnabled {
		return nil, false, errors.New("管理员关闭了新用户注册")
	}

	username := buildEcosystemUsername(logtoSub)
	displayName := strings.TrimSpace(profileName)
	if displayName == "" {
		displayName = truncateEcosystemUsername(firstNonEmpty(strings.TrimSpace(email), username))
	}
	displayName = truncateEcosystemUsername(displayName)

	newUser := &model.User{
		Username:    username,
		DisplayName: displayName,
		Email:       strings.TrimSpace(email),
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
		OidcId:      logtoSub,
	}

	if err := newUser.Insert(0); err != nil {
		return nil, false, err
	}
	if err := model.DB.Where("oidc_id = ?", logtoSub).First(newUser).Error; err != nil {
		return nil, true, err
	}
	return newUser, true, nil
}

func GetEcosystemUserGroups(user *model.User) map[string]map[string]interface{} {
	if user == nil {
		return map[string]map[string]interface{}{}
	}
	usableGroups := make(map[string]map[string]interface{})
	userUsableGroups := GetUserUsableGroups(user.Group)
	for groupName := range ratio_setting.GetGroupRatioCopy() {
		if desc, ok := userUsableGroups[groupName]; ok {
			usableGroups[groupName] = map[string]interface{}{
				"ratio": GetUserGroupRatio(user.Group, groupName),
				"desc":  desc,
			}
		}
	}
	if _, ok := userUsableGroups["auto"]; ok {
		usableGroups["auto"] = map[string]interface{}{
			"ratio": "自动",
			"desc":  setting.GetUsableGroupDescription("auto"),
		}
	}
	return usableGroups
}

func GetEcosystemUserModels(user *model.User) []string {
	if user == nil {
		return []string{}
	}
	groups := GetUserUsableGroups(user.Group)
	models := make([]string, 0)
	seen := make(map[string]bool)
	for group := range groups {
		for _, enabledModel := range model.GetGroupEnabledModels(group) {
			if seen[enabledModel] {
				continue
			}
			seen[enabledModel] = true
			models = append(models, enabledModel)
		}
	}
	return models
}

func ListEcosystemTokens(user *model.User) ([]EcosystemTokenInfo, error) {
	if user == nil {
		return nil, errors.New("user 为空！")
	}
	if user.Status != common.UserStatusEnabled {
		return nil, ErrEcosystemUserDisabled
	}

	var tokens []model.Token
	if err := model.DB.Where("user_id = ? AND status = ?", user.Id, common.TokenStatusEnabled).
		Order("id asc").
		Find(&tokens).Error; err != nil {
		return nil, err
	}

	baseURL := GetLogtoEcosystemBaseURL()
	result := make([]EcosystemTokenInfo, 0, len(tokens))
	for _, token := range tokens {
		result = append(result, EcosystemTokenInfo{
			TokenID:   token.Id,
			TokenName: token.Name,
			APIKey:    formatEcosystemAPIKey(token.GetFullKey()),
			BaseURL:   baseURL,
			Group:     token.Group,
		})
	}
	return result, nil
}

func buildEcosystemUsername(logtoSub string) string {
	sum := sha256.Sum256([]byte(logtoSub))
	base := "eco_" + hex.EncodeToString(sum[:])[:12]
	if exists, err := model.CheckUserExistOrDeleted(base, ""); err == nil && !exists {
		return base
	}
	for i := 0; i < 10; i++ {
		username := "eco_" + hex.EncodeToString(sum[:])[:8] + "_" + common.GetRandomString(4)
		if exists, err := model.CheckUserExistOrDeleted(username, ""); err == nil && !exists {
			return username
		}
	}
	return "eco_" + common.GetRandomString(16)
}

func truncateEcosystemUsername(username string) string {
	username = strings.TrimSpace(username)
	if len(username) <= model.UserNameMaxLength {
		return username
	}
	return username[:model.UserNameMaxLength]
}

func GetLogtoEcosystemBaseURL() string {
	baseURL := strings.TrimSpace(system_setting.GetLogtoEcosystemSettings().BaseURL)
	if baseURL == "" {
		baseURL = strings.TrimSpace(system_setting.ServerAddress)
	}
	if baseURL == "" {
		return "/v1"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL
	}
	return baseURL + "/v1"
}

func formatEcosystemAPIKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" || strings.HasPrefix(key, "sk-") {
		return key
	}
	return "sk-" + key
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
