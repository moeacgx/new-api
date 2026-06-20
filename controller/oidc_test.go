package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupOIDCDefaultTokenTestDB(t *testing.T) *gorm.DB {
	t.Helper()

	gin.SetMode(gin.TestMode)

	oldDB := model.DB
	oldLogDB := model.LOG_DB
	oldUsingSQLite := common.UsingSQLite
	oldUsingMySQL := common.UsingMySQL
	oldUsingPostgreSQL := common.UsingPostgreSQL
	oldRedisEnabled := common.RedisEnabled
	oldGenerateDefaultToken := constant.GenerateDefaultToken
	oldDefaultUseAutoGroup := setting.DefaultUseAutoGroup
	oldRegisterEnabled := common.RegisterEnabled
	oldQuotaForNewUser := common.QuotaForNewUser
	oldOIDCSettings := *system_setting.GetOIDCSettings()

	common.UsingSQLite = true
	common.UsingMySQL = false
	common.UsingPostgreSQL = false
	common.RedisEnabled = false
	constant.GenerateDefaultToken = true
	setting.DefaultUseAutoGroup = false
	common.RegisterEnabled = true
	common.QuotaForNewUser = 0
	*system_setting.GetOIDCSettings() = system_setting.OIDCSettings{
		Enabled:          true,
		ClientId:         "client-id",
		ClientSecret:     "client-secret",
		TokenEndpoint:    "http://127.0.0.1/token",
		UserInfoEndpoint: "http://127.0.0.1/userinfo",
	}

	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	model.DB = db
	model.LOG_DB = db

	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}, &model.Log{}, &model.UserIPRecord{}))

	t.Cleanup(func() {
		sqlDB, err := db.DB()
		if err == nil {
			_ = sqlDB.Close()
		}

		model.DB = oldDB
		model.LOG_DB = oldLogDB
		common.UsingSQLite = oldUsingSQLite
		common.UsingMySQL = oldUsingMySQL
		common.UsingPostgreSQL = oldUsingPostgreSQL
		common.RedisEnabled = oldRedisEnabled
		constant.GenerateDefaultToken = oldGenerateDefaultToken
		setting.DefaultUseAutoGroup = oldDefaultUseAutoGroup
		common.RegisterEnabled = oldRegisterEnabled
		common.QuotaForNewUser = oldQuotaForNewUser
		*system_setting.GetOIDCSettings() = oldOIDCSettings
	})

	return db
}

func setupOIDCProviderServer(t *testing.T, subject string, email string) *httptest.Server {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if r.Method != http.MethodPost {
				t.Errorf("token endpoint method = %s, want %s", r.Method, http.MethodPost)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if err := r.ParseForm(); err != nil {
				t.Errorf("token endpoint ParseForm error: %v", err)
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.Form.Get("grant_type") != "authorization_code" {
				t.Errorf("grant_type = %s, want authorization_code", r.Form.Get("grant_type"))
				http.Error(w, "bad grant_type", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"oidc-access-token","token_type":"Bearer"}`))
		case "/userinfo":
			if r.Method != http.MethodGet {
				t.Errorf("userinfo endpoint method = %s, want %s", r.Method, http.MethodGet)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			if r.Header.Get("Authorization") != "Bearer oidc-access-token" {
				t.Errorf("Authorization = %s, want Bearer oidc-access-token", r.Header.Get("Authorization"))
				http.Error(w, "bad authorization", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"sub":%q,"email":%q,"name":"OIDC User"}`, subject, email)
		default:
			http.NotFound(w, r)
		}
	}))

	settings := system_setting.GetOIDCSettings()
	settings.TokenEndpoint = server.URL + "/token"
	settings.UserInfoEndpoint = server.URL + "/userinfo"

	t.Cleanup(server.Close)
	return server
}

func performOIDCCallback(t *testing.T, router *gin.Engine) *httptest.ResponseRecorder {
	t.Helper()

	stateReq := httptest.NewRequest(http.MethodGet, "/api/oauth/state", nil)
	stateRecorder := httptest.NewRecorder()
	router.ServeHTTP(stateRecorder, stateReq)
	require.Equal(t, http.StatusOK, stateRecorder.Code)
	require.NotEmpty(t, stateRecorder.Result().Cookies())

	var stateResponse struct {
		Success bool   `json:"success"`
		Data    string `json:"data"`
	}
	require.NoError(t, common.Unmarshal(stateRecorder.Body.Bytes(), &stateResponse))
	require.True(t, stateResponse.Success)
	require.NotEmpty(t, stateResponse.Data)

	state := stateResponse.Data
	callbackReq := httptest.NewRequest(http.MethodGet, "/api/oauth/oidc?state="+state+"&code=code", nil)
	for _, responseCookie := range stateRecorder.Result().Cookies() {
		callbackReq.AddCookie(responseCookie)
	}
	callbackRecorder := httptest.NewRecorder()
	router.ServeHTTP(callbackRecorder, callbackReq)
	return callbackRecorder
}

func setupOIDCTestRouter() *gin.Engine {
	router := gin.New()
	router.Use(sessions.Sessions("session", cookie.NewStore([]byte("oidc-test-secret"))))
	router.GET("/api/oauth/state", GenerateOAuthCode)
	router.GET("/api/oauth/:provider", HandleOAuth)
	return router
}

func TestHandleOAuthCreatesDefaultTokenForNewOIDCUser(t *testing.T) {
	db := setupOIDCDefaultTokenTestDB(t)
	setupOIDCProviderServer(t, "oidc-sub-new", "oidc-new@example.com")
	router := setupOIDCTestRouter()

	response := performOIDCCallback(t, router)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"success":true`)

	var user model.User
	require.NoError(t, db.Where("oidc_id = ?", "oidc-sub-new").First(&user).Error)
	require.Equal(t, "oidc-new@example.com", user.Username)

	var tokens []model.Token
	require.NoError(t, db.Where("user_id = ?", user.Id).Find(&tokens).Error)
	require.Len(t, tokens, 1)

	token := tokens[0]
	require.Equal(t, user.Id, token.UserId)
	require.Equal(t, "oidc-new@example.com的初始令牌", token.Name)
	require.NotEmpty(t, token.Key)
	require.Equal(t, int64(-1), token.ExpiredTime)
	require.Equal(t, 500000, token.RemainQuota)
	require.True(t, token.UnlimitedQuota)
	require.False(t, token.ModelLimitsEnabled)
	require.Equal(t, "default", token.Group)
}

func TestHandleOAuthDoesNotBackfillDefaultTokenForExistingOIDCUser(t *testing.T) {
	db := setupOIDCDefaultTokenTestDB(t)
	setupOIDCProviderServer(t, "oidc-sub-existing", "oidc-existing@example.com")
	router := setupOIDCTestRouter()

	user := model.User{
		Username:    "oidc-existing",
		DisplayName: "Existing OIDC User",
		Email:       "oidc-existing@example.com",
		OidcId:      "oidc-sub-existing",
		Role:        common.RoleCommonUser,
		Status:      common.UserStatusEnabled,
		Group:       "default",
	}
	require.NoError(t, db.Create(&user).Error)

	response := performOIDCCallback(t, router)
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), `"success":true`)

	var count int64
	require.NoError(t, db.Model(&model.Token{}).Where("user_id = ?", user.Id).Count(&count).Error)
	require.Equal(t, int64(0), count)
}
