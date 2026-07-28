package router

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type securityAuditPermissionResponse struct {
	Success bool `json:"success"`
}

func TestSecurityAuditAdminRoutesAreRootOnly(t *testing.T) {
	root, admin := setupSecurityAuditRouterTestDB(t)
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(sessions.Sessions("session", cookie.NewStore([]byte("security-audit-router-test"))))
	engine.GET("/test/login/:id", func(c *gin.Context) {
		id := root.Id
		user := root
		if c.Param("id") == fmt.Sprintf("%d", admin.Id) {
			id = admin.Id
			user = admin
		}
		session := sessions.Default(c)
		session.Set("username", user.Username)
		session.Set("role", user.Role)
		session.Set("id", id)
		session.Set("status", user.Status)
		session.Set("group", user.Group)
		require.NoError(t, session.Save())
		c.Status(http.StatusNoContent)
	})
	SetApiRouter(engine)

	routes := []struct {
		method string
		path   string
		call   string
	}{
		{http.MethodGet, "/api/security-audit/config", "/api/security-audit/config"},
		{http.MethodPut, "/api/security-audit/config", "/api/security-audit/config"},
		{http.MethodGet, "/api/security-audit/builtin-policy", "/api/security-audit/builtin-policy"},
		{http.MethodPut, "/api/security-audit/builtin-policy", "/api/security-audit/builtin-policy"},
		{http.MethodPost, "/api/security-audit/endpoints/probe", "/api/security-audit/endpoints/probe"},
		{http.MethodGet, "/api/security-audit/runtime", "/api/security-audit/runtime"},
		{http.MethodGet, "/api/security-audit/events", "/api/security-audit/events"},
		{http.MethodGet, "/api/security-audit/events/:id", "/api/security-audit/events/1"},
		{http.MethodDelete, "/api/security-audit/events/:id", "/api/security-audit/events/1"},
		{http.MethodPost, "/api/security-audit/events/batch-delete", "/api/security-audit/events/batch-delete"},
		{http.MethodPost, "/api/security-audit/events/delete-preview", "/api/security-audit/events/delete-preview"},
		{http.MethodPost, "/api/security-audit/events/delete-by-filter", "/api/security-audit/events/delete-by-filter"},
	}
	registered := make(map[string]struct{})
	for _, route := range engine.Routes() {
		registered[route.Method+" "+route.Path] = struct{}{}
	}

	adminCookies := securityAuditLoginCookies(t, engine, admin.Id)
	for _, route := range routes {
		_, ok := registered[route.method+" "+route.path]
		require.True(t, ok, "%s %s 未注册", route.method, route.path)

		unauthenticated := httptest.NewRecorder()
		engine.ServeHTTP(unauthenticated, httptest.NewRequest(route.method, route.call, nil))
		require.Equal(t, http.StatusUnauthorized, unauthenticated.Code)

		request := httptest.NewRequest(route.method, route.call, nil)
		request.Header.Set("New-Api-User", fmt.Sprintf("%d", admin.Id))
		for _, value := range adminCookies {
			request.AddCookie(value)
		}
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		require.Equal(t, http.StatusOK, recorder.Code)
		var response securityAuditPermissionResponse
		require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
		require.False(t, response.Success, "%s %s 不应允许普通管理员", route.method, route.call)
	}

	rootCookies := securityAuditLoginCookies(t, engine, root.Id)
	request := httptest.NewRequest(http.MethodGet, "/api/security-audit/config", nil)
	request.Header.Set("New-Api-User", fmt.Sprintf("%d", root.Id))
	for _, value := range rootCookies {
		request.AddCookie(value)
	}
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	var response securityAuditPermissionResponse
	require.NoError(t, common.Unmarshal(recorder.Body.Bytes(), &response))
	require.True(t, response.Success)
}

func securityAuditLoginCookies(t *testing.T, engine *gin.Engine, userID int) []*http.Cookie {
	t.Helper()
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(
		http.MethodGet, fmt.Sprintf("/test/login/%d", userID), nil,
	))
	require.Equal(t, http.StatusNoContent, recorder.Code)
	return recorder.Result().Cookies()
}

func setupSecurityAuditRouterTestDB(t *testing.T) (*model.User, *model.User) {
	t.Helper()
	oldDB := model.DB
	oldLogDB := model.LOG_DB
	oldRedis := common.RedisEnabled
	oldSQLite, oldMySQL, oldPostgreSQL := common.UsingSQLite, common.UsingMySQL, common.UsingPostgreSQL
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "security-audit-router.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.User{}, &model.PromptAuditConfig{}, &model.PromptAuditEndpoint{},
		&model.PromptAuditJob{}, &model.PromptAuditEvent{}, &model.PromptAuditQueueState{},
	))
	model.DB, model.LOG_DB = db, db
	common.RedisEnabled = false
	common.UsingSQLite, common.UsingMySQL, common.UsingPostgreSQL = true, false, false
	root := &model.User{Id: 501, Username: "audit-root", Password: "password123", DisplayName: "Audit Root",
		Role: common.RoleRootUser, Status: common.UserStatusEnabled, Group: "default", AffCode: "audit-root-aff"}
	admin := &model.User{Id: 502, Username: "audit-admin", Password: "password123", DisplayName: "Audit Admin",
		Role: common.RoleAdminUser, Status: common.UserStatusEnabled, Group: "default", AffCode: "audit-admin-aff"}
	require.NoError(t, db.Create(root).Error)
	require.NoError(t, db.Create(admin).Error)
	t.Cleanup(func() {
		model.DB, model.LOG_DB = oldDB, oldLogDB
		common.RedisEnabled = oldRedis
		common.UsingSQLite, common.UsingMySQL, common.UsingPostgreSQL = oldSQLite, oldMySQL, oldPostgreSQL
		sqlDB, sqlErr := db.DB()
		if sqlErr == nil {
			_ = sqlDB.Close()
		}
	})
	return root, admin
}
