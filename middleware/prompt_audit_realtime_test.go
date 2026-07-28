package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestPromptAuditRealtimeBlocksBeforeNextMiddleware(t *testing.T) {
	tests := []struct {
		name             string
		guardContent     string
		wantNext         int64
		wantCloseCode    int
		wantErrorCode    string
		wantAcknowledged bool
	}{
		{
			name: "安全首帧继续进入渠道链路", guardContent: "Safety: Safe\nCategories: None",
			wantNext: 1, wantAcknowledged: true,
		},
		{
			name: "风险首帧在渠道前阻断", guardContent: "Safety: Unsafe\nCategories: Jailbreak",
			wantCloseCode: 4403, wantErrorCode: service.PromptGuardBlockedCode,
		},
		{
			name: "非法 Guard 响应在渠道前失败", guardContent: "not-a-valid-guard-response",
			wantCloseCode: websocket.CloseTryAgainLater, wantErrorCode: service.PromptGuardInvalidResponseCode,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = fmt.Fprintf(w, `{"choices":[{"message":{"content":%q}}]}`, test.guardContent)
			}))
			defer guard.Close()
			setupPromptAuditRealtimeTestDB(t, guard.URL)

			var nextCalls atomic.Int64
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.GET("/v1/realtime",
				func(c *gin.Context) {
					common.SetContextKey(c, constant.ContextKeyUserId, 10)
					common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
					common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
					common.SetContextKey(c, constant.ContextKeyTokenId, 20)
					c.Next()
				},
				PromptAuditRealtime(),
				func(c *gin.Context) {
					nextCalls.Add(1)
					realtimeActive := common.GetContextKeyBool(c, constant.ContextKeyPromptAuditRealtimeActive)
					require.True(t, realtimeActive)
					conn, ok := common.GetContextKeyType[*websocket.Conn](c, constant.ContextKeyPromptAuditRealtimeClientWs)
					require.True(t, ok)
					frames, ok := common.GetContextKeyType[service.PromptAuditRealtimeFrames](c, constant.ContextKeyPromptAuditRealtimeBufferedFrames)
					require.True(t, ok)
					require.Len(t, frames, 1)
					require.Contains(t, string(frames[0].Payload), "first realtime prompt")
					_ = conn.WriteJSON(map[string]string{"type": "audit.ack"})
				},
			)
			server := httptest.NewServer(router)
			defer server.Close()

			dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
			conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.WriteJSON(map[string]interface{}{
				"type":    "session.update",
				"session": map[string]string{"instructions": "first realtime prompt"},
			}))

			_, payload, readErr := conn.ReadMessage()
			if test.wantAcknowledged {
				require.NoError(t, readErr)
				require.Contains(t, string(payload), "audit.ack")
				require.Equal(t, test.wantNext, nextCalls.Load())
				return
			}
			require.NoError(t, readErr)
			require.Contains(t, string(payload), test.wantErrorCode)
			_, _, readErr = conn.ReadMessage()
			var closeErr *websocket.CloseError
			require.ErrorAs(t, readErr, &closeErr)
			require.Equal(t, test.wantCloseCode, closeErr.Code)
			require.Zero(t, nextCalls.Load())
		})
	}
}

func TestPromptAuditRealtimeGuardOffStillRunsSensitiveRuleBeforeDistribution(t *testing.T) {
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)
	cfg, endpoints, err := model.LoadPromptAuditConfig()
	require.NoError(t, err)
	cfg.Enabled = false
	cfg.BlockingEnabled = false
	require.NoError(t, model.SavePromptAuditConfig(cfg.ConfigVersion, cfg, endpoints))
	service.InvalidatePromptAuditConfig()

	oldEnabled, oldPromptEnabled := setting.CheckSensitiveEnabled, setting.CheckSensitiveOnPromptEnabled
	oldRules, oldConfigured := setting.SensitiveRules, setting.SensitiveRulesConfigured
	oldChannelIDs := setting.SensitiveRuleChannelIds
	setting.CheckSensitiveEnabled = true
	setting.CheckSensitiveOnPromptEnabled = true
	setting.SensitiveRulesConfigured = true
	setting.SensitiveRules = []setting.SensitiveRule{{
		ID: "realtime-sensitive", Name: "Realtime Sensitive", Enabled: true,
		Action: setting.SensitiveRuleActionBlock, Scope: setting.SensitiveRuleScopeRequest,
		Keywords: []string{"realtime-secret"},
	}}
	setting.SensitiveRuleChannelIds = []int{99}
	t.Cleanup(func() {
		setting.CheckSensitiveEnabled, setting.CheckSensitiveOnPromptEnabled = oldEnabled, oldPromptEnabled
		setting.SensitiveRules, setting.SensitiveRulesConfigured = oldRules, oldConfigured
		setting.SensitiveRuleChannelIds = oldChannelIDs
	})

	var nextCalls atomic.Int64
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/realtime",
		func(c *gin.Context) {
			common.SetContextKey(c, constant.ContextKeyUserId, 10)
			common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenId, 20)
			c.Next()
		},
		PromptAuditRealtime(),
		func(c *gin.Context) { nextCalls.Add(1) },
	)
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime", nil)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.WriteJSON(map[string]interface{}{
		"type": "session.update", "session": map[string]string{"instructions": "realtime-secret"},
	}))
	_, payload, readErr := conn.ReadMessage()
	require.NoError(t, readErr)
	require.Contains(t, string(payload), string(types.ErrorCodeSensitiveWordsDetected))
	_, _, readErr = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, readErr, &closeErr)
	require.Equal(t, 4403, closeErr.Code)
	require.Zero(t, nextCalls.Load())

	var event model.PromptAuditEvent
	require.NoError(t, model.DB.First(&event, "source = ?", service.PromptAuditSourceSensitiveWord).Error)
	require.Equal(t, "realtime_request", event.Stage)
}

func TestPromptAuditRealtimeMaskForwardsRewrittenFrameButGuardsOriginal(t *testing.T) {
	guardBodies := make(chan string, 1)
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		guardBodies <- string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)

	oldEnabled, oldPromptEnabled := setting.CheckSensitiveEnabled, setting.CheckSensitiveOnPromptEnabled
	oldRules, oldConfigured := setting.SensitiveRules, setting.SensitiveRulesConfigured
	oldChannelIDs, oldWords := setting.SensitiveRuleChannelIds, setting.SensitiveWords
	setting.CheckSensitiveEnabled = true
	setting.CheckSensitiveOnPromptEnabled = true
	setting.SensitiveRulesConfigured = true
	setting.SensitiveRules = []setting.SensitiveRule{{
		ID: "realtime-mask", Name: "Realtime Mask", Enabled: true,
		Action: setting.SensitiveRuleActionMask, Scope: setting.SensitiveRuleScopeRequest,
		Keywords: []string{"original-secret"}, Replacement: "[masked]",
	}}
	setting.SensitiveRuleChannelIds = []int{99}
	setting.SensitiveWords = nil
	t.Cleanup(func() {
		setting.CheckSensitiveEnabled, setting.CheckSensitiveOnPromptEnabled = oldEnabled, oldPromptEnabled
		setting.SensitiveRules, setting.SensitiveRulesConfigured = oldRules, oldConfigured
		setting.SensitiveRuleChannelIds, setting.SensitiveWords = oldChannelIDs, oldWords
	})

	forwardedFrames := make(chan string, 1)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/realtime",
		func(c *gin.Context) {
			common.SetContextKey(c, constant.ContextKeyUserId, 10)
			common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenId, 20)
			c.Next()
		},
		PromptAuditRealtime(),
		func(c *gin.Context) {
			frames, _ := common.GetContextKeyType[service.PromptAuditRealtimeFrames](c, constant.ContextKeyPromptAuditRealtimeBufferedFrames)
			forwardedFrames <- string(frames[0].Payload)
			conn, _ := common.GetContextKeyType[*websocket.Conn](c, constant.ContextKeyPromptAuditRealtimeClientWs)
			_ = conn.WriteJSON(map[string]string{"type": "audit.ack"})
		},
	)
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime", nil)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.WriteJSON(map[string]interface{}{
		"type": "session.update", "session": map[string]string{"instructions": "original-secret"},
	}))
	_, _, err = conn.ReadMessage()
	require.NoError(t, err)

	require.Contains(t, <-guardBodies, "original-secret")
	forwarded := <-forwardedFrames
	require.Contains(t, forwarded, "[masked]")
	require.NotContains(t, forwarded, "original-secret")
}

func TestPromptAuditRealtimeBuffersRawBinaryBeforeRiskJSON(t *testing.T) {
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"Safety: Unsafe\nCategories: Jailbreak"}}]}`)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)

	var nextCalls atomic.Int64
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/realtime",
		func(c *gin.Context) {
			common.SetContextKey(c, constant.ContextKeyUserId, 10)
			common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenId, 20)
			c.Next()
		},
		PromptAuditRealtime(),
		func(c *gin.Context) {
			nextCalls.Add(1)
			conn, _ := common.GetContextKeyType[*websocket.Conn](c, constant.ContextKeyPromptAuditRealtimeClientWs)
			_ = conn.WriteJSON(map[string]string{"type": "audit.ack"})
		},
	)
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte{0x01, 0x7f, 0x00, 0xa5}))
	require.NoError(t, conn.WriteJSON(map[string]interface{}{
		"type":    "session.update",
		"session": map[string]string{"instructions": "blocked after binary audio"},
	}))

	_, payload, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Contains(t, string(payload), service.PromptGuardBlockedCode)
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, 4403, closeErr.Code)
	require.Zero(t, nextCalls.Load())
}

func TestPromptAuditRealtimeAuditsBinaryJSON(t *testing.T) {
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"Safety: Unsafe\nCategories: Jailbreak"}}]}`)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)

	var nextCalls atomic.Int64
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/realtime",
		func(c *gin.Context) {
			common.SetContextKey(c, constant.ContextKeyUserId, 10)
			common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenId, 20)
			c.Next()
		},
		PromptAuditRealtime(),
		func(c *gin.Context) {
			nextCalls.Add(1)
			conn, _ := common.GetContextKeyType[*websocket.Conn](c, constant.ContextKeyPromptAuditRealtimeClientWs)
			_ = conn.WriteJSON(map[string]string{"type": "audit.ack"})
		},
	)
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte(
		`{"type":"response.create","response":{"instructions":"binary JSON risk"}}`,
	)))

	_, payload, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Contains(t, string(payload), service.PromptGuardBlockedCode)
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, 4403, closeErr.Code)
	require.Zero(t, nextCalls.Load())
}

func TestPromptAuditRealtimeRejectsInvalidFirstControlFrameBeforeDistribution(t *testing.T) {
	var guardCalls atomic.Int64
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		guardCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)

	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "空对象", payload: []byte(`{}`)},
		{name: "缺少类型", payload: []byte(`{"session":{"instructions":"text"}}`)},
		{name: "类型为空", payload: []byte(`{"type":"  "}`)},
		{name: "JSON 数组", payload: []byte(`[]`)},
		{name: "非 JSON 文本", payload: []byte(`not-json`)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var nextCalls atomic.Int64
			gin.SetMode(gin.TestMode)
			router := gin.New()
			router.GET("/v1/realtime",
				func(c *gin.Context) {
					common.SetContextKey(c, constant.ContextKeyUserId, 10)
					common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
					common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
					c.Next()
				},
				PromptAuditRealtime(),
				func(c *gin.Context) { nextCalls.Add(1) },
			)
			server := httptest.NewServer(router)
			defer server.Close()

			dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
			conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime", nil)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.WriteMessage(websocket.TextMessage, test.payload))

			_, payload, err := conn.ReadMessage()
			require.NoError(t, err)
			require.Contains(t, string(payload), string(types.ErrorCodeInvalidRequest))
			_, _, err = conn.ReadMessage()
			var closeErr *websocket.CloseError
			require.ErrorAs(t, err, &closeErr)
			require.Equal(t, websocket.CloseInvalidFramePayloadData, closeErr.Code)
			require.Zero(t, nextCalls.Load())
		})
	}
	require.Zero(t, guardCalls.Load(), "非法首帧不应调用 Guard 或进入渠道分配")
}

func TestPromptAuditRealtimeRejectsTooManyBufferedFrames(t *testing.T) {
	var guardCalls atomic.Int64
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		guardCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)

	var nextCalls atomic.Int64
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/realtime",
		func(c *gin.Context) {
			common.SetContextKey(c, constant.ContextKeyUserId, 10)
			common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenId, 20)
			c.Next()
		},
		PromptAuditRealtime(),
		func(c *gin.Context) {
			nextCalls.Add(1)
		},
	)
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	require.NoError(t, err)
	defer conn.Close()
	for index := 0; index <= promptAuditRealtimeMaxBufferedFrames; index++ {
		require.NoError(t, conn.WriteMessage(websocket.BinaryMessage, []byte{0x00}))
	}

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(3*time.Second)))
	_, payload, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Contains(t, string(payload), string(types.ErrorCodeInvalidRequest))
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, websocket.CloseMessageTooBig, closeErr.Code)
	require.Zero(t, nextCalls.Load())
	require.Zero(t, guardCalls.Load())
}

func TestPromptAuditRealtimeReturnsDistributionFailureAsWebSocketEvent(t *testing.T) {
	guard := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"choices":[{"message":{"content":"Safety: Safe\nCategories: None"}}]}`)
	}))
	defer guard.Close()
	setupPromptAuditRealtimeTestDB(t, guard.URL)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/v1/realtime",
		func(c *gin.Context) {
			common.SetContextKey(c, constant.ContextKeyUserId, 10)
			common.SetContextKey(c, constant.ContextKeyUserGroupId, 1)
			common.SetContextKey(c, constant.ContextKeyUserGroup, "default")
			common.SetContextKey(c, constant.ContextKeyTokenId, 20)
			c.Next()
		},
		PromptAuditRealtime(),
		func(c *gin.Context) {
			abortWithOpenAiMessage(c, http.StatusServiceUnavailable, "当前没有可用渠道", types.ErrorCodeModelNotFound)
		},
	)
	server := httptest.NewServer(router)
	defer server.Close()

	dialer := websocket.Dialer{Subprotocols: []string{"realtime"}}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/v1/realtime?model=gpt-realtime", nil)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.WriteJSON(map[string]interface{}{
		"type":    "session.update",
		"session": map[string]string{"instructions": "safe realtime prompt"},
	}))

	_, payload, err := conn.ReadMessage()
	require.NoError(t, err)
	require.Contains(t, string(payload), string(types.ErrorCodeModelNotFound))
	require.Contains(t, string(payload), "当前没有可用渠道")
	_, _, err = conn.ReadMessage()
	var closeErr *websocket.CloseError
	require.ErrorAs(t, err, &closeErr)
	require.Equal(t, websocket.CloseTryAgainLater, closeErr.Code)
}

func setupPromptAuditRealtimeTestDB(t *testing.T, guardURL string) {
	t.Helper()
	oldDB := model.DB
	oldSecret := common.CryptoSecret
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "prompt-audit-realtime.db")), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&model.PromptAuditConfig{}, &model.PromptAuditEndpoint{}, &model.PromptAuditJob{},
		&model.PromptAuditEvent{}, &model.PromptAuditQueueState{},
	))
	model.DB = db
	t.Setenv("CRYPTO_SECRET", "stable-realtime-test-secret")
	common.CryptoSecret = "stable-realtime-test-secret"
	require.NoError(t, model.EnsurePromptAuditDefaults())
	cfg, _, err := model.LoadPromptAuditConfig()
	require.NoError(t, err)
	cfg.Enabled = true
	cfg.BlockingEnabled = true
	require.NoError(t, model.SavePromptAuditConfig(cfg.ConfigVersion, cfg, []model.PromptAuditEndpoint{{
		Id: "guard-realtime", Name: "Guard Realtime", Protocol: "openai_compatible",
		BaseUrl: guardURL, Model: service.PromptAuditDefaultModel,
		TimeoutMs: 1000, InputLimit: service.PromptAuditDefaultInputLimit, Enabled: true,
	}}))
	service.InvalidatePromptAuditConfig()
	t.Cleanup(func() {
		service.InvalidatePromptAuditConfig()
		common.CryptoSecret = oldSecret
		model.DB = oldDB
		sqlDB, sqlErr := db.DB()
		if sqlErr == nil {
			_ = sqlDB.Close()
		}
	})
}
