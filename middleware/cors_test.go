package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestCORSPreflightAllowsCanvasJsonRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withCORSAllowedOrigins(t, []string{"maolaoapi.com"})
	router := gin.New()
	router.Use(CORS())
	router.POST("/canvas/v1/images/generations", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	request := httptest.NewRequest(http.MethodOptions, "/canvas/v1/images/generations?group=Image2", nil)
	request.Header.Set("Origin", "https://canvas.maolaoapi.com")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "content-type")

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusNoContent, recorder.Code)
	require.Equal(t, "https://canvas.maolaoapi.com", recorder.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, strings.ToLower(recorder.Header().Get("Access-Control-Allow-Headers")), "content-type")
}

func TestCORSAllowsConfiguredCredentialOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withCORSAllowedOrigins(t, []string{
		"eggai.icu",
		"example.com",
		"*.api.example.net",
		"https://console.example.org",
	})
	router := gin.New()
	router.Use(CORS())
	router.POST("/v1/chat/completions", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	allowedOrigins := []string{
		"https://eggai.icu",
		"https://api.eggai.icu",
		"https://canvas.api.eggai.icu",
		"https://app.example.com",
		"https://foo.api.example.net",
		"https://console.example.org",
	}
	for _, origin := range allowedOrigins {
		request := httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("Access-Control-Request-Method", http.MethodPost)
		request.Header.Set("Access-Control-Request-Headers", "authorization,content-type")

		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)

		require.Equal(t, http.StatusNoContent, recorder.Code, origin)
		require.Equal(t, origin, recorder.Header().Get("Access-Control-Allow-Origin"), origin)
	}
}

func TestCORSRejectsLookalikeConfiguredOrigins(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withCORSAllowedOrigins(t, []string{
		"eggai.icu",
		"*.api.example.net",
	})

	cases := []string{
		"https://eggai.icu.evil.com",
		"https://fakeeggai.icu",
		"https://example.net",
	}
	for _, origin := range cases {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "https://newapi.local/v1/models", nil)

		require.False(t, isAllowedCredentialOrigin(c, origin), origin)
	}
}

func withCORSAllowedOrigins(t *testing.T, origins []string) {
	t.Helper()
	originalOrigins := constant.CORSAllowedOrigins
	constant.CORSAllowedOrigins = origins
	t.Cleanup(func() {
		constant.CORSAllowedOrigins = originalOrigins
	})
}
