package middleware

import (
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var defaultAllowedCredentialOrigins []string

func CORS() gin.HandlerFunc {
	config := cors.DefaultConfig()
	config.AllowCredentials = true
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{
		"Accept",
		"Authorization",
		"Cache-Control",
		"Content-Length",
		"Content-Type",
		"New-API-User",
		"Origin",
		"X-API-Key",
		"X-Requested-With",
		"anthropic-beta",
		"anthropic-version",
	}
	config.AllowOriginWithContextFunc = func(c *gin.Context, origin string) bool {
		return isAllowedCredentialOrigin(c, origin)
	}
	return cors.New(config)
}

func isAllowedCredentialOrigin(c *gin.Context, origin string) bool {
	if origin == "" {
		// Empty origin comes from same-origin or non-browser clients;
		// no CORS headers needed. Return false to avoid unnecessary
		// credential headers (gin-cors won't echo an empty ACAO anyway).
		return false
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	requestHost := strings.ToLower(c.Request.Host)
	if requestHost != "" {
		if host == strings.ToLower(strings.Split(requestHost, ":")[0]) {
			return true
		}
	}
	for _, allowedOrigin := range allowedCredentialOrigins() {
		if isAllowedCredentialDomain(host, allowedOrigin) {
			return true
		}
	}
	return false
}

func isAllowedCredentialDomain(host string, domain string) bool {
	exactOnly := false
	if strings.HasPrefix(domain, "=") {
		exactOnly = true
		domain = strings.TrimPrefix(domain, "=")
	}
	domain = normalizeAllowedCredentialDomain(domain)
	if domain == "" {
		return false
	}
	if exactOnly {
		return host == domain
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func allowedCredentialOrigins() []string {
	if len(constant.CORSAllowedOrigins) > 0 {
		return constant.CORSAllowedOrigins
	}
	return defaultAllowedCredentialOrigins
}

func normalizeAllowedCredentialDomain(domain string) string {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return ""
	}
	if strings.Contains(domain, "://") {
		parsed, err := url.Parse(domain)
		if err == nil && parsed.Hostname() != "" {
			domain = parsed.Hostname()
		}
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")
	domain = strings.TrimSuffix(domain, ".")
	return domain
}

func PoweredBy() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-New-Api-Version", common.Version)
		c.Next()
	}
}
