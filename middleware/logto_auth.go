package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

const (
	LogtoContextSub      = "logto_sub"
	LogtoContextEmail    = "logto_email"
	LogtoContextClientID = "logto_client_id"
	LogtoContextScopes   = "logto_scopes"
	LogtoContextAudience = "logto_audience"
	LogtoContextInfo     = "logto_token_info"

	logtoJWKSCacheTTL = 5 * time.Minute
	logtoJWKSMaxBytes = 1 << 20
)

var (
	ErrLogtoEcosystemDisabled = errors.New("logto_ecosystem_disabled")
	ErrLogtoTokenInvalid      = errors.New("invalid_logto_token")
	ErrLogtoInsufficientScope = errors.New("insufficient_scope")
)

type LogtoAccessTokenClaims struct {
	jwt.RegisteredClaims
	Scope         string `json:"scope"`
	Email         string `json:"email"`
	ClientID      string `json:"client_id"`
	LogtoClientID string `json:"clientId"`
	AZP           string `json:"azp"`
}

type LogtoTokenInfo struct {
	Subject  string
	Email    string
	ClientID string
	Scopes   []string
	Audience []string
}

type logtoJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type logtoJWKS struct {
	Keys []logtoJWK `json:"keys"`
}

type logtoJWKSCacheState struct {
	mu        sync.RWMutex
	uri       string
	keys      map[string]any
	singleKey any
	expiresAt time.Time
}

var logtoJWKSCache = &logtoJWKSCacheState{}

func LogtoAuth(requiredScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		info, err := ValidateLogtoAccessToken(c.GetHeader("Authorization"), requiredScopes...)
		if err != nil {
			status := http.StatusUnauthorized
			message := ErrLogtoTokenInvalid.Error()
			if errors.Is(err, ErrLogtoEcosystemDisabled) {
				status = http.StatusForbidden
				message = ErrLogtoEcosystemDisabled.Error()
			} else if errors.Is(err, ErrLogtoInsufficientScope) {
				status = http.StatusForbidden
				message = ErrLogtoInsufficientScope.Error()
			}
			c.JSON(status, gin.H{
				"success": false,
				"message": message,
			})
			c.Abort()
			return
		}

		c.Set(LogtoContextSub, info.Subject)
		c.Set(LogtoContextEmail, info.Email)
		c.Set(LogtoContextClientID, info.ClientID)
		c.Set(LogtoContextScopes, info.Scopes)
		c.Set(LogtoContextAudience, info.Audience)
		c.Set(LogtoContextInfo, info)
		c.Next()
	}
}

func ValidateLogtoAccessToken(authHeader string, requiredScopes ...string) (*LogtoTokenInfo, error) {
	settings := system_setting.GetLogtoEcosystemSettings()
	if !settings.Enabled {
		return nil, ErrLogtoEcosystemDisabled
	}
	if strings.TrimSpace(settings.Issuer) == "" || strings.TrimSpace(settings.Audience) == "" || strings.TrimSpace(settings.JWKSURI) == "" {
		return nil, fmt.Errorf("%w: missing logto ecosystem settings", ErrLogtoTokenInvalid)
	}

	rawToken, err := extractBearerToken(authHeader)
	if err != nil {
		return nil, err
	}

	claims := &LogtoAccessTokenClaims{}
	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (interface{}, error) {
			return logtoKeyFunc(token, settings.JWKSURI)
		},
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(settings.Issuer),
		jwt.WithAudience(settings.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(30*time.Second),
	)
	if err != nil || token == nil || !token.Valid {
		return nil, fmt.Errorf("%w: %v", ErrLogtoTokenInvalid, err)
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return nil, fmt.Errorf("%w: missing sub", ErrLogtoTokenInvalid)
	}

	scopes := splitScopes(claims.Scope)
	allRequiredScopes := append([]string{}, settings.RequiredScopes...)
	allRequiredScopes = append(allRequiredScopes, requiredScopes...)
	if !hasRequiredScopes(scopes, allRequiredScopes) {
		return nil, ErrLogtoInsufficientScope
	}

	clientID := strings.TrimSpace(claims.ClientID)
	if clientID == "" {
		clientID = strings.TrimSpace(claims.LogtoClientID)
	}
	if clientID == "" {
		clientID = strings.TrimSpace(claims.AZP)
	}

	return &LogtoTokenInfo{
		Subject:  claims.Subject,
		Email:    strings.TrimSpace(claims.Email),
		ClientID: clientID,
		Scopes:   scopes,
		Audience: []string(claims.Audience),
	}, nil
}

func extractBearerToken(authHeader string) (string, error) {
	parts := strings.Fields(strings.TrimSpace(authHeader))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", ErrLogtoTokenInvalid
	}
	return parts[1], nil
}

func logtoKeyFunc(token *jwt.Token, jwksURI string) (any, error) {
	kid, _ := token.Header["kid"].(string)
	key, err := getLogtoSigningKey(jwksURI, kid)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLogtoTokenInvalid, err)
	}
	switch key.(type) {
	case *rsa.PublicKey:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			return key, nil
		}
		if _, ok := token.Method.(*jwt.SigningMethodRSAPSS); ok {
			return key, nil
		}
	case *ecdsa.PublicKey:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); ok {
			return key, nil
		}
	}
	return nil, fmt.Errorf("%w: signing method does not match jwk type", ErrLogtoTokenInvalid)
}

func getLogtoSigningKey(jwksURI string, kid string) (any, error) {
	if key, ok := getCachedLogtoSigningKey(jwksURI, kid); ok {
		return key, nil
	}
	if err := refreshLogtoJWKS(jwksURI); err != nil {
		return nil, err
	}
	if key, ok := getCachedLogtoSigningKey(jwksURI, kid); ok {
		return key, nil
	}
	if kid == "" {
		return nil, errors.New("jwks has no usable single key")
	}
	return nil, fmt.Errorf("jwk kid %q not found", kid)
}

func getCachedLogtoSigningKey(jwksURI string, kid string) (any, bool) {
	logtoJWKSCache.mu.RLock()
	defer logtoJWKSCache.mu.RUnlock()
	if logtoJWKSCache.uri != jwksURI || time.Now().After(logtoJWKSCache.expiresAt) {
		return nil, false
	}
	if kid == "" && logtoJWKSCache.singleKey != nil {
		return logtoJWKSCache.singleKey, true
	}
	key, ok := logtoJWKSCache.keys[kid]
	return key, ok
}

func refreshLogtoJWKS(jwksURI string) error {
	req, err := http.NewRequest(http.MethodGet, jwksURI, nil)
	if err != nil {
		return err
	}
	client := http.Client{Timeout: 5 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", res.StatusCode)
	}

	var doc logtoJWKS
	if err := common.DecodeJson(io.LimitReader(res.Body, logtoJWKSMaxBytes), &doc); err != nil {
		return err
	}
	keys := make(map[string]any)
	for _, jwk := range doc.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		key, err := jwk.publicKey()
		if err != nil {
			continue
		}
		keys[jwk.Kid] = key
	}
	if len(keys) == 0 {
		return errors.New("jwks has no usable signing keys")
	}

	var singleKey any
	if len(keys) == 1 {
		for _, key := range keys {
			singleKey = key
		}
	}

	logtoJWKSCache.mu.Lock()
	logtoJWKSCache.uri = jwksURI
	logtoJWKSCache.keys = keys
	logtoJWKSCache.singleKey = singleKey
	logtoJWKSCache.expiresAt = time.Now().Add(logtoJWKSCacheTTL)
	logtoJWKSCache.mu.Unlock()
	return nil
}

func (jwk logtoJWK) publicKey() (any, error) {
	switch jwk.Kty {
	case "RSA":
		n, err := decodeBase64URLBigInt(jwk.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeBase64URLBigInt(jwk.E)
		if err != nil {
			return nil, err
		}
		if !e.IsInt64() || e.Int64() <= 0 {
			return nil, errors.New("invalid rsa exponent")
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
	case "EC":
		curve := curveByJWKName(jwk.Crv)
		if curve == nil {
			return nil, errors.New("unsupported ec curve")
		}
		x, err := decodeBase64URLBigInt(jwk.X)
		if err != nil {
			return nil, err
		}
		y, err := decodeBase64URLBigInt(jwk.Y)
		if err != nil {
			return nil, err
		}
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("ec point is not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, errors.New("unsupported jwk key type")
	}
}

func decodeBase64URLBigInt(value string) (*big.Int, error) {
	if value == "" {
		return nil, errors.New("empty jwk integer")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(value)
		if err != nil {
			return nil, err
		}
	}
	return new(big.Int).SetBytes(decoded), nil
}

func curveByJWKName(name string) elliptic.Curve {
	switch name {
	case "P-256":
		return elliptic.P256()
	case "P-384":
		return elliptic.P384()
	case "P-521":
		return elliptic.P521()
	default:
		return nil
	}
}

func splitScopes(scope string) []string {
	parts := strings.Fields(scope)
	result := make([]string, 0, len(parts))
	seen := make(map[string]bool)
	for _, part := range parts {
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		result = append(result, part)
	}
	return result
}

func hasRequiredScopes(scopes []string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	scopeSet := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		scopeSet[scope] = true
	}
	for _, scope := range required {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			continue
		}
		if !scopeSet[scope] {
			return false
		}
	}
	return true
}
