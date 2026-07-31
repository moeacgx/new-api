package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestValidateLogtoAccessToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	issuer := "http://logto.example/oidc"
	audience := "https://newapi.example"
	kid := "test-kid"
	payload, err := common.Marshal(logtoJWKS{Keys: []logtoJWK{{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
	}}})
	require.NoError(t, err)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer jwksServer.Close()

	restore := configureLogtoEcosystemSettingsForTest(t, issuer, audience, jwksServer.URL)
	defer restore()

	validToken := signLogtoTestToken(t, privateKey, kid, issuer, audience, time.Now().Add(time.Hour), "ecosystem:me ecosystem:tokens:read")
	info, err := ValidateLogtoAccessToken("Bearer "+validToken, "ecosystem:me")
	require.NoError(t, err)
	require.Equal(t, "logto-user-1", info.Subject)
	require.Equal(t, "user@example.com", info.Email)
	require.Equal(t, "canvas-client", info.ClientID)

	camelClientIDToken := signLogtoTestTokenWithClientClaims(t, privateKey, kid, issuer, audience, time.Now().Add(time.Hour), "ecosystem:me", "", "logto-camel-client", "")
	info, err = ValidateLogtoAccessToken("Bearer "+camelClientIDToken, "ecosystem:me")
	require.NoError(t, err)
	require.Equal(t, "logto-camel-client", info.ClientID)

	_, err = ValidateLogtoAccessToken("Bearer "+validToken, "ecosystem:models:read")
	require.ErrorIs(t, err, ErrLogtoInsufficientScope)

	expiredToken := signLogtoTestToken(t, privateKey, kid, issuer, audience, time.Now().Add(-time.Hour), "ecosystem:me")
	_, err = ValidateLogtoAccessToken("Bearer "+expiredToken, "ecosystem:me")
	require.ErrorIs(t, err, ErrLogtoTokenInvalid)

	wrongIssuerToken := signLogtoTestToken(t, privateKey, kid, issuer+"/wrong", audience, time.Now().Add(time.Hour), "ecosystem:me")
	_, err = ValidateLogtoAccessToken("Bearer "+wrongIssuerToken, "ecosystem:me")
	require.ErrorIs(t, err, ErrLogtoTokenInvalid)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	badSignatureToken := signLogtoTestToken(t, otherKey, kid, issuer, audience, time.Now().Add(time.Hour), "ecosystem:me")
	_, err = ValidateLogtoAccessToken("Bearer "+badSignatureToken, "ecosystem:me")
	require.ErrorIs(t, err, ErrLogtoTokenInvalid)

}

func configureLogtoEcosystemSettingsForTest(t *testing.T, issuer string, audience string, jwksURI string) func() {
	t.Helper()
	settings := system_setting.GetLogtoEcosystemSettings()
	original := *settings
	resetLogtoJWKSCacheForTest()
	*settings = system_setting.LogtoEcosystemSettings{
		Enabled:        true,
		Issuer:         issuer,
		Audience:       audience,
		JWKSURI:        jwksURI,
		RequiredScopes: []string{},
		BaseURL:        "https://newapi.example",
	}
	return func() {
		*settings = original
		resetLogtoJWKSCacheForTest()
	}
}

func TestLogtoAuthMiddlewareRejectsMissingBearer(t *testing.T) {
	oldSettings := *system_setting.GetLogtoEcosystemSettings()
	*system_setting.GetLogtoEcosystemSettings() = system_setting.LogtoEcosystemSettings{Enabled: true, Issuer: "x", Audience: "y", JWKSURI: "z"}
	defer func() {
		*system_setting.GetLogtoEcosystemSettings() = oldSettings
	}()
	info, err := ValidateLogtoAccessToken("", "ecosystem:me")
	require.ErrorIs(t, err, ErrLogtoTokenInvalid)
	require.Nil(t, info)
}

func signLogtoTestToken(t *testing.T, privateKey *rsa.PrivateKey, kid string, issuer string, audience string, expiresAt time.Time, scope string) string {
	t.Helper()
	return signLogtoTestTokenWithClientClaims(t, privateKey, kid, issuer, audience, expiresAt, scope, "canvas-client", "", "")
}

func signLogtoTestTokenWithClientClaims(t *testing.T, privateKey *rsa.PrivateKey, kid string, issuer string, audience string, expiresAt time.Time, scope string, clientID string, logtoClientID string, azp string) string {
	t.Helper()
	claims := LogtoAccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "logto-user-1",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		},
		Scope:         scope,
		Email:         "user@example.com",
		ClientID:      clientID,
		LogtoClientID: logtoClientID,
		AZP:           azp,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return signed
}

func TestValidateLogtoAccessTokenDisabled(t *testing.T) {
	settings := system_setting.GetLogtoEcosystemSettings()
	original := *settings
	*settings = system_setting.LogtoEcosystemSettings{}
	defer func() {
		*settings = original
	}()
	_, err := ValidateLogtoAccessToken("Bearer token", "ecosystem:me")
	require.ErrorIs(t, err, ErrLogtoEcosystemDisabled)
}

func resetLogtoJWKSCacheForTest() {
	logtoJWKSCache.mu.Lock()
	defer logtoJWKSCache.mu.Unlock()
	logtoJWKSCache.uri = ""
	logtoJWKSCache.keys = nil
	logtoJWKSCache.singleKey = nil
	logtoJWKSCache.expiresAt = time.Time{}
}
