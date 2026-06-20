package imageutil

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"

	"github.com/gin-gonic/gin"
)

func newImageUtilTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	return c, rec
}

func TestWriteResponseBytesUsesCompletedSSEWhenClientStreams(t *testing.T) {
	c, rec := newImageUtilTestContext()
	info := &relaycommon.RelayInfo{
		ImageClientStream: true,
		RelayMode:         relayconstant.RelayModeImagesGenerations,
	}

	apiErr := WriteResponseBytes(c, nil, info, []byte(`{"created":1,"data":[{"url":"https://example.com/a.png"},{"url":"https://example.com/b.png"}]}`))
	if apiErr != nil {
		t.Fatal(apiErr)
	}

	out := rec.Body.String()
	if !strings.Contains(out, "event: image_generation.completed") {
		t.Fatalf("missing generation completed event in %q", out)
	}
	if strings.Count(out, "event: image_generation.completed") != 2 {
		t.Fatalf("expected one completed event per image in %q", out)
	}
	if !strings.Contains(out, `"url":"https://example.com/a.png"`) || !strings.Contains(out, `"url":"https://example.com/b.png"`) {
		t.Fatalf("missing image payload in %q", out)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/event-stream") {
		t.Fatalf("expected text/event-stream content type, got %q", got)
	}
}

func TestWriteResponseBytesUsesEditCompletedEvent(t *testing.T) {
	c, rec := newImageUtilTestContext()
	info := &relaycommon.RelayInfo{
		ImageClientStream: true,
		RelayMode:         relayconstant.RelayModeImagesEdits,
	}

	apiErr := WriteResponseBytes(c, nil, info, []byte(`{"created":1,"data":[{"b64_json":"abc"}]}`))
	if apiErr != nil {
		t.Fatal(apiErr)
	}

	out := rec.Body.String()
	if !strings.Contains(out, "event: image_edit.completed") {
		t.Fatalf("missing edit completed event in %q", out)
	}
	if !strings.Contains(out, `"type":"image_edit.completed"`) {
		t.Fatalf("missing edit event type in %q", out)
	}
}

func TestWriteResponseBytesUsesJSONWhenClientDoesNotStream(t *testing.T) {
	c, rec := newImageUtilTestContext()
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	info := &relaycommon.RelayInfo{ImageClientStream: false}

	apiErr := WriteResponseBytes(c, resp, info, []byte(`{"created":1,"data":[{"b64_json":"abc"}]}`))
	if apiErr != nil {
		t.Fatal(apiErr)
	}

	out := rec.Body.String()
	if strings.Contains(out, "event:") {
		t.Fatalf("did not expect SSE event in %q", out)
	}
	if !strings.Contains(out, `"b64_json":"abc"`) {
		t.Fatalf("missing image payload in %q", out)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected application/json content type, got %q", got)
	}
}

func TestNormalizeUsageKeepsImageInputTokens(t *testing.T) {
	usage := &dto.Usage{
		InputTokens:  2,
		OutputTokens: 3,
		TotalTokens:  5,
		InputTokensDetails: &dto.InputTokenDetails{
			ImageTokens: 7,
			TextTokens:  11,
		},
	}

	NormalizeUsage(usage)

	if usage.PromptTokens != 2 || usage.CompletionTokens != 3 || usage.TotalTokens != 5 {
		t.Fatalf("unexpected normalized usage: %#v", usage)
	}
	if usage.PromptTokensDetails.ImageTokens != 7 || usage.PromptTokensDetails.TextTokens != 11 {
		t.Fatalf("unexpected token details: %#v", usage.PromptTokensDetails)
	}
}
