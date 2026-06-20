package openai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"

	"github.com/gin-gonic/gin"
)

func newImageStreamTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	return c, rec
}

func TestOpenAIImageStreamHandlerForwardsNamedEventsAndUsage(t *testing.T) {
	c, rec := newImageStreamTestContext()
	body := strings.Join([]string{
		"event: image_generation.partial_image",
		`data: {"type":"image_generation.partial_image","partial_image_index":0,"b64_json":"abc"}`,
		"",
		"event: image_generation.completed",
		`data: {"type":"image_generation.completed","b64_json":"final","usage":{"input_tokens":2,"output_tokens":3,"total_tokens":5}}`,
		"",
	}, "\n")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	info := &relaycommon.RelayInfo{
		IsStream:            true,
		ImageClientStream:   true,
		ImageUpstreamStream: true,
		RelayMode:           relayconstant.RelayModeImagesGenerations,
		ChannelMeta:         &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeOpenAI},
	}

	usage, err := OpenAIImageStreamHandler(c, info, resp)
	if err != nil {
		t.Fatal(err)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: image_generation.partial_image") {
		t.Fatalf("missing partial event in %q", out)
	}
	if !strings.Contains(out, "event: image_generation.completed") {
		t.Fatalf("missing completed event in %q", out)
	}
	if usage.TotalTokens != 5 || usage.PromptTokens != 2 || usage.CompletionTokens != 3 {
		t.Fatalf("unexpected usage: %#v", usage)
	}
}

func TestOpenAIImageSyntheticStreamHandlerUsesEditEvent(t *testing.T) {
	c, rec := newImageStreamTestContext()
	body := `{"created":1,"data":[{"b64_json":"final"}],"usage":{"input_tokens":4,"output_tokens":6,"total_tokens":10}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	info := &relaycommon.RelayInfo{
		ImageClientStream:   true,
		ImageUpstreamStream: false,
		RelayMode:           relayconstant.RelayModeImagesEdits,
		ChannelMeta:         &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeOpenAI},
	}

	usage, err := OpenAIImageSyntheticStreamHandler(c, info, resp)
	if err != nil {
		t.Fatal(err)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: image_edit.completed") {
		t.Fatalf("missing edit completed event in %q", out)
	}
	if !strings.Contains(out, `"b64_json":"final"`) {
		t.Fatalf("missing image payload in %q", out)
	}
	if !strings.Contains(out, `"type":"image_edit.completed"`) {
		t.Fatalf("missing edit event type in %q", out)
	}
	if usage.TotalTokens != 10 || usage.PromptTokens != 4 || usage.CompletionTokens != 6 {
		t.Fatalf("unexpected usage: %#v", usage)
	}
}

func TestOpenAIImageHandlerFallsBackToSyntheticStreamWhenNativeCapabilityReturnsJSON(t *testing.T) {
	c, rec := newImageStreamTestContext()
	body := `{"created":1,"data":[{"b64_json":"final"}],"usage":{"input_tokens":4,"output_tokens":6,"total_tokens":10}}`
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	info := &relaycommon.RelayInfo{
		ImageClientStream:   true,
		ImageUpstreamStream: true,
		RelayMode:           relayconstant.RelayModeImagesGenerations,
		ChannelMeta:         &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeOpenAI},
	}

	usage, err := OpenAIImageHandler(c, info, resp)
	if err != nil {
		t.Fatal(err)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: image_generation.completed") {
		t.Fatalf("missing synthetic completed event in %q", out)
	}
	if strings.Contains(out, "event: image_generation.partial_image") {
		t.Fatalf("unexpected partial event for JSON fallback in %q", out)
	}
	if usage.TotalTokens != 10 || usage.PromptTokens != 4 || usage.CompletionTokens != 6 {
		t.Fatalf("unexpected usage: %#v", usage)
	}
}

func TestOpenAIImageStreamHandlerInfersEventNameFromEditType(t *testing.T) {
	c, rec := newImageStreamTestContext()
	body := strings.Join([]string{
		`data: {"type":"image_edit.partial_image","partial_image_index":0,"b64_json":"abc"}`,
		"",
		`data: {"type":"image_edit.completed","b64_json":"final","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}`,
		"",
	}, "\n")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
	info := &relaycommon.RelayInfo{
		IsStream:            true,
		ImageClientStream:   true,
		ImageUpstreamStream: true,
		RelayMode:           relayconstant.RelayModeImagesEdits,
		ChannelMeta:         &relaycommon.ChannelMeta{ChannelType: constant.ChannelTypeOpenAI},
	}

	usage, err := OpenAIImageStreamHandler(c, info, resp)
	if err != nil {
		t.Fatal(err)
	}
	out := rec.Body.String()
	if !strings.Contains(out, "event: image_edit.partial_image") {
		t.Fatalf("missing edit partial event in %q", out)
	}
	if !strings.Contains(out, "event: image_edit.completed") {
		t.Fatalf("missing edit completed event in %q", out)
	}
	if usage.TotalTokens != 3 || usage.PromptTokens != 1 || usage.CompletionTokens != 2 {
		t.Fatalf("unexpected usage: %#v", usage)
	}
}
