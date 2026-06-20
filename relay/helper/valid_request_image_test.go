package helper

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	relayconstant "github.com/QuantumNous/new-api/relay/constant"

	"github.com/gin-gonic/gin"
)

func TestGetAndValidOpenAIImageRequestDefaultsStream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-1","prompt":"x"}`))
	c.Request.Header.Set("Content-Type", "application/json")

	req, err := GetAndValidOpenAIImageRequest(c, relayconstant.RelayModeImagesGenerations)
	if err != nil {
		t.Fatal(err)
	}
	if req.Stream == nil || *req.Stream || req.IsStream(c) {
		t.Fatalf("expected omitted stream to default to non-stream, got %#v", req.Stream)
	}
}

func TestGetAndValidOpenAIImageRequestRespectsStreamFalse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-1","prompt":"x","stream":false,"partial_images":0}`))
	c.Request.Header.Set("Content-Type", "application/json")

	req, err := GetAndValidOpenAIImageRequest(c, relayconstant.RelayModeImagesGenerations)
	if err != nil {
		t.Fatal(err)
	}
	if req.Stream == nil || *req.Stream || req.IsStream(c) {
		t.Fatalf("expected explicit stream false, got %#v", req.Stream)
	}
	if req.PartialImages != nil {
		t.Fatalf("expected partial_images removed when stream=false, got %#v", req.PartialImages)
	}
}

func TestGetAndValidOpenAIImageRequestKeepsPartialImagesZero(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-1","prompt":"x","stream":true,"partial_images":0}`))
	c.Request.Header.Set("Content-Type", "application/json")

	req, err := GetAndValidOpenAIImageRequest(c, relayconstant.RelayModeImagesGenerations)
	if err != nil {
		t.Fatal(err)
	}
	if req.PartialImages == nil || *req.PartialImages != 0 {
		t.Fatalf("expected partial_images=0 to be preserved, got %#v", req.PartialImages)
	}
}

func TestGetAndValidOpenAIImageRequestKeepsPartialImagesWhenDefaultStreaming(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", strings.NewReader(`{"model":"gpt-image-1","prompt":"x","stream":true,"partial_images":2}`))
	c.Request.Header.Set("Content-Type", "application/json")

	req, err := GetAndValidOpenAIImageRequest(c, relayconstant.RelayModeImagesGenerations)
	if err != nil {
		t.Fatal(err)
	}
	if req.Stream == nil || !*req.Stream || !req.IsStream(c) {
		t.Fatalf("expected default stream request, got %#v", req.Stream)
	}
	if req.PartialImages == nil || *req.PartialImages != 2 {
		t.Fatalf("expected partial_images preserved for default stream, got %#v", req.PartialImages)
	}
}
