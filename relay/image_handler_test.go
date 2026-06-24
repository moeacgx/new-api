package relay

import (
	"testing"

	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
)

func TestPrepareImageStreamRequestRemovesStreamForSyntheticMode(t *testing.T) {
	partialImages := 0
	stream := true
	req := &dto.ImageRequest{
		Model:         "gpt-image-1",
		Prompt:        "x",
		Stream:        &stream,
		PartialImages: &partialImages,
	}

	prepareImageStreamRequest(req, false)

	if req.Stream != nil {
		t.Fatalf("expected stream removed for synthetic upstream mode, got %#v", req.Stream)
	}
	if req.PartialImages != nil {
		t.Fatalf("expected partial_images removed for synthetic upstream mode, got %#v", req.PartialImages)
	}
}

func TestPrepareImageStreamRequestRemovesPartialImagesWhenStreamFalse(t *testing.T) {
	partialImages := 0
	stream := false
	req := &dto.ImageRequest{
		Model:         "gpt-image-1",
		Prompt:        "x",
		Stream:        &stream,
		PartialImages: &partialImages,
	}

	prepareImageStreamRequest(req, false)

	if req.Stream != nil {
		t.Fatalf("expected stream removed for non-stream upstream request, got %#v", req.Stream)
	}
	if req.PartialImages != nil {
		t.Fatalf("expected partial_images removed for non-stream upstream request, got %#v", req.PartialImages)
	}
}

func TestPrepareImageStreamRequestKeepsPartialImagesZeroForNativeMode(t *testing.T) {
	partialImages := 0
	stream := false
	req := &dto.ImageRequest{
		Model:         "gpt-image-1",
		Prompt:        "x",
		Stream:        &stream,
		PartialImages: &partialImages,
	}

	prepareImageStreamRequest(req, true)

	if req.Stream == nil || !*req.Stream {
		t.Fatalf("expected stream forced true for native upstream mode, got %#v", req.Stream)
	}
	if req.PartialImages == nil || *req.PartialImages != 0 {
		t.Fatalf("expected partial_images=0 preserved for native upstream mode, got %#v", req.PartialImages)
	}
}

func TestImageStreamFieldsNeedRewriteAllowsNonStreamPassthroughWhenDefaultOnly(t *testing.T) {
	stream := false
	req := &dto.ImageRequest{
		Model:  "gpt-image-1",
		Prompt: "x",
		Stream: &stream,
	}

	if imageStreamFieldsNeedRewrite(req, false, false) {
		t.Fatal("expected no rewrite when non-stream request only has validation default fields")
	}
}

func TestImageStreamFieldsNeedRewriteForExplicitPartialImages(t *testing.T) {
	stream := false
	req := &dto.ImageRequest{
		Model:                 "gpt-image-1",
		Prompt:                "x",
		Stream:                &stream,
		PartialImagesExplicit: true,
	}

	if !imageStreamFieldsNeedRewrite(req, false, false) {
		t.Fatal("expected rewrite when client explicitly sent partial_images")
	}
}

func TestShouldUseNativeOpenAIImageStreamUsesChannelCapability(t *testing.T) {
	info := &relaycommon.RelayInfo{
		ImageClientStream: true,
		ChannelMeta: &relaycommon.ChannelMeta{
			ChannelSetting: dto.ChannelSettings{ImagesNativeStreamEnabled: true},
		},
	}
	if !shouldUseNativeOpenAIImageStream(info) {
		t.Fatal("expected channel capability to enable native image stream")
	}

	info.ChannelSetting.ImagesNativeStreamEnabled = false
	if shouldUseNativeOpenAIImageStream(info) {
		t.Fatal("expected disabled channel capability to use synthetic stream")
	}
}
