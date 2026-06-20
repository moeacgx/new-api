package dto

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
)

func TestImageRequestStreamPointerSemantics(t *testing.T) {
	var req ImageRequest
	if err := common.Unmarshal([]byte(`{"model":"gpt-image-1","prompt":"x","stream":false,"partial_images":0}`), &req); err != nil {
		t.Fatal(err)
	}
	if req.Stream == nil || *req.Stream {
		t.Fatalf("expected explicit stream=false to be preserved, got %#v", req.Stream)
	}
	if req.PartialImages == nil || *req.PartialImages != 0 {
		t.Fatalf("expected partial_images=0 to be preserved, got %#v", req.PartialImages)
	}
	if req.IsStream(nil) {
		t.Fatal("expected IsStream to respect explicit false")
	}

	var absent ImageRequest
	if err := common.Unmarshal([]byte(`{"model":"gpt-image-1","prompt":"x"}`), &absent); err != nil {
		t.Fatal(err)
	}
	if absent.Stream != nil {
		t.Fatalf("expected raw DTO unmarshal to leave stream nil before validation, got %#v", absent.Stream)
	}
	if absent.IsStream(nil) {
		t.Fatal("expected omitted stream to default to non-streaming")
	}
}
