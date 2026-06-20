package dto

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
)

func TestChannelSettingsImagesNativeStreamEnabledRoundTrip(t *testing.T) {
	settings := ChannelSettings{ImagesNativeStreamEnabled: true}

	data, err := common.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}

	var got ChannelSettings
	if err := common.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	if !got.ImagesNativeStreamEnabled {
		t.Fatalf("expected images native stream capability to round-trip, got %#v", got)
	}
}
