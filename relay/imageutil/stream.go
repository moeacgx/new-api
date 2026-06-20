package imageutil

import (
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	relayconstant "github.com/QuantumNous/new-api/relay/constant"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
)

type ResponseWithUsage struct {
	dto.ImageResponse
	Usage dto.Usage `json:"usage,omitempty"`
}

type CompletedEvent struct {
	Type          string     `json:"type"`
	Url           string     `json:"url,omitempty"`
	B64Json       string     `json:"b64_json,omitempty"`
	RevisedPrompt string     `json:"revised_prompt,omitempty"`
	Usage         *dto.Usage `json:"usage,omitempty"`
}

func CompletedEventName(info *relaycommon.RelayInfo) string {
	if info != nil && info.RelayMode == relayconstant.RelayModeImagesEdits {
		return "image_edit.completed"
	}
	return "image_generation.completed"
}

func NormalizeUsage(usage *dto.Usage) {
	if usage == nil {
		return
	}
	if usage.InputTokens > 0 {
		usage.PromptTokens += usage.InputTokens
	}
	if usage.OutputTokens > 0 {
		usage.CompletionTokens += usage.OutputTokens
	}
	if usage.InputTokensDetails != nil {
		usage.PromptTokensDetails.ImageTokens += usage.InputTokensDetails.ImageTokens
		usage.PromptTokensDetails.TextTokens += usage.InputTokensDetails.TextTokens
	}
}

func ExtractUsage(responseBody []byte) *dto.Usage {
	if len(responseBody) == 0 {
		return &dto.Usage{}
	}
	var usageResp dto.SimpleResponse
	if err := common.Unmarshal(responseBody, &usageResp); err != nil {
		return &dto.Usage{}
	}
	NormalizeUsage(&usageResp.Usage)
	return &usageResp.Usage
}

func HasUsage(usage dto.Usage) bool {
	return usage.PromptTokens != 0 ||
		usage.CompletionTokens != 0 ||
		usage.TotalTokens != 0 ||
		usage.InputTokens != 0 ||
		usage.OutputTokens != 0 ||
		usage.InputTokensDetails != nil ||
		usage.PromptTokensDetails.ImageTokens != 0 ||
		usage.PromptTokensDetails.TextTokens != 0 ||
		usage.PromptTokensDetails.AudioTokens != 0 ||
		usage.CompletionTokenDetails.ImageTokens != 0 ||
		usage.CompletionTokenDetails.TextTokens != 0 ||
		usage.CompletionTokenDetails.AudioTokens != 0 ||
		usage.CompletionTokenDetails.ReasoningTokens != 0
}

func WriteResponse(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo, response any) *types.NewAPIError {
	responseBody, err := common.Marshal(response)
	if err != nil {
		return types.NewError(err, types.ErrorCodeBadResponseBody)
	}
	return WriteResponseBytes(c, resp, info, responseBody)
}

func WriteResponseBytes(c *gin.Context, resp *http.Response, info *relaycommon.RelayInfo, responseBody []byte) *types.NewAPIError {
	if info != nil && info.ImageClientStream {
		helper.SetEventStreamHeaders(c)
		if apiErr := writeCompletedEvents(c, info, responseBody); apiErr != nil {
			return apiErr
		}
		return nil
	}
	if resp != nil {
		resp.Header.Set("Content-Type", "application/json")
	}
	service.IOCopyBytesGracefully(c, resp, responseBody)
	return nil
}

func writeCompletedEvents(c *gin.Context, info *relaycommon.RelayInfo, responseBody []byte) *types.NewAPIError {
	eventName := CompletedEventName(info)

	var imageResp ResponseWithUsage
	if err := common.Unmarshal(responseBody, &imageResp); err == nil && len(imageResp.Data) > 0 {
		NormalizeUsage(&imageResp.Usage)
		for i, item := range imageResp.Data {
			event := CompletedEvent{
				Type:          eventName,
				Url:           item.Url,
				B64Json:       item.B64Json,
				RevisedPrompt: item.RevisedPrompt,
			}
			if i == len(imageResp.Data)-1 && HasUsage(imageResp.Usage) {
				usage := imageResp.Usage
				event.Usage = &usage
			}
			eventBytes, err := common.Marshal(event)
			if err != nil {
				return types.NewError(err, types.ErrorCodeBadResponseBody)
			}
			if err := helper.FinalEventData(c, eventName, string(eventBytes)); err != nil {
				return types.NewOpenAIError(err, types.ErrorCodeBadResponse, http.StatusInternalServerError)
			}
		}
		return nil
	}

	if err := helper.FinalEventData(c, eventName, string(responseBody)); err != nil {
		return types.NewOpenAIError(err, types.ErrorCodeBadResponse, http.StatusInternalServerError)
	}
	return nil
}
