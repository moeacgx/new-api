package relay

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/logger"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/model_setting"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/types"
	"github.com/bytedance/gopkg/util/gopool"

	"github.com/gin-gonic/gin"
)

func ImageHelper(c *gin.Context, info *relaycommon.RelayInfo) (newAPIError *types.NewAPIError) {
	info.InitChannelMeta(c)

	imageReq, ok := info.Request.(*dto.ImageRequest)
	if !ok {
		return types.NewErrorWithStatusCode(fmt.Errorf("invalid request type, expected dto.ImageRequest, got %T", info.Request), types.ErrorCodeInvalidRequest, http.StatusBadRequest, types.ErrOptionWithSkipRetry())
	}

	request, err := common.DeepCopy(imageReq)
	if err != nil {
		return types.NewError(fmt.Errorf("failed to copy request to ImageRequest: %w", err), types.ErrorCodeInvalidRequest, types.ErrOptionWithSkipRetry())
	}

	err = helper.ModelMappedHelper(c, info, request)
	if err != nil {
		return types.NewError(err, types.ErrorCodeChannelModelMappedError, types.ErrOptionWithSkipRetry())
	}

	adaptor := GetAdaptor(info.ApiType)
	if adaptor == nil {
		return types.NewError(fmt.Errorf("invalid api type: %d", info.ApiType), types.ErrorCodeInvalidApiType, types.ErrOptionWithSkipRetry())
	}
	adaptor.Init(info)

	var requestBody io.Reader
	info.ImageClientStream = request.IsStream(c)
	info.ImageUpstreamStream = shouldUseNativeOpenAIImageStream(info)
	rewriteImageStreamFields := imageStreamFieldsNeedRewrite(request, info.ImageClientStream, info.ImageUpstreamStream)
	info.IsStream = info.ImageUpstreamStream

	// Synthetic stream: client wants SSE but upstream doesn't support it.
	// When ImageSyntheticStreamEnabled is on, we set SSE headers ourselves
	// and start an image-specific ping goroutine to prevent CF/reverse-proxy
	// 504 timeouts.  We intentionally do NOT set info.IsStream = true —
	// IsStream is read by logging, perf metrics, and stream-status code that
	// assume it means "upstream is a real stream".  DisablePing=true prevents
	// doRequest from starting the global ping (which requires
	// PingIntervalEnabled and would affect chat etc.).
	generalSettings := operation_setting.GetGeneralSetting()
	syntheticStream := info.ImageClientStream && !info.ImageUpstreamStream &&
		generalSettings.ImageSyntheticStreamEnabled
	if syntheticStream {
		// Do NOT set info.IsStream = true here.  IsStream is read by logging
		// (service/quota.go), stream-status (service/log_info_generate.go), and
		// perf metrics (pkg/perf_metrics) — setting it true would pollute those
		// paths with "stream" semantics for what is actually a non-stream
		// upstream call.  SSE headers are set explicitly below, and the
		// synthetic-stream response handler (imageutil.WriteResponseBytes) also
		// calls SetEventStreamHeaders idempotently.
		info.DisablePing = true
	}
	prepareImageStreamRequest(request, info.ImageUpstreamStream)

	if (model_setting.GetGlobalSettings().PassThroughRequestEnabled || info.ChannelSetting.PassThroughBodyEnabled) && !info.ImageClientStream && !rewriteImageStreamFields {
		storage, err := common.GetBodyStorage(c)
		if err != nil {
			return types.NewErrorWithStatusCode(err, types.ErrorCodeReadRequestBodyFailed, http.StatusBadRequest, types.ErrOptionWithSkipRetry())
		}
		requestBody = common.ReaderOnly(storage)
	} else {
		convertedRequest, err := adaptor.ConvertImageRequest(c, info, *request)
		if err != nil {
			return types.NewError(err, types.ErrorCodeConvertRequestFailed)
		}
		relaycommon.AppendRequestConversionFromRequest(info, convertedRequest)

		switch convertedRequest.(type) {
		case *bytes.Buffer:
			requestBody = convertedRequest.(io.Reader)
		default:
			jsonData, err := common.Marshal(convertedRequest)
			if err != nil {
				return types.NewError(err, types.ErrorCodeConvertRequestFailed, types.ErrOptionWithSkipRetry())
			}

			// apply param override
			if len(info.ParamOverride) > 0 {
				jsonData, err = relaycommon.ApplyParamOverrideWithRelayInfo(jsonData, info)
				if err != nil {
					return newAPIErrorFromParamOverride(err)
				}
			}

			logger.LogDebug(c, "image request body: %s", jsonData)
			body, size, closer, err := relaycommon.NewOutboundJSONBody(jsonData)
			if err != nil {
				return types.NewError(err, types.ErrorCodeConvertRequestFailed, types.ErrOptionWithSkipRetry())
			}
			defer closer.Close()
			jsonData = nil
			info.UpstreamRequestBodySize = size
			requestBody = body
		}
	}

	statusCodeMappingStr := c.GetString("status_code_mapping")

	// For synthetic-stream image requests, start a dedicated ping keep-alive
	// goroutine BEFORE calling upstream. This prevents Cloudflare and other
	// reverse-proxies from returning 504 when image generation takes a long
	// time. The pinger is independent of the global PingIntervalEnabled
	// setting, so it doesn't affect chat or other streaming paths.
	//
	// The ping lifecycle deliberately covers BOTH DoRequest (upstream
	// processing wait) AND the ReadAll phase inside DoResponse (body
	// download).  It is stopped inside imageutil.WriteResponseBytes right
	// before the first SSE data event is written — this avoids concurrent
	// writes to c.Writer.  A deferred safety-net ensures the goroutine
	// is cleaned up on any error/panic path.
	if syntheticStream {
		// Set SSE headers before the ping goroutine starts, so the first
		// PingData flush commits "200 text/event-stream" to the wire.
		// This is idempotent — imageutil.WriteResponseBytes also calls it.
		helper.SetEventStreamHeaders(c)
		pingInterval := time.Duration(generalSettings.PingIntervalSeconds) * time.Second
		if pingInterval <= 0 {
			pingInterval = helper.DefaultPingInterval
		}
		stopImagePing := startImagePingKeepAlive(c, pingInterval)
		// Store stop func for imageutil.WriteResponseBytes to call before
		// writing data events (eliminates concurrent-write race).
		c.Set("stop_image_ping", func() { stopImagePing() })
		// Safety net: ensure the goroutine is always stopped, even on
		// panic, early return, or if WriteResponseBytes is never reached.
		defer helper.StopImagePingIfRunning(c)
	}

	resp, err := adaptor.DoRequest(c, info, requestBody)
	// Do NOT stop ping here — let it keep the client connection alive
	// through the ReadAll phase of DoResponse.

	if err != nil {
		return types.NewOpenAIError(err, types.ErrorCodeDoRequestFailed, http.StatusInternalServerError)
	}
	var httpResp *http.Response
	if resp != nil {
		httpResp = resp.(*http.Response)
		markActualStreamFromResponse(c, info, httpResp)
		if httpResp.StatusCode != http.StatusOK {
			if httpResp.StatusCode == http.StatusCreated && info.ApiType == constant.APITypeReplicate {
				// replicate channel returns 201 Created when using Prefer: wait, treat it as success.
				httpResp.StatusCode = http.StatusOK
			} else {
				newAPIError = service.RelayErrorHandler(c.Request.Context(), httpResp, false)
				// reset status code 重置状态码
				service.ResetStatusCode(newAPIError, statusCodeMappingStr)
				return newAPIError
			}
		}
	}

	usage, newAPIError := adaptor.DoResponse(c, httpResp, info)
	if newAPIError != nil {
		// reset status code 重置状态码
		service.ResetStatusCode(newAPIError, statusCodeMappingStr)
		return newAPIError
	}

	imageN := uint(1)
	if request.N != nil {
		imageN = *request.N
	}

	// n is handled via OtherRatio so it is applied exactly once in quota
	// calculation (both price-based and ratio-based paths).
	// Adaptors may have already set a more accurate count from the
	// upstream response; only set the default when they haven't.
	if info.PriceData.UsePrice { // only price model use N ratio
		if _, hasN := info.PriceData.OtherRatios["n"]; !hasN {
			info.PriceData.AddOtherRatio("n", float64(imageN))
		}
	}

	if usage.(*dto.Usage).TotalTokens == 0 {
		usage.(*dto.Usage).TotalTokens = 1
	}
	if usage.(*dto.Usage).PromptTokens == 0 {
		usage.(*dto.Usage).PromptTokens = 1
	}

	quality := request.Quality
	if quality == "" {
		quality = "standard"
	}

	var logContent []string

	if len(request.Size) > 0 {
		logContent = append(logContent, fmt.Sprintf("大小 %s", request.Size))
	}
	if len(quality) > 0 {
		logContent = append(logContent, fmt.Sprintf("品质 %s", quality))
	}
	if imageN > 0 {
		logContent = append(logContent, fmt.Sprintf("生成数量 %d", imageN))
	}

	service.PostTextConsumeQuota(c, info, usage.(*dto.Usage), logContent)
	return nil
}

func prepareImageStreamRequest(request *dto.ImageRequest, upstreamStream bool) {
	if request == nil {
		return
	}
	if upstreamStream {
		request.Stream = common.GetPointer(true)
		return
	}
	request.Stream = nil
	request.PartialImages = nil
}

func imageStreamFieldsNeedRewrite(request *dto.ImageRequest, clientStream bool, upstreamStream bool) bool {
	if request == nil {
		return false
	}
	if clientStream {
		return true
	}
	if request.PartialImagesExplicit {
		return true
	}
	return request.StreamExplicit && !upstreamStream
}

func shouldUseNativeOpenAIImageStream(info *relaycommon.RelayInfo) bool {
	if info == nil || !info.ImageClientStream || info.ChannelMeta == nil {
		return false
	}
	return info.ChannelSetting.ImagesNativeStreamEnabled
}

func isEventStreamResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")
}

// startImagePingKeepAlive starts a background goroutine that sends
// SSE comment lines (": PING\n\n") at the given interval.  It is used
// ONLY for the synthetic-stream image path and is independent of the
// global PingIntervalEnabled setting, so chat and other streams are
// unaffected.  The interval is read from GeneralSetting.PingIntervalSeconds.
//
// Call the returned cancel func to stop the goroutine.  The cancel func
// blocks until the goroutine has fully exited, so after it returns the
// caller is guaranteed no more writes to c.Writer will occur from this
// goroutine — this eliminates the race between the last ping write and
// the subsequent DoResponse write on the main goroutine.
func startImagePingKeepAlive(c *gin.Context, interval time.Duration) context.CancelFunc {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)

	gopool.Go(func() {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				logger.LogDebug(c, "image ping goroutine panic recovered: %v", r)
			}
		}()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Hard upper bound: image generation should never take longer than
		// 30 minutes.  This is a safety net against goroutine leaks in case
		// both ctx.Done() and c.Request.Context().Done() fail to fire.
		maxDuration := time.NewTimer(30 * time.Minute)
		defer maxDuration.Stop()

		for {
			select {
			case <-ticker.C:
				if err := helper.PingDataWithWriteDeadline(c, 10*time.Second); err != nil {
					logger.LogDebug(c, "image ping error, stopping: %s", err.Error())
					return
				}
				logger.LogDebug(c, "image ping sent")
			case <-ctx.Done():
				return
			case <-c.Request.Context().Done():
				return
			case <-maxDuration.C:
				logger.LogDebug(c, "image ping goroutine max duration reached, stopping")
				return
			}
		}
	})

	return func() {
		cancel()
		wg.Wait()
	}
}
