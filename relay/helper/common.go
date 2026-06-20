package helper

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/logger"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const timingDiagnosticsRelayInfoKey = "timing_diagnostics_relay_info"

func SetTimingDiagnosticsRelayInfo(c *gin.Context, info *relaycommon.RelayInfo) {
	if c == nil || info == nil {
		return
	}
	c.Set(timingDiagnosticsRelayInfoKey, info)
}

func markFirstDownstreamWrite(c *gin.Context) {
	if c == nil {
		return
	}
	if info, ok := c.Get(timingDiagnosticsRelayInfoKey); ok {
		if relayInfo, ok := info.(*relaycommon.RelayInfo); ok && relayInfo != nil {
			relayInfo.MarkTimingFirstDownstreamWrite()
		}
	}
}

func FlushWriter(c *gin.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("flush panic recovered: %v", r)
		}
	}()

	if c == nil || c.Writer == nil {
		return nil
	}

	if c.Request != nil && c.Request.Context().Err() != nil {
		return fmt.Errorf("request context done: %w", c.Request.Context().Err())
	}

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		return errors.New("streaming error: flusher not found")
	}

	flusher.Flush()
	return nil
}

func SetEventStreamHeaders(c *gin.Context) {
	// 检查是否已经设置过头部
	if _, exists := c.Get("event_stream_headers_set"); exists {
		return
	}

	// 设置标志，表示头部已经设置过
	c.Set("event_stream_headers_set", true)

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
}

func ClaudeData(c *gin.Context, resp dto.ClaudeResponse) error {
	if c.GetBool("sensitive_response_stream_blocked") {
		return nil
	}
	jsonData, err := common.Marshal(resp)
	if err != nil {
		common.SysError("error marshalling stream response: " + err.Error())
	} else {
		if blocked, err := writeFilteredEventData(c, fmt.Sprintf("event: %s\n", resp.Type), string(jsonData)); blocked || err != nil {
			return err
		}
	}
	_ = FlushWriter(c)
	return nil
}

func ClaudeChunkData(c *gin.Context, resp dto.ClaudeResponse, data string) {
	if c.GetBool("sensitive_response_stream_blocked") {
		return
	}
	if blocked, _ := writeFilteredEventData(c, fmt.Sprintf("event: %s\n", resp.Type), data); blocked {
		return
	}
	_ = FlushWriter(c)
}

func ResponseChunkData(c *gin.Context, resp dto.ResponsesStreamResponse, data string) {
	if c.GetBool("sensitive_response_stream_blocked") {
		return
	}
	if blocked, _ := writeFilteredEventData(c, fmt.Sprintf("event: %s\n", resp.Type), data); blocked {
		return
	}
	_ = FlushWriter(c)
}

func EventData(c *gin.Context, eventName string, data string) error {
	if strings.TrimSpace(eventName) == "" {
		return StringData(c, data)
	}
	if c.GetBool("sensitive_response_stream_blocked") {
		return nil
	}
	if blocked, err := writeFilteredEventData(c, fmt.Sprintf("event: %s\n", eventName), data); blocked || err != nil {
		return err
	}
	return FlushWriter(c)
}

func FinalEventData(c *gin.Context, eventName string, data string) error {
	eventName = strings.TrimSpace(eventName)
	if err := EventData(c, eventName, data); err != nil {
		return err
	}
	if c.GetBool("sensitive_response_stream_blocked") {
		return nil
	}
	items := service.FlushSensitiveStreamDataForSend(c)
	if len(items) == 0 {
		return nil
	}
	if eventName == "" {
		writeStreamDataItems(c, items)
		return FlushWriter(c)
	}
	writeFilteredEventDataItems(c, fmt.Sprintf("event: %s\n", eventName), items)
	return FlushWriter(c)
}

func StringData(c *gin.Context, str string) error {
	if c == nil || c.Writer == nil {
		return errors.New("context or writer is nil")
	}
	if c.GetBool("sensitive_response_stream_blocked") {
		return nil
	}

	if c.Request != nil && c.Request.Context().Err() != nil {
		return fmt.Errorf("request context done: %w", c.Request.Context().Err())
	}

	result, err := service.ApplySensitiveFilterToStreamDataForSend(c, str)
	if err != nil {
		return err
	}
	if result.Blocked {
		logger.LogWarn(c, fmt.Sprintf("upstream stream response blocked by sensitive rules: %s", service.FormatSensitiveFilterMatches(result.Matches)))
		c.Set("sensitive_response_stream_blocked", true)
		writeSensitiveStreamErrorEvent(c)
		return FlushWriter(c)
	}
	writeStreamDataItems(c, result.Data)
	return FlushWriter(c)
}

func PingData(c *gin.Context) error {
	if c == nil || c.Writer == nil {
		return errors.New("context or writer is nil")
	}

	if c.Request != nil && c.Request.Context().Err() != nil {
		return fmt.Errorf("request context done: %w", c.Request.Context().Err())
	}

	if _, err := c.Writer.Write([]byte(": PING\n\n")); err != nil {
		return fmt.Errorf("write ping data failed: %w", err)
	}
	return FlushWriter(c)
}

func PingDataWithWriteDeadline(c *gin.Context, timeout time.Duration) error {
	if c == nil || c.Writer == nil {
		return errors.New("context or writer is nil")
	}
	if timeout <= 0 {
		return PingData(c)
	}

	rc := http.NewResponseController(c.Writer)
	if err := rc.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		logger.LogDebug(c, "set ping write deadline failed: %s", err.Error())
	}
	err := PingData(c)
	if resetErr := rc.SetWriteDeadline(time.Time{}); resetErr != nil {
		logger.LogDebug(c, "reset ping write deadline failed: %s", resetErr.Error())
	}
	return err
}

func ObjectData(c *gin.Context, object interface{}) error {
	if object == nil {
		return errors.New("object is nil")
	}
	jsonData, err := common.Marshal(object)
	if err != nil {
		return fmt.Errorf("error marshalling object: %w", err)
	}
	return StringData(c, string(jsonData))
}

func writeFilteredEventData(c *gin.Context, eventLine string, data string) (bool, error) {
	result, err := service.ApplySensitiveFilterToStreamDataForSend(c, data)
	if err != nil {
		return false, err
	}
	if result.Blocked {
		logger.LogWarn(c, fmt.Sprintf("upstream stream response blocked by sensitive rules: %s", service.FormatSensitiveFilterMatches(result.Matches)))
		c.Set("sensitive_response_stream_blocked", true)
		writeSensitiveStreamErrorEvent(c)
		_ = FlushWriter(c)
		return true, nil
	}
	writeFilteredEventDataItems(c, eventLine, result.Data)
	return false, nil
}

func writeStreamDataItems(c *gin.Context, items []string) {
	for _, item := range items {
		markFirstDownstreamWrite(c)
		c.Render(-1, common.CustomEvent{Data: "data: " + item})
	}
}

func writeFilteredEventDataItems(c *gin.Context, eventLine string, items []string) {
	for _, item := range items {
		markFirstDownstreamWrite(c)
		c.Render(-1, common.CustomEvent{Data: eventLine})
		c.Render(-1, common.CustomEvent{Data: "data: " + item})
	}
}

func writeSensitiveStreamErrorEvent(c *gin.Context) {
	c.Render(-1, common.CustomEvent{Data: "event: error\n"})
	c.Render(-1, common.CustomEvent{Data: "data: " + string(service.SensitiveFilterOpenAIErrorBody(c))})
}

// WriteSSEError writes an error as an SSE event to an already-committed
// event-stream response.  Call this instead of c.JSON() when
// c.Writer.Written() is true — at that point the HTTP status code and
// Content-Type headers are already on the wire and cannot be changed.
//
// The errorPayload is marshaled to JSON and sent as:
//
//	event: error
//	data: <json>
//
// This follows the same format as writeSensitiveStreamErrorEvent and is
// compatible with OpenAI SDK streaming error handling.
func WriteSSEError(c *gin.Context, errorPayload any) {
	// If the client already disconnected, don't bother writing.
	if c.Request != nil && c.Request.Context().Err() != nil {
		logger.LogDebug(c, "WriteSSEError: client already disconnected, skipping")
		return
	}

	errBody, err := common.Marshal(errorPayload)
	if err != nil {
		errBody = []byte(`{"error":{"message":"internal error","type":"server_error"}}`)
	}
	c.Render(-1, common.CustomEvent{Data: "event: error\n"})
	c.Render(-1, common.CustomEvent{Data: "data: " + string(errBody)})
	if err := FlushWriter(c); err != nil {
		logger.LogDebug(c, "WriteSSEError: flush failed: %s", err.Error())
	}
	// Send [DONE] terminator so clients cleanly close the stream.
	// Use StringData directly instead of Done() because Done() has
	// sensitive-filter flush logic that is irrelevant on error paths.
	_ = StringData(c, "[DONE]")
}

// StopImagePingIfRunning stops the synthetic-stream image ping goroutine
// stored in the "stop_image_ping" context key, if it is still running.
// It is safe to call multiple times — the second call is a no-op.
//
// Two call sites:
//   - imageutil.WriteResponseBytes — right before writing SSE data events,
//     so ping and data writes never race on c.Writer.
//   - image_handler.go defer — safety net for error/panic paths where
//     WriteResponseBytes is never reached.
func StopImagePingIfRunning(c *gin.Context) {
	if v, ok := c.Get("stop_image_ping"); ok && v != nil {
		v.(func())()
		c.Set("stop_image_ping", nil)
	}
}

func Done(c *gin.Context) {
	if c.GetBool("sensitive_response_stream_blocked") {
		return
	}
	writeStreamDataItems(c, service.FlushSensitiveStreamDataForSend(c))
	_ = StringData(c, "[DONE]")
}

func WssString(c *gin.Context, ws *websocket.Conn, str string) error {
	if ws == nil {
		logger.LogError(c, "websocket connection is nil")
		return errors.New("websocket connection is nil")
	}
	//common.LogInfo(c, fmt.Sprintf("sending message: %s", str))
	return ws.WriteMessage(1, []byte(str))
}

func WssObject(c *gin.Context, ws *websocket.Conn, object interface{}) error {
	jsonData, err := common.Marshal(object)
	if err != nil {
		return fmt.Errorf("error marshalling object: %w", err)
	}
	if ws == nil {
		logger.LogError(c, "websocket connection is nil")
		return errors.New("websocket connection is nil")
	}
	//common.LogInfo(c, fmt.Sprintf("sending message: %s", jsonData))
	return ws.WriteMessage(1, jsonData)
}

func WssError(c *gin.Context, ws *websocket.Conn, openaiError types.OpenAIError) {
	if ws == nil {
		return
	}
	errorObj := &dto.RealtimeEvent{
		Type:    "error",
		EventId: GetLocalRealtimeID(c),
		Error:   &openaiError,
	}
	_ = WssObject(c, ws, errorObj)
}

func GetResponseID(c *gin.Context) string {
	logID := c.GetString(common.RequestIdKey)
	return fmt.Sprintf("chatcmpl-%s", logID)
}

func GetLocalRealtimeID(c *gin.Context) string {
	logID := c.GetString(common.RequestIdKey)
	return fmt.Sprintf("evt_%s", logID)
}

func GenerateStartEmptyResponse(id string, createAt int64, model string, systemFingerprint *string) *dto.ChatCompletionsStreamResponse {
	return &dto.ChatCompletionsStreamResponse{
		Id:                id,
		Object:            "chat.completion.chunk",
		Created:           createAt,
		Model:             model,
		SystemFingerprint: systemFingerprint,
		Choices: []dto.ChatCompletionsStreamResponseChoice{
			{
				Delta: dto.ChatCompletionsStreamResponseChoiceDelta{
					Role:    "assistant",
					Content: common.GetPointer(""),
				},
			},
		},
	}
}

func GenerateStopResponse(id string, createAt int64, model string, finishReason string) *dto.ChatCompletionsStreamResponse {
	return &dto.ChatCompletionsStreamResponse{
		Id:                id,
		Object:            "chat.completion.chunk",
		Created:           createAt,
		Model:             model,
		SystemFingerprint: nil,
		Choices: []dto.ChatCompletionsStreamResponseChoice{
			{
				FinishReason: &finishReason,
			},
		},
	}
}

func GenerateFinalUsageResponse(id string, createAt int64, model string, usage dto.Usage) *dto.ChatCompletionsStreamResponse {
	return &dto.ChatCompletionsStreamResponse{
		Id:                id,
		Object:            "chat.completion.chunk",
		Created:           createAt,
		Model:             model,
		SystemFingerprint: nil,
		Choices:           make([]dto.ChatCompletionsStreamResponseChoice, 0),
		Usage:             &usage,
	}
}
