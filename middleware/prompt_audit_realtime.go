package middleware

import (
	"net/http"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/types"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var promptAuditRealtimeUpgrader = websocket.Upgrader{
	Subprotocols: []string{"realtime"},
	CheckOrigin: func(_ *http.Request) bool {
		return true
	},
}

const (
	promptAuditRealtimeMaxBufferedBytes  int64 = 16 * 1024 * 1024
	promptAuditRealtimeMaxBufferedFrames       = 1024
	promptAuditRealtimeFirstJSONTimeout        = 30 * time.Second
)

// PromptAuditRealtime 在渠道分配前升级客户端连接，缓存首个 JSON 控制帧
// 及其之前的原始二进制帧，并完成首轮审计。因此首轮被阻断或 Guard
// 失效时，不会选择渠道、占用并发或连接上游。
func PromptAuditRealtime() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c == nil || c.Request == nil {
			return
		}
		cfg, cfgErr := service.GetPromptAuditConfig(c.Request.Context())
		mode := service.PromptAuditEffectiveMode(cfg)
		if cfg == nil && cfgErr != nil {
			// 无法读取配置时不能把审计误判为 off。将本次连接视为
			// blocking，升级后通过 OpenAI 错误事件和 1013 关闭码返回。
			mode = service.PromptAuditModeBlocking
		}
		shouldAudit, groupId, groupName := promptAuditResolveGroupScope(c, cfg)
		guardActive := mode != service.PromptAuditModeOff && shouldAudit
		sensitiveActive := service.ShouldCheckSensitiveBeforeDistribution(c)
		if !guardActive && !sensitiveActive {
			c.Next()
			return
		}
		if guardActive {
			common.SetContextKey(c, constant.ContextKeyPromptAuditGroupId, groupId)
			common.SetContextKey(c, constant.ContextKeyPromptAuditGroupName, groupName)
			// 只有本次连接在渠道分配前完成了首帧 Guard 门禁，后续帧
			// 才继续逐帧 Guard；内置屏蔽词不依赖这个开关。
			common.SetContextKey(c, constant.ContextKeyPromptAuditRealtimeActive, true)
		}

		clientConn, err := promptAuditRealtimeUpgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			c.Abort()
			return
		}
		defer clientConn.Close()
		common.SetContextKey(c, constant.ContextKeyPromptAuditRealtimeClientWs, clientConn)

		if guardActive && cfgErr != nil && mode == service.PromptAuditModeBlocking {
			writePromptAuditRealtimeDecision(c, clientConn, service.PromptAuditDecision{
				Allow: false, ErrorCode: service.PromptGuardUnavailableCode,
				HTTPStatus: http.StatusServiceUnavailable,
				Message:    "提示词安全审计服务暂时不可用",
			})
			c.Abort()
			return
		}

		maxRequestBodyMB := constant.MaxRequestBodyMB
		if maxRequestBodyMB <= 0 {
			// 与普通 HTTP BodyStorage 使用同一默认上限，避免未显式
			// 配置时 Realtime 首轮缓冲意外退化为 1 MiB。
			maxRequestBodyMB = 128
		}
		readLimit := int64(maxRequestBodyMB) * 1024 * 1024
		bufferLimit := readLimit
		if bufferLimit > promptAuditRealtimeMaxBufferedBytes {
			bufferLimit = promptAuditRealtimeMaxBufferedBytes
		}
		clientConn.SetReadLimit(bufferLimit)
		_ = clientConn.SetReadDeadline(time.Now().Add(promptAuditRealtimeFirstJSONTimeout))
		bufferedFrames := make(service.PromptAuditRealtimeFrames, 0, 4)
		var bufferedBytes int64
		for {
			messageType, payload, readErr := clientConn.ReadMessage()
			if readErr != nil {
				if timeoutErr, ok := readErr.(interface{ Timeout() bool }); ok && timeoutErr.Timeout() {
					writePromptAuditRealtimeProtocolError(c, clientConn,
						"等待 Realtime 首个 JSON 控制帧超时", types.ErrorCodeInvalidRequest,
						websocket.ClosePolicyViolation, "missing_realtime_control_frame")
				}
				c.Abort()
				return
			}
			if len(bufferedFrames) >= promptAuditRealtimeMaxBufferedFrames ||
				int64(len(payload)) > bufferLimit-bufferedBytes {
				writePromptAuditRealtimeProtocolError(c, clientConn,
					"Realtime 首轮缓冲数据超过大小限制", types.ErrorCodeInvalidRequest,
					websocket.CloseMessageTooBig, "realtime_audit_buffer_too_large")
				c.Abort()
				return
			}
			bufferedBytes += int64(len(payload))
			bufferedFrames = append(bufferedFrames, service.PromptAuditRealtimeFrame{
				MessageType: messageType,
				Payload:     append([]byte(nil), payload...),
			})

			// 只有无法解析为 JSON 对象的二进制负载才视为原始音频。
			// 它必须继续缓冲到首个 JSON 控制帧完成审计，避免客户端用
			// 二进制首帧提前触发渠道分配；二进制 JSON 本身仍须审计。
			isJSONObject := service.IsPromptAuditRealtimeJSONFrame(payload)
			if messageType == websocket.BinaryMessage && !isJSONObject {
				continue
			}
			if !isJSONObject || !service.IsPromptAuditRealtimeControlFrame(payload) {
				writePromptAuditRealtimeProtocolError(c, clientConn,
					"Realtime 客户端帧必须是带有效 type 的 JSON 对象", types.ErrorCodeInvalidRequest,
					websocket.CloseInvalidFramePayloadData, "invalid_realtime_frame")
				c.Abort()
				return
			}
			// 屏蔽词 mask 可以改写实际转发帧，但 Guard 必须继续审核
			// 客户端提交的原始文本，避免替换内容掩盖语义风险。
			guardPayload := append([]byte(nil), payload...)
			if sensitiveActive {
				filterResult, filteredPayload, filterErr := service.ApplySensitiveFilterToRealtimeRequestFrameBeforeDistribution(c, payload)
				if filterErr != nil {
					writePromptAuditRealtimeProtocolError(c, clientConn,
						"Realtime 客户端帧格式无效", types.ErrorCodeInvalidRequest,
						websocket.CloseInvalidFramePayloadData, "invalid_realtime_frame")
					c.Abort()
					return
				}
				if filterResult.Blocked {
					writePromptAuditRealtimeProtocolError(c, clientConn,
						"sensitive words detected", types.ErrorCodeSensitiveWordsDetected,
						4403, string(types.ErrorCodeSensitiveWordsDetected))
					c.Abort()
					return
				}
				adjustedBytes := bufferedBytes - int64(len(payload)) + int64(len(filteredPayload))
				if adjustedBytes > bufferLimit {
					writePromptAuditRealtimeProtocolError(c, clientConn,
						"Realtime 首轮缓冲数据超过大小限制", types.ErrorCodeInvalidRequest,
						websocket.CloseMessageTooBig, "realtime_audit_buffer_too_large")
					c.Abort()
					return
				}
				bufferedBytes = adjustedBytes
				payload = filteredPayload
				bufferedFrames[len(bufferedFrames)-1].Payload = append([]byte(nil), payload...)
			}
			if guardActive {
				decision, _, auditErr := service.AuditPromptRealtimeFrame(
					c.Request.Context(), promptAuditRealtimeRequest(c, guardPayload, groupId, groupName),
				)
				if auditErr != nil {
					writePromptAuditRealtimeProtocolError(c, clientConn,
						"Realtime 客户端帧格式无效", types.ErrorCodeInvalidRequest,
						websocket.CloseInvalidFramePayloadData, "invalid_realtime_frame")
					c.Abort()
					return
				}
				if !decision.Allow {
					writePromptAuditRealtimeDecision(c, clientConn, decision)
					c.Abort()
					return
				}
			}

			common.SetContextKey(c, constant.ContextKeyPromptAuditRealtimeBufferedFrames, bufferedFrames)
			// 后续帧不再累计在首轮缓冲区中，恢复部署配置的常规单帧上限。
			clientConn.SetReadLimit(readLimit)
			_ = clientConn.SetReadDeadline(time.Time{})
			c.Next()
			return
		}
	}
}

func promptAuditRealtimeRequest(c *gin.Context, payload []byte, groupId int, groupName string) service.PromptAuditRequest {
	return service.PromptAuditRequest{
		RequestId: c.GetString(common.RequestIdKey),
		UserId:    common.GetContextKeyInt(c, constant.ContextKeyUserId),
		Username:  common.GetContextKeyString(c, constant.ContextKeyUserName),
		UserEmail: common.GetContextKeyString(c, constant.ContextKeyUserEmail),
		TokenId:   common.GetContextKeyInt(c, constant.ContextKeyTokenId),
		TokenName: c.GetString("token_name"),
		GroupId:   groupId,
		GroupName: groupName,
		Provider:  "openai",
		Endpoint:  c.Request.URL.Path,
		Protocol:  "openai_realtime",
		Model:     c.Query("model"),
		Body:      payload,
		Stage:     "realtime",
	}
}

func writePromptAuditRealtimeDecision(c *gin.Context, clientConn *websocket.Conn, decision service.PromptAuditDecision) {
	message := decision.Message
	if message == "" {
		message = "提示词安全审计服务暂时不可用"
	}
	helper.WssError(c, clientConn, types.OpenAIError{
		Message: message, Type: string(types.ErrorTypeNewAPIError), Param: "", Code: decision.ErrorCode,
	})
	closeCode := websocket.CloseTryAgainLater
	if decision.ErrorCode == service.PromptGuardBlockedCode {
		closeCode = 4403
	}
	_ = clientConn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(closeCode, decision.ErrorCode), time.Now().Add(time.Second))
}

func writePromptAuditRealtimeProtocolError(
	c *gin.Context,
	clientConn *websocket.Conn,
	message string,
	code types.ErrorCode,
	closeCode int,
	closeReason string,
) {
	helper.WssError(c, clientConn, types.OpenAIError{
		Message: message, Type: string(types.ErrorTypeNewAPIError), Param: "", Code: string(code),
	})
	_ = clientConn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(closeCode, closeReason), time.Now().Add(time.Second))
}
