package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

const promptAuditDeleteTokenTTL = 5 * time.Minute

type PromptAuditDeletePreview struct {
	MatchedCount      int64  `json:"matched_count"`
	SnapshotMaxId     int64  `json:"snapshot_max_id"`
	FilterHash        string `json:"filter_hash"`
	ConfirmationToken string `json:"confirmation_token"`
	ExpiresAt         int64  `json:"expires_at"`
}

type promptAuditDeleteClaims struct {
	MatchedCount  int64  `json:"matched_count"`
	SnapshotMaxId int64  `json:"snapshot_max_id"`
	FilterHash    string `json:"filter_hash"`
	ExpiresAt     int64  `json:"expires_at"`
	Nonce         string `json:"nonce"`
	// AdminId 将预览令牌绑定到发起预览的 Root 管理员，避免令牌被
	// 复制到另一个管理员会话后重放。旧的服务层测试/内部调用使用 0
	// 作为兼容值；HTTP 控制器始终传入真实管理员 ID。
	AdminId int `json:"admin_id"`
}

type PromptAuditDeleteResult struct {
	DeletedEvents int64 `json:"deleted_events"`
	DeletedJobs   int64 `json:"deleted_jobs"`
}

func PreviewPromptAuditDelete(filter model.PromptAuditEventFilter) (*PromptAuditDeletePreview, error) {
	return PreviewPromptAuditDeleteForActor(filter, 0)
}

// PreviewPromptAuditDeleteForActor 创建绑定 Root 管理员身份的删除预览。
// adminId 为 0 仅保留给旧的服务层内部调用；管理 API 必须传入正数。
func PreviewPromptAuditDeleteForActor(filter model.PromptAuditEventFilter, adminId int) (*PromptAuditDeletePreview, error) {
	if adminId < 0 {
		return nil, errors.New("删除预览管理员 ID 无效")
	}
	filter = normalizePromptAuditDeleteFilter(filter)
	if err := validatePromptAuditDeleteFilter(filter); err != nil {
		return nil, err
	}
	matched, maxId, err := model.PreviewPromptAuditEventDelete(filter)
	if err != nil {
		return nil, err
	}
	filterHash, err := promptAuditFilterHash(filter)
	if err != nil {
		return nil, err
	}
	claims := promptAuditDeleteClaims{
		MatchedCount: matched, SnapshotMaxId: maxId, FilterHash: filterHash,
		ExpiresAt: time.Now().Add(promptAuditDeleteTokenTTL).Unix(),
		Nonce:     strconv.FormatInt(time.Now().UnixNano(), 36),
		AdminId:   adminId,
	}
	token, err := signPromptAuditDeleteClaims(claims)
	if err != nil {
		return nil, err
	}
	return &PromptAuditDeletePreview{
		MatchedCount: matched, SnapshotMaxId: maxId, FilterHash: filterHash,
		ConfirmationToken: token, ExpiresAt: claims.ExpiresAt,
	}, nil
}

func DeletePromptAuditByConfirmedFilter(filter model.PromptAuditEventFilter, token string) (*PromptAuditDeleteResult, error) {
	return DeletePromptAuditByConfirmedFilterForActor(filter, token, 0)
}

// DeletePromptAuditByConfirmedFilterForActor 仅接受与预览管理员一致的令牌。
// 管理 API 必须使用真实 Root 管理员 ID，防止跨会话重放确认令牌。
func DeletePromptAuditByConfirmedFilterForActor(filter model.PromptAuditEventFilter, token string, adminId int) (*PromptAuditDeleteResult, error) {
	if adminId < 0 {
		return nil, errors.New("删除确认管理员 ID 无效")
	}
	filter = normalizePromptAuditDeleteFilter(filter)
	if err := validatePromptAuditDeleteFilter(filter); err != nil {
		return nil, err
	}
	claims, err := verifyPromptAuditDeleteClaimsForActor(token, adminId)
	if err != nil {
		return nil, err
	}
	filterHash, err := promptAuditFilterHash(filter)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal([]byte(filterHash), []byte(claims.FilterHash)) {
		return nil, errors.New("删除筛选条件与预览不一致")
	}
	filter.SnapshotMaxId = claims.SnapshotMaxId
	matched, maxId, err := model.PreviewPromptAuditEventDelete(filter)
	if err != nil {
		return nil, err
	}
	if matched != claims.MatchedCount || (matched > 0 && maxId != claims.SnapshotMaxId) {
		return nil, errors.New("审计事件已发生变化，请重新预览后再删除")
	}
	// 零匹配预览没有可用的高水位 ID。确认后直接返回空结果，避免在
	// “再次计数”和真正删除之间恰好插入的新事件因缺少 id 上界而被误删。
	if claims.MatchedCount == 0 {
		return &PromptAuditDeleteResult{}, nil
	}
	deletedEvents, deletedJobs, err := model.DeletePromptAuditEventsByFilter(filter)
	if err != nil {
		return nil, err
	}
	return &PromptAuditDeleteResult{DeletedEvents: deletedEvents, DeletedJobs: deletedJobs}, nil
}

func DeletePromptAuditByIDs(ids []int64) (*PromptAuditDeleteResult, error) {
	seen := make(map[int64]struct{}, len(ids))
	unique := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id <= 0 {
			return nil, errors.New("安全审计事件 ID 无效")
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		unique = append(unique, id)
	}
	if len(unique) == 0 || len(unique) > 500 {
		return nil, errors.New("每次只能删除 1 到 500 条安全审计事件")
	}
	deletedEvents, deletedJobs, err := model.DeletePromptAuditEventsByIDs(unique)
	if err != nil {
		return nil, err
	}
	return &PromptAuditDeleteResult{DeletedEvents: deletedEvents, DeletedJobs: deletedJobs}, nil
}

func normalizePromptAuditDeleteFilter(filter model.PromptAuditEventFilter) model.PromptAuditEventFilter {
	filter.Source = strings.ToLower(strings.TrimSpace(filter.Source))
	filter.Stage = strings.ToLower(strings.TrimSpace(filter.Stage))
	filter.Decision = strings.ToLower(strings.TrimSpace(filter.Decision))
	filter.RiskLevel = strings.ToLower(strings.TrimSpace(filter.RiskLevel))
	filter.Endpoint = strings.TrimSpace(filter.Endpoint)
	filter.RequestId = strings.TrimSpace(filter.RequestId)
	filter.PromptHash = strings.ToLower(strings.TrimSpace(filter.PromptHash))
	filter.Keyword = strings.TrimSpace(filter.Keyword)
	filter.SnapshotMaxId = 0
	return filter
}

func validatePromptAuditDeleteFilter(filter model.PromptAuditEventFilter) error {
	if filter.UserId < 0 || filter.TokenId < 0 || filter.GroupId < 0 || filter.StartAt < 0 || filter.EndAt < 0 {
		return errors.New("安全审计删除筛选中的 ID 和时间不能为负数")
	}
	if filter.StartAt > 0 && filter.EndAt > 0 && filter.StartAt > filter.EndAt {
		return errors.New("开始时间不能晚于结束时间")
	}
	if filter.Source == "" && filter.Stage == "" && filter.Decision == "" && filter.RiskLevel == "" && filter.Endpoint == "" &&
		filter.RequestId == "" && filter.PromptHash == "" && filter.Keyword == "" &&
		filter.UserId == 0 && filter.TokenId == 0 && filter.GroupId == 0 &&
		filter.StartAt == 0 && filter.EndAt == 0 {
		return errors.New("按筛选删除至少需要一个筛选条件")
	}
	return nil
}

func promptAuditFilterHash(filter model.PromptAuditEventFilter) (string, error) {
	filter.SnapshotMaxId = 0
	data, err := common.Marshal(filter)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest[:]), nil
}

func promptAuditDeleteSigningKey() ([]byte, error) {
	if !PromptAuditCryptoReady() {
		return nil, errors.New("生成删除确认令牌前必须显式配置稳定的 CRYPTO_SECRET")
	}
	digest := sha256.Sum256([]byte("new-api:prompt-security-audit:delete-confirm:v1:" + common.CryptoSecret))
	return digest[:], nil
}

func signPromptAuditDeleteClaims(claims promptAuditDeleteClaims) (string, error) {
	payload, err := common.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingKey, err := promptAuditDeleteSigningKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyPromptAuditDeleteClaims(token string) (promptAuditDeleteClaims, error) {
	return verifyPromptAuditDeleteClaimsForActor(token, -1)
}

// verifyPromptAuditDeleteClaimsForActor expectedAdminId 为 -1 时只校验签名和
// 有效期（兼容旧的内部测试）；非负值时额外校验令牌所属管理员。
func verifyPromptAuditDeleteClaimsForActor(token string, expectedAdminId int) (promptAuditDeleteClaims, error) {
	var claims promptAuditDeleteClaims
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return claims, errors.New("删除确认令牌无效")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims, errors.New("删除确认令牌无效")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("删除确认令牌无效")
	}
	signingKey, err := promptAuditDeleteSigningKey()
	if err != nil {
		return claims, err
	}
	mac := hmac.New(sha256.New, signingKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return claims, errors.New("删除确认令牌签名无效")
	}
	if err := common.Unmarshal(payload, &claims); err != nil {
		return claims, errors.New("删除确认令牌无效")
	}
	if claims.ExpiresAt <= time.Now().Unix() {
		return claims, errors.New("删除确认令牌已过期，请重新预览")
	}
	if claims.FilterHash == "" || claims.MatchedCount < 0 || claims.SnapshotMaxId < 0 {
		return claims, errors.New("删除确认令牌无效")
	}
	if claims.AdminId < 0 || (expectedAdminId >= 0 && claims.AdminId != expectedAdminId) {
		return claims, errors.New("删除确认令牌不属于当前管理员")
	}
	return claims, nil
}
