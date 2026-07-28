package model

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	PromptAuditConfigID = 1

	PromptAuditJobQueued     = "queued"
	PromptAuditJobProcessing = "processing"
	PromptAuditJobRetry      = "retry"
	PromptAuditJobDone       = "done"
	PromptAuditJobFailed     = "failed"

	// 事件密文用途必须由模型字段明确标记，不能通过尝试解析明文 JSON
	// 来猜测，否则用户提示词恰好具有内部字段时会被错误改写。
	PromptAuditCipherKindPrompt     = "prompt_v1"
	PromptAuditCipherKindJobPayload = "job_payload_v1"
	// PromptAuditJobMaxAttempts 与服务层的重试上限保持一致。租约回收
	// 不能把已经耗尽尝试次数的任务无限地重新放回队列。
	PromptAuditJobMaxAttempts = 3

	promptAuditDeleteBatchSize = 500
)

// PromptAuditConfig 保存安全审计的单例策略。复杂数组使用 TEXT JSON，保证三库兼容。
type PromptAuditConfig struct {
	Id                        int    `json:"id" gorm:"primaryKey"`
	ConfigVersion             int64  `json:"config_version" gorm:"not null;default:1"`
	Enabled                   bool   `json:"enabled" gorm:"not null;default:false"`
	BlockingEnabled           bool   `json:"blocking_enabled" gorm:"not null;default:false"`
	StorePassEvents           bool   `json:"store_pass_events" gorm:"not null;default:false"`
	UpstreamPolicyEnabled     bool   `json:"upstream_policy_enabled" gorm:"not null;default:true"`
	SensitiveWordAuditEnabled bool   `json:"sensitive_word_audit_enabled" gorm:"not null;default:true"`
	Strategy                  string `json:"strategy" gorm:"type:varchar(32);not null;default:'priority'"`
	WorkerCount               int    `json:"worker_count" gorm:"not null;default:4"`
	QueueCapacity             int    `json:"queue_capacity" gorm:"not null;default:32768"`
	RetentionDays             int    `json:"retention_days" gorm:"not null;default:30"`
	Scanners                  string `json:"-" gorm:"type:text;not null"`
	AllGroups                 bool   `json:"all_groups" gorm:"not null;default:true"`
	GroupIds                  string `json:"-" gorm:"type:text;not null"`
	UpdatedAt                 int64  `json:"updated_at" gorm:"not null;default:0"`
	UpdatedBy                 int    `json:"updated_by" gorm:"not null;default:0"`
	ChangeSummary             string `json:"change_summary" gorm:"type:text;not null"`
}

func (PromptAuditConfig) TableName() string { return "prompt_audit_configs" }

// PromptAuditEndpoint 的令牌只保存版本化密文，任何 API 都不得直接序列化该模型。
type PromptAuditEndpoint struct {
	Id              string `json:"id" gorm:"type:varchar(64);primaryKey"`
	Name            string `json:"name" gorm:"type:varchar(128);not null"`
	Protocol        string `json:"protocol" gorm:"type:varchar(32);not null"`
	BaseUrl         string `json:"base_url" gorm:"type:text;not null"`
	Model           string `json:"model" gorm:"type:varchar(255);not null"`
	TokenCiphertext string `json:"-" gorm:"type:text;not null"`
	TimeoutMs       int    `json:"timeout_ms" gorm:"not null"`
	InputLimit      int    `json:"input_limit" gorm:"not null"`
	Enabled         bool   `json:"enabled" gorm:"not null;index"`
	Priority        int    `json:"priority" gorm:"not null;default:0;index"`
	ConfigVersion   int64  `json:"config_version" gorm:"not null;index"`
	CreatedAt       int64  `json:"created_at" gorm:"not null;default:0"`
	UpdatedAt       int64  `json:"updated_at" gorm:"not null;default:0"`
}

func (PromptAuditEndpoint) TableName() string { return "prompt_audit_endpoints" }

type PromptAuditJob struct {
	Id               int64                `json:"id" gorm:"primaryKey"`
	Status           string               `json:"status" gorm:"type:varchar(24);not null;index:idx_prompt_jobs_claim,priority:1"`
	ClaimVersion     int64                `json:"claim_version" gorm:"not null;default:0"`
	WorkerId         string               `json:"worker_id" gorm:"type:varchar(128);not null;default:'';index"`
	LeaseUntil       int64                `json:"lease_until" gorm:"not null;default:0;index:idx_prompt_jobs_claim,priority:3"`
	Attempts         int                  `json:"attempts" gorm:"not null;default:0"`
	NextAttemptAt    int64                `json:"next_attempt_at" gorm:"not null;default:0;index:idx_prompt_jobs_claim,priority:2"`
	PromptCiphertext PromptAuditLargeText `json:"-" gorm:"not null"`
	Snapshot         string               `json:"-" gorm:"type:text;not null"`
	ConfigVersion    int64                `json:"config_version" gorm:"not null;index"`
	LastErrorCode    string               `json:"last_error_code" gorm:"type:varchar(64);not null;default:''"`
	LastErrorMessage string               `json:"last_error_message" gorm:"type:varchar(512);not null;default:''"`
	CreatedAt        int64                `json:"created_at" gorm:"not null;index"`
	UpdatedAt        int64                `json:"updated_at" gorm:"not null"`
	FinishedAt       int64                `json:"finished_at" gorm:"not null;default:0;index"`
}

func (PromptAuditJob) TableName() string { return "prompt_audit_jobs" }

// PromptAuditEvent 列表字段不含明文。PromptCiphertext 只允许详情接口按需解密。
type PromptAuditEvent struct {
	Id                int64                `json:"id" gorm:"primaryKey"`
	JobId             int64                `json:"job_id" gorm:"not null;default:0;index"`
	RequestId         string               `json:"request_id" gorm:"type:varchar(128);not null;index"`
	UserId            int                  `json:"user_id" gorm:"not null;index"`
	Username          string               `json:"username" gorm:"type:varchar(128);not null"`
	UserEmail         string               `json:"user_email" gorm:"type:varchar(255);not null"`
	TokenId           int                  `json:"api_key_id" gorm:"not null;index"`
	TokenName         string               `json:"api_key_name" gorm:"type:varchar(128);not null"`
	GroupId           int                  `json:"group_id" gorm:"not null;default:0;index"`
	GroupName         string               `json:"group_name" gorm:"type:varchar(128);not null"`
	Provider          string               `json:"provider" gorm:"type:varchar(64);not null"`
	Endpoint          string               `json:"endpoint" gorm:"type:varchar(255);not null;index"`
	Protocol          string               `json:"protocol" gorm:"type:varchar(64);not null"`
	Model             string               `json:"model" gorm:"type:varchar(255);not null;index"`
	PromptHash        string               `json:"prompt_hash" gorm:"type:char(64);not null;index"`
	RedactedPreview   string               `json:"redacted_preview" gorm:"type:text;not null"`
	PromptCiphertext  PromptAuditLargeText `json:"-" gorm:"not null"`
	PromptCipherKind  string               `json:"-" gorm:"type:varchar(32);not null;default:'prompt_v1'"`
	PromptLength      int                  `json:"prompt_length" gorm:"not null"`
	PromptTruncated   bool                 `json:"prompt_truncated" gorm:"not null;default:false"`
	PromptAvailable   bool                 `json:"prompt_available" gorm:"not null;default:true"`
	MessageCount      int                  `json:"message_count" gorm:"not null;default:0"`
	Source            string               `json:"source" gorm:"type:varchar(32);not null;default:'prompt_guard';index"`
	Stage             string               `json:"stage" gorm:"type:varchar(32);not null;default:'request';index"`
	Decision          string               `json:"decision" gorm:"type:varchar(24);not null;index"`
	RiskLevel         string               `json:"risk_level" gorm:"type:varchar(24);not null;index"`
	RiskScore         float64              `json:"risk_score" gorm:"not null;default:0"`
	Action            string               `json:"action" gorm:"type:varchar(24);not null"`
	Safety            string               `json:"safety" gorm:"type:varchar(32);not null;index"`
	Categories        string               `json:"-" gorm:"type:text;not null"`
	MatchedScanners   string               `json:"-" gorm:"type:text;not null"`
	UnknownCategories string               `json:"-" gorm:"type:text;not null"`
	GuardEndpointId   string               `json:"guard_endpoint_id" gorm:"type:varchar(64);not null;index"`
	ConfigVersion     int64                `json:"config_version" gorm:"not null;index"`
	ChunkTotal        int                  `json:"chunk_total" gorm:"not null;default:0"`
	LatencyMs         int64                `json:"latency_ms" gorm:"not null;default:0"`
	ErrorCode         string               `json:"error_code" gorm:"type:varchar(64);not null;default:'';index"`
	ErrorMessage      string               `json:"error_message" gorm:"type:varchar(512);not null;default:''"`
	CreatedAt         int64                `json:"created_at" gorm:"not null;index"`
	ExpiresAt         int64                `json:"expires_at" gorm:"not null;index"`
}

func (PromptAuditEvent) TableName() string { return "prompt_audit_events" }

// promptAuditRecoverySnapshot 只包含任务快照中的脱敏元数据。完整提示词和
// Guard 扫描文本使用 json:"-" 保存在独立密文中，因此租约回收路径绝不能
// 尝试从 Snapshot 读取或重建明文。
type promptAuditRecoverySnapshot struct {
	RequestId       string `json:"request_id"`
	UserId          int    `json:"user_id"`
	Username        string `json:"username"`
	UserEmail       string `json:"user_email"`
	TokenId         int    `json:"api_key_id"`
	TokenName       string `json:"api_key_name"`
	GroupId         int    `json:"group_id"`
	GroupName       string `json:"group_name"`
	Provider        string `json:"provider"`
	Endpoint        string `json:"endpoint"`
	Protocol        string `json:"protocol"`
	Model           string `json:"model"`
	PromptHash      string `json:"prompt_hash"`
	RedactedPreview string `json:"redacted_preview"`
	PromptLength    int    `json:"prompt_length"`
	PromptTruncated bool   `json:"prompt_truncated"`
	MessageCount    int    `json:"message_count"`
}

type PromptAuditQueueState struct {
	Id          int   `json:"id" gorm:"primaryKey"`
	ActiveCount int64 `json:"active_count" gorm:"not null;default:0"`
	Version     int64 `json:"version" gorm:"not null;default:0"`
	UpdatedAt   int64 `json:"updated_at" gorm:"not null;default:0"`
}

func (PromptAuditQueueState) TableName() string { return "prompt_audit_queue_states" }

func defaultPromptAuditConfig() PromptAuditConfig {
	scanners, _ := common.Marshal([]string{
		"violent", "non_violent_illegal_acts", "sexual_content_or_sexual_acts",
		"pii", "suicide_and_self_harm", "unethical_acts", "politically_sensitive_topics",
		"copyright_violation", "jailbreak",
	})
	groups, _ := common.Marshal([]int{})
	return PromptAuditConfig{
		Id: PromptAuditConfigID, ConfigVersion: 1, Strategy: "priority", WorkerCount: 4,
		QueueCapacity: 32768, RetentionDays: 30, Scanners: string(scanners),
		AllGroups: true, GroupIds: string(groups), ChangeSummary: "{}",
		UpstreamPolicyEnabled: true, SensitiveWordAuditEnabled: true,
	}
}

func EnsurePromptAuditDefaults() error {
	cfg := defaultPromptAuditConfig()
	if err := DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&cfg).Error; err != nil {
		return err
	}
	state := PromptAuditQueueState{Id: PromptAuditConfigID, UpdatedAt: time.Now().Unix()}
	return DB.Clauses(clause.OnConflict{DoNothing: true}).Create(&state).Error
}

func LoadPromptAuditConfig() (*PromptAuditConfig, []PromptAuditEndpoint, error) {
	if err := EnsurePromptAuditDefaults(); err != nil {
		return nil, nil, err
	}
	var cfg PromptAuditConfig
	if err := DB.First(&cfg, "id = ?", PromptAuditConfigID).Error; err != nil {
		return nil, nil, err
	}
	var endpoints []PromptAuditEndpoint
	if err := DB.Order("priority ASC, id ASC").Find(&endpoints).Error; err != nil {
		return nil, nil, err
	}
	return &cfg, endpoints, nil
}

var ErrPromptAuditConfigConflict = errors.New("prompt audit config conflict")

func SavePromptAuditConfig(expectedVersion int64, cfg *PromptAuditConfig, endpoints []PromptAuditEndpoint) error {
	if cfg == nil {
		return errors.New("prompt audit config is nil")
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now().Unix()
		cfg.Id = PromptAuditConfigID
		cfg.ConfigVersion = expectedVersion + 1
		cfg.UpdatedAt = now
		updates := map[string]interface{}{
			"config_version": cfg.ConfigVersion, "enabled": cfg.Enabled,
			"blocking_enabled": cfg.BlockingEnabled, "store_pass_events": cfg.StorePassEvents,
			"upstream_policy_enabled":      cfg.UpstreamPolicyEnabled,
			"sensitive_word_audit_enabled": cfg.SensitiveWordAuditEnabled,
			"strategy":                     cfg.Strategy, "worker_count": cfg.WorkerCount,
			"queue_capacity": cfg.QueueCapacity, "retention_days": cfg.RetentionDays,
			"scanners": cfg.Scanners, "all_groups": cfg.AllGroups, "group_ids": cfg.GroupIds,
			"updated_at": now, "updated_by": cfg.UpdatedBy, "change_summary": cfg.ChangeSummary,
		}
		result := tx.Model(&PromptAuditConfig{}).
			Where("id = ? AND config_version = ?", PromptAuditConfigID, expectedVersion).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return ErrPromptAuditConfigConflict
		}

		var existing []PromptAuditEndpoint
		if err := tx.Find(&existing).Error; err != nil {
			return err
		}
		keep := make(map[string]struct{}, len(endpoints))
		for i := range endpoints {
			ep := &endpoints[i]
			ep.Priority = i
			ep.ConfigVersion = cfg.ConfigVersion
			ep.UpdatedAt = now
			if ep.CreatedAt == 0 {
				ep.CreatedAt = now
			}
			keep[ep.Id] = struct{}{}
			if err := tx.Save(ep).Error; err != nil {
				return err
			}
		}
		for _, ep := range existing {
			if _, ok := keep[ep.Id]; ok {
				continue
			}
			if err := tx.Delete(&PromptAuditEndpoint{}, "id = ?", ep.Id).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

func EnqueuePromptAuditJob(job *PromptAuditJob, capacity int) error {
	if job == nil {
		return errors.New("prompt audit job is nil")
	}
	if capacity < 1 {
		return errors.New("prompt audit queue capacity is invalid")
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now().Unix()
		state := PromptAuditQueueState{Id: PromptAuditConfigID, UpdatedAt: now}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&state).Error; err != nil {
			return err
		}
		result := tx.Model(&PromptAuditQueueState{}).
			Where("id = ? AND active_count < ?", PromptAuditConfigID, capacity).
			Updates(map[string]interface{}{
				"active_count": gorm.Expr("active_count + ?", 1),
				"version":      gorm.Expr("version + ?", 1),
				"updated_at":   now,
			})
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return fmt.Errorf("prompt audit queue is full")
		}
		job.Status = PromptAuditJobQueued
		job.NextAttemptAt = now
		job.CreatedAt = now
		job.UpdatedAt = now
		return tx.Create(job).Error
	})
}

func ClaimPromptAuditJob(workerId string, lease time.Duration) (*PromptAuditJob, error) {
	now := time.Now().Unix()
	leaseUntil := time.Now().Add(lease).Unix()
	var candidates []PromptAuditJob
	if err := DB.Where("status IN ? AND next_attempt_at <= ? AND (lease_until = 0 OR lease_until < ?)",
		[]string{PromptAuditJobQueued, PromptAuditJobRetry}, now, now).
		Order("id ASC").Limit(16).Find(&candidates).Error; err != nil {
		return nil, err
	}
	for _, candidate := range candidates {
		result := DB.Model(&PromptAuditJob{}).
			Where("id = ? AND status IN ? AND claim_version = ? AND next_attempt_at <= ? AND (lease_until = 0 OR lease_until < ?)",
				candidate.Id, []string{PromptAuditJobQueued, PromptAuditJobRetry}, candidate.ClaimVersion, now, now).
			Updates(map[string]interface{}{
				"status": PromptAuditJobProcessing, "worker_id": workerId,
				"lease_until": leaseUntil, "claim_version": gorm.Expr("claim_version + ?", 1),
				"attempts": gorm.Expr("attempts + ?", 1), "updated_at": now,
			})
		if result.Error != nil {
			return nil, result.Error
		}
		if result.RowsAffected != 1 {
			continue
		}
		var claimed PromptAuditJob
		if err := DB.First(&claimed, "id = ?", candidate.Id).Error; err != nil {
			return nil, err
		}
		return &claimed, nil
	}
	return nil, gorm.ErrRecordNotFound
}

// RenewPromptAuditJobLease 仅允许当前 claim_version 和 worker 续期，
// 避免租约过期后旧 Worker 覆盖新领取者的 fencing 边界。
func RenewPromptAuditJobLease(job *PromptAuditJob, lease time.Duration) error {
	if job == nil || lease <= 0 {
		return errors.New("提示词审计任务租约参数无效")
	}
	now := time.Now()
	leaseUntil := now.Add(lease).Unix()
	result := DB.Model(&PromptAuditJob{}).
		Where("id = ? AND status = ? AND claim_version = ? AND worker_id = ?",
			job.Id, PromptAuditJobProcessing, job.ClaimVersion, job.WorkerId).
		Updates(map[string]interface{}{"lease_until": leaseUntil, "updated_at": now.Unix()})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("prompt audit lease claim lost")
	}
	job.LeaseUntil = leaseUntil
	return nil
}

func RetryPromptAuditJob(job *PromptAuditJob, code, message string, next time.Time) error {
	if job == nil {
		return errors.New("prompt audit job is nil")
	}
	result := DB.Model(&PromptAuditJob{}).
		Where("id = ? AND status = ? AND claim_version = ? AND worker_id = ?",
			job.Id, PromptAuditJobProcessing, job.ClaimVersion, job.WorkerId).
		Updates(map[string]interface{}{
			"status": PromptAuditJobRetry, "worker_id": "", "lease_until": 0,
			"next_attempt_at": next.Unix(), "last_error_code": code,
			"last_error_message": truncatePromptAuditError(message), "updated_at": time.Now().Unix(),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("prompt audit retry claim lost")
	}
	return nil
}

func FinishPromptAuditJob(job *PromptAuditJob, event *PromptAuditEvent, failed bool) error {
	if job == nil {
		return errors.New("prompt audit job is nil")
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		now := time.Now().Unix()
		if event != nil {
			event.JobId = job.Id
			if event.CreatedAt == 0 {
				event.CreatedAt = now
			}
			if err := tx.Create(event).Error; err != nil {
				return err
			}
		}
		status := PromptAuditJobDone
		if failed {
			status = PromptAuditJobFailed
		}
		updates := map[string]interface{}{
			"status": status, "worker_id": "", "lease_until": 0,
			"finished_at": now, "updated_at": now,
		}
		// 成功完成时，事件已经保存了可解密的完整提示词，因此可以
		// 清掉队列副本。失败路径不能假设 event 一定带有可用密文：
		// 例如密钥轮换、密文损坏、任务负载非法或重新加密失败时，
		// 原任务密文仍是数据库中唯一的完整审计文本副本。保留它直到
		// 结束任务保留期清理，避免失败处理把审计正文变成不可恢复的
		// 空值。
		if !failed || (event != nil && event.PromptCiphertext != "") {
			updates["prompt_ciphertext"] = ""
		}
		if failed && event != nil {
			updates["last_error_code"] = event.ErrorCode
			updates["last_error_message"] = truncatePromptAuditError(event.ErrorMessage)
		}
		result := tx.Model(&PromptAuditJob{}).
			Where("id = ? AND status = ? AND claim_version = ? AND worker_id = ?",
				job.Id, PromptAuditJobProcessing, job.ClaimVersion, job.WorkerId).
			Updates(updates)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected != 1 {
			return errors.New("prompt audit completion claim lost")
		}
		return decrementPromptAuditActiveCount(tx, now)
	})
}

func CreatePromptAuditEvent(event *PromptAuditEvent) error {
	if event == nil {
		return errors.New("prompt audit event is nil")
	}
	if event.CreatedAt == 0 {
		event.CreatedAt = time.Now().Unix()
	}
	if event.PromptAvailable {
		return DB.Create(event).Error
	}
	// GORM 对带 default 标签的 bool 零值会省略写入。新来源在无
	// CRYPTO_SECRET 时必须明确保存 false，并把插入与修正放进同一事务，
	// 避免进程中断后留下“可查看但没有密文”的半状态事件。
	return DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(event).Error; err != nil {
			return err
		}
		event.PromptAvailable = false
		return tx.Model(&PromptAuditEvent{}).Where("id = ?", event.Id).
			UpdateColumn("prompt_available", false).Error
	})
}

// UpdatePromptAuditEvent 只更新已经创建的同步待审事件。
// 调用方必须保留原事件 ID，避免 Guard 返回后误插入第二条记录。
func UpdatePromptAuditEvent(event *PromptAuditEvent) error {
	if event == nil || event.Id <= 0 {
		return errors.New("prompt audit event id is invalid")
	}
	result := DB.Model(&PromptAuditEvent{}).Where("id = ?", event.Id).Updates(map[string]interface{}{
		"job_id": event.JobId, "request_id": event.RequestId,
		"user_id": event.UserId, "username": event.Username, "user_email": event.UserEmail,
		"token_id": event.TokenId, "token_name": event.TokenName,
		"group_id": event.GroupId, "group_name": event.GroupName,
		"provider": event.Provider, "endpoint": event.Endpoint, "protocol": event.Protocol, "model": event.Model,
		"prompt_hash": event.PromptHash, "redacted_preview": event.RedactedPreview,
		"prompt_ciphertext": event.PromptCiphertext, "prompt_cipher_kind": event.PromptCipherKind,
		"prompt_length":    event.PromptLength,
		"prompt_truncated": event.PromptTruncated, "prompt_available": event.PromptAvailable,
		"message_count": event.MessageCount, "source": event.Source, "stage": event.Stage,
		"decision": event.Decision, "risk_level": event.RiskLevel, "risk_score": event.RiskScore,
		"action": event.Action, "safety": event.Safety,
		"categories": event.Categories, "matched_scanners": event.MatchedScanners,
		"unknown_categories": event.UnknownCategories,
		"guard_endpoint_id":  event.GuardEndpointId, "config_version": event.ConfigVersion,
		"chunk_total": event.ChunkTotal, "latency_ms": event.LatencyMs,
		"error_code": event.ErrorCode, "error_message": event.ErrorMessage,
		"created_at": event.CreatedAt, "expires_at": event.ExpiresAt,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

func decrementPromptAuditActiveCount(tx *gorm.DB, now int64) error {
	return tx.Model(&PromptAuditQueueState{}).
		Where("id = ?", PromptAuditConfigID).
		Updates(map[string]interface{}{
			"active_count": gorm.Expr("CASE WHEN active_count > 0 THEN active_count - 1 ELSE 0 END"),
			"version":      gorm.Expr("version + ?", 1), "updated_at": now,
		}).Error
}

func RecoverExpiredPromptAuditJobs(now int64) (int64, error) {
	if now <= 0 {
		return 0, errors.New("提示词审计租约回收时间无效")
	}
	// 先读取候选，再以 status + claim_version + worker_id + lease 条件更新，
	// 这样不会把已经被新 Worker 重新领取的任务误改回 retry。所有数据库都
	// 支持这组普通条件更新，不依赖 SKIP LOCKED 或数据库专有锁。
	var candidates []PromptAuditJob
	if err := DB.Where("status = ? AND lease_until > 0 AND lease_until < ?",
		PromptAuditJobProcessing, now).Order("id ASC").Limit(promptAuditDeleteBatchSize).Find(&candidates).Error; err != nil {
		return 0, err
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	var recovered int64
	var terminal int64
	err := DB.Transaction(func(tx *gorm.DB) error {
		retentionDays := 30
		var config PromptAuditConfig
		configErr := tx.Select("retention_days").First(&config, "id = ?", PromptAuditConfigID).Error
		if configErr == nil && config.RetentionDays > 0 {
			retentionDays = config.RetentionDays
		} else if configErr != nil && !errors.Is(configErr, gorm.ErrRecordNotFound) {
			return configErr
		}
		for _, candidate := range candidates {
			status := PromptAuditJobRetry
			nextAttemptAt := now
			finishedAt := int64(0)
			message := "任务租约已过期，等待重新领取"
			if candidate.Attempts >= PromptAuditJobMaxAttempts {
				status = PromptAuditJobFailed
				nextAttemptAt = 0
				finishedAt = now
				message = "任务租约已过期且已达到最大重试次数"
			}
			result := tx.Model(&PromptAuditJob{}).
				Where("id = ? AND status = ? AND claim_version = ? AND worker_id = ? AND lease_until > 0 AND lease_until < ?",
					candidate.Id, PromptAuditJobProcessing, candidate.ClaimVersion, candidate.WorkerId, now).
				Updates(map[string]interface{}{
					"status": status, "worker_id": "", "lease_until": 0,
					"next_attempt_at": nextAttemptAt, "last_error_code": "prompt_audit_lease_expired",
					"last_error_message": message, "finished_at": finishedAt, "updated_at": now,
				})
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected != 1 {
				continue
			}
			recovered++
			if status == PromptAuditJobFailed {
				// 任务终态与失败事件必须位于同一事务。否则进程恰好在状态
				// 更新后退出时，数据库会永久留下没有审计事件的失败任务。
				event := buildExpiredPromptAuditJobEvent(candidate, now, retentionDays)
				if err := tx.Create(event).Error; err != nil {
					return err
				}
				terminal++
			}
		}
		if terminal == 0 {
			return nil
		}
		return tx.Model(&PromptAuditQueueState{}).Where("id = ?", PromptAuditConfigID).
			Updates(map[string]interface{}{
				"active_count": gorm.Expr("CASE WHEN active_count >= ? THEN active_count - ? ELSE 0 END", terminal, terminal),
				"version":      gorm.Expr("version + ?", 1), "updated_at": now,
			}).Error
	})
	return recovered, err
}

func buildExpiredPromptAuditJobEvent(job PromptAuditJob, now int64, retentionDays int) *PromptAuditEvent {
	if retentionDays < 1 {
		retentionDays = 30
	}
	var snapshot promptAuditRecoverySnapshot
	// Snapshot 损坏时仍记录稳定错误和原任务密文；元数据使用零值，
	// 不把解析错误或数据库内容拼接进对外可见的错误消息。
	_ = common.UnmarshalJsonStr(job.Snapshot, &snapshot)
	return &PromptAuditEvent{
		JobId: job.Id, RequestId: snapshot.RequestId,
		UserId: snapshot.UserId, Username: snapshot.Username, UserEmail: snapshot.UserEmail,
		TokenId: snapshot.TokenId, TokenName: snapshot.TokenName,
		GroupId: snapshot.GroupId, GroupName: snapshot.GroupName,
		Provider: snapshot.Provider, Endpoint: snapshot.Endpoint, Protocol: snapshot.Protocol, Model: snapshot.Model,
		PromptHash: snapshot.PromptHash, RedactedPreview: snapshot.RedactedPreview,
		PromptCiphertext: job.PromptCiphertext, PromptCipherKind: PromptAuditCipherKindJobPayload,
		PromptLength:    snapshot.PromptLength,
		PromptTruncated: snapshot.PromptTruncated, PromptAvailable: job.PromptCiphertext != "",
		MessageCount: snapshot.MessageCount, Source: "prompt_guard", Stage: "async_worker",
		Decision: "error", RiskLevel: "unknown", Action: "Error", Safety: "Unknown",
		Categories: "[]", MatchedScanners: "[]", UnknownCategories: "[]",
		ConfigVersion: job.ConfigVersion,
		ErrorCode:     "prompt_audit_lease_expired", ErrorMessage: "任务租约已过期且已达到最大重试次数",
		CreatedAt: now, ExpiresAt: now + int64(retentionDays)*24*60*60,
	}
}

type PromptAuditEventFilter struct {
	Source, Stage, Decision, RiskLevel, Endpoint, RequestId, PromptHash, Keyword string
	UserId, TokenId, GroupId                                                     int
	StartAt, EndAt, SnapshotMaxId                                                int64
}

func applyPromptAuditEventFilter(query *gorm.DB, filter PromptAuditEventFilter) *gorm.DB {
	if filter.Source != "" {
		query = query.Where("source = ?", filter.Source)
	}
	if filter.Stage != "" {
		query = query.Where("stage = ?", filter.Stage)
	}
	if filter.Decision != "" {
		query = query.Where("decision = ?", filter.Decision)
	}
	if filter.RiskLevel != "" {
		query = query.Where("risk_level = ?", filter.RiskLevel)
	}
	if filter.Endpoint != "" {
		query = query.Where("guard_endpoint_id = ?", filter.Endpoint)
	}
	if filter.UserId > 0 {
		query = query.Where("user_id = ?", filter.UserId)
	}
	if filter.TokenId > 0 {
		query = query.Where("token_id = ?", filter.TokenId)
	}
	if filter.GroupId > 0 {
		query = query.Where("group_id = ?", filter.GroupId)
	}
	if filter.RequestId != "" {
		query = query.Where("request_id = ?", filter.RequestId)
	}
	if filter.PromptHash != "" {
		query = query.Where("prompt_hash = ?", strings.ToLower(filter.PromptHash))
	}
	if filter.Keyword != "" {
		query = query.Where("redacted_preview LIKE ? ESCAPE '!'", "%"+escapePromptAuditLike(filter.Keyword)+"%")
	}
	if filter.StartAt > 0 {
		query = query.Where("created_at >= ?", filter.StartAt)
	}
	if filter.EndAt > 0 {
		query = query.Where("created_at <= ?", filter.EndAt)
	}
	if filter.SnapshotMaxId > 0 {
		query = query.Where("id <= ?", filter.SnapshotMaxId)
	}
	return query
}

func escapePromptAuditLike(value string) string {
	// 使用显式 ESCAPE 字符，使三种数据库都把用户输入的通配符当作普通字符。
	return strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(value)
}

func ListPromptAuditEvents(filter PromptAuditEventFilter, page, pageSize int) ([]PromptAuditEvent, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	query := applyPromptAuditEventFilter(DB.Model(&PromptAuditEvent{}), filter)
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	var events []PromptAuditEvent
	if err := query.Select("id", "job_id", "request_id", "user_id", "username", "user_email", "token_id", "token_name",
		"group_id", "group_name", "provider", "endpoint", "protocol", "model", "prompt_hash", "redacted_preview",
		"prompt_length", "prompt_truncated", "prompt_available", "message_count", "source", "stage",
		"decision", "risk_level", "risk_score", "action", "safety",
		"categories", "matched_scanners", "unknown_categories", "guard_endpoint_id", "config_version", "chunk_total", "latency_ms",
		"error_code", "error_message", "created_at", "expires_at").
		Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&events).Error; err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

func GetPromptAuditEvent(id int64) (*PromptAuditEvent, error) {
	var event PromptAuditEvent
	if err := DB.First(&event, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &event, nil
}

func DeletePromptAuditEvent(id int64) (int64, int64, error) {
	return DeletePromptAuditEventsByIds([]int64{id})
}

// DeletePromptAuditEventsByIds 只删除显式选中的事件，避免保留期清理或批量操作扩大匹配范围。
func DeletePromptAuditEventsByIds(ids []int64) (int64, int64, error) {
	if len(ids) == 0 {
		return 0, 0, nil
	}
	var deletedEvents, deletedJobs int64
	err := DB.Transaction(func(tx *gorm.DB) error {
		for start := 0; start < len(ids); start += promptAuditDeleteBatchSize {
			end := start + promptAuditDeleteBatchSize
			if end > len(ids) {
				end = len(ids)
			}
			var rows []PromptAuditEvent
			if err := tx.Where("id IN ?", ids[start:end]).Select("id", "job_id").Find(&rows).Error; err != nil {
				return err
			}
			events, jobs, err := deletePromptAuditEventRowsTx(tx, rows)
			if err != nil {
				return err
			}
			deletedEvents += events
			deletedJobs += jobs
		}
		if deletedEvents == 0 {
			return gorm.ErrRecordNotFound
		}
		return nil
	})
	return deletedEvents, deletedJobs, err
}

func deletePromptAuditEventRowsTx(tx *gorm.DB, rows []PromptAuditEvent) (int64, int64, error) {
	if len(rows) == 0 {
		return 0, 0, nil
	}
	eventIds := make([]int64, 0, len(rows))
	jobIdSet := make(map[int64]struct{}, len(rows))
	for _, row := range rows {
		eventIds = append(eventIds, row.Id)
		if row.JobId > 0 {
			jobIdSet[row.JobId] = struct{}{}
		}
	}
	result := tx.Where("id IN ?", eventIds).Delete(&PromptAuditEvent{})
	if result.Error != nil {
		return 0, 0, result.Error
	}
	if len(jobIdSet) == 0 {
		return result.RowsAffected, 0, nil
	}
	jobIds := make([]int64, 0, len(jobIdSet))
	for id := range jobIdSet {
		jobIds = append(jobIds, id)
	}
	// 一个任务原则上只会生成一个事件，但删除接口不能依赖这一隐含
	// 约束。只有在事件删除后已经没有其他事件引用该任务时才清理任务，
	// 避免测试数据、历史迁移或同步重试产生共享 job_id 时误删仍可关联
	// 的事实记录。查询使用普通 IN 条件，兼容三种数据库。
	var referenced []PromptAuditEvent
	if err := tx.Where("job_id IN ?", jobIds).Select("job_id").Find(&referenced).Error; err != nil {
		return 0, 0, err
	}
	for _, event := range referenced {
		delete(jobIdSet, event.JobId)
	}
	jobIds = jobIds[:0]
	for id := range jobIdSet {
		jobIds = append(jobIds, id)
	}
	if len(jobIds) == 0 {
		return result.RowsAffected, 0, nil
	}
	jobs := tx.Where("id IN ? AND status IN ?", jobIds,
		[]string{PromptAuditJobDone, PromptAuditJobFailed}).Delete(&PromptAuditJob{})
	if jobs.Error != nil {
		return 0, 0, jobs.Error
	}
	return result.RowsAffected, jobs.RowsAffected, nil
}

func PreviewPromptAuditEventDelete(filter PromptAuditEventFilter) (int64, int64, error) {
	query := applyPromptAuditEventFilter(DB.Model(&PromptAuditEvent{}), filter)
	var count, maxId int64
	if err := query.Count(&count).Error; err != nil {
		return 0, 0, err
	}
	if count == 0 {
		return 0, 0, nil
	}
	if err := query.Select("COALESCE(MAX(id), 0)").Scan(&maxId).Error; err != nil {
		return 0, 0, err
	}
	return count, maxId, nil
}

func DeletePromptAuditEventsByFilter(filter PromptAuditEventFilter) (int64, int64, error) {
	if filter.UserId < 0 || filter.TokenId < 0 || filter.GroupId < 0 || filter.StartAt < 0 || filter.EndAt < 0 {
		return 0, 0, errors.New("安全审计删除筛选中的 ID 和时间不能为负数")
	}
	if filter.Source == "" && filter.Stage == "" && filter.Decision == "" && filter.RiskLevel == "" && filter.Endpoint == "" &&
		filter.RequestId == "" && filter.PromptHash == "" && filter.Keyword == "" &&
		filter.UserId == 0 && filter.TokenId == 0 && filter.GroupId == 0 &&
		filter.StartAt == 0 && filter.EndAt == 0 {
		return 0, 0, errors.New("按筛选删除至少需要一个筛选条件")
	}
	var deletedEvents, deletedJobs int64
	err := DB.Transaction(func(tx *gorm.DB) error {
		// SQLite 默认仅允许约 999 个绑定参数。固定按 500 条循环，既避免
		// IN 参数溢出，也避免一次把全部匹配事件读入内存。
		for {
			var rows []PromptAuditEvent
			if err := applyPromptAuditEventFilter(tx.Model(&PromptAuditEvent{}), filter).
				Select("id", "job_id").Order("id ASC").Limit(promptAuditDeleteBatchSize).Find(&rows).Error; err != nil {
				return err
			}
			if len(rows) == 0 {
				return nil
			}
			events, jobs, err := deletePromptAuditEventRowsTx(tx, rows)
			if err != nil {
				return err
			}
			deletedEvents += events
			deletedJobs += jobs
		}
	})
	return deletedEvents, deletedJobs, err
}

type PromptAuditRuntimeCounts struct {
	Queued         int64 `json:"queued"`
	Processing     int64 `json:"processing"`
	Retry          int64 `json:"retry"`
	Done           int64 `json:"done"`
	Failed         int64 `json:"failed"`
	Active         int64 `json:"active"`
	Capacity       int64 `json:"capacity"`
	OldestQueuedAt int64 `json:"oldest_queued_at"`
}

func GetPromptAuditRuntimeCounts(capacity int) (PromptAuditRuntimeCounts, error) {
	result := PromptAuditRuntimeCounts{Capacity: int64(capacity)}
	type row struct {
		Status string
		Count  int64
	}
	var rows []row
	if err := DB.Model(&PromptAuditJob{}).Select("status, COUNT(*) AS count").Group("status").Scan(&rows).Error; err != nil {
		return result, err
	}
	for _, item := range rows {
		switch item.Status {
		case PromptAuditJobQueued:
			result.Queued = item.Count
		case PromptAuditJobProcessing:
			result.Processing = item.Count
		case PromptAuditJobRetry:
			result.Retry = item.Count
		case PromptAuditJobDone:
			result.Done = item.Count
		case PromptAuditJobFailed:
			result.Failed = item.Count
		}
	}
	result.Active = result.Queued + result.Processing + result.Retry
	_ = DB.Model(&PromptAuditJob{}).Where("status IN ?", []string{PromptAuditJobQueued, PromptAuditJobRetry}).
		Select("COALESCE(MIN(created_at), 0)").Scan(&result.OldestQueuedAt).Error
	return result, nil
}

func CleanupPromptAuditData(now int64, batch int) (int64, int64, error) {
	if batch < 1 || batch > promptAuditDeleteBatchSize {
		batch = promptAuditDeleteBatchSize
	}
	var events []PromptAuditEvent
	if err := DB.Where("expires_at > 0 AND expires_at <= ?", now).Order("id ASC").Limit(batch).
		Select("id", "job_id").Find(&events).Error; err != nil {
		return 0, 0, err
	}
	if len(events) == 0 {
		return 0, 0, nil
	}
	ids := make([]int64, 0, len(events))
	for _, event := range events {
		ids = append(ids, event.Id)
	}
	return DeletePromptAuditEventsByIds(ids)
}

func truncatePromptAuditError(message string) string {
	runes := []rune(strings.TrimSpace(message))
	if len(runes) > 500 {
		runes = runes[:500]
	}
	return string(runes)
}
