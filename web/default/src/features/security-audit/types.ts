/*
Copyright (C) 2023-2026 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/
export type SecurityAuditMode = 'off' | 'async_audit' | 'blocking'
export type SecurityAuditTokenAction = 'keep' | 'replace' | 'clear'

export const SECURITY_AUDIT_SCANNERS = [
  'violent',
  'non_violent_illegal_acts',
  'sexual_content_or_sexual_acts',
  'pii',
  'suicide_and_self_harm',
  'unethical_acts',
  'politically_sensitive_topics',
  'copyright_violation',
  'jailbreak',
] as const

export type SecurityAuditScanner = (typeof SECURITY_AUDIT_SCANNERS)[number]

export interface SecurityAuditEndpoint {
  id: string
  name: string
  protocol: 'openai_compatible'
  base_url: string
  model: string
  timeout_ms: number
  input_limit: number
  enabled: boolean
  has_token: boolean
  token_status: 'configured' | 'missing' | 'unreadable' | string
}

export interface SecurityAuditEndpointDraft extends SecurityAuditEndpoint {
  token_action: SecurityAuditTokenAction
  token: string
}

export interface SecurityAuditConfig {
  enabled: boolean
  blocking_enabled: boolean
  upstream_policy_enabled: boolean
  sensitive_word_audit_enabled: boolean
  store_pass_events: boolean
  effective_mode: SecurityAuditMode
  strategy: 'priority'
  worker_count: number
  queue_capacity: number
  retention_days: number
  scanners: SecurityAuditScanner[]
  all_groups: boolean
  group_ids: number[]
  endpoints: SecurityAuditEndpoint[]
  config_version: number
  updated_at: number
  updated_by: number
  change_summary?: string
}

export interface SecurityAuditConfigDraft extends Omit<
  SecurityAuditConfig,
  'endpoints' | 'effective_mode'
> {
  mode: SecurityAuditMode
  endpoints: SecurityAuditEndpointDraft[]
}

export interface SecurityAuditConfigUpdate {
  expected_version: number
  enabled: boolean
  blocking_enabled: boolean
  store_pass_events: boolean
  strategy: 'priority'
  worker_count: number
  queue_capacity: number
  retention_days: number
  scanners: SecurityAuditScanner[]
  all_groups: boolean
  group_ids: number[]
  endpoints: Array<{
    id: string
    name: string
    protocol: 'openai_compatible'
    base_url: string
    model: string
    timeout_ms: number
    input_limit: number
    enabled: boolean
    token_action: SecurityAuditTokenAction
    token?: string
  }>
}

export interface SecurityAuditQueueRuntime {
  queued: number
  processing: number
  retry: number
  done: number
  failed: number
  active: number
  capacity: number
  oldest_queued_at: number
}

export interface SecurityAuditMetrics {
  total: number
  allowed: number
  flagged: number
  blocked: number
  unavailable: number
  invalid: number
  timeouts: number
  failovers: number
  bulkhead_full: number
  record_failed: number
  enqueued: number
  dropped: number
  processed: number
  failed: number
}

export interface SecurityAuditEndpointHealth {
  id: string
  name: string
  enabled: boolean
  healthy: boolean
  status: string
  latency_ms: number
  checked_at: number
  error_code?: string
}

export interface SecurityAuditRuntime {
  process_status: string
  effective_mode: SecurityAuditMode
  config_version: number
  crypto_ready: boolean
  worker_total: number
  worker_active: number
  worker_heartbeat_at: number
  queue: SecurityAuditQueueRuntime
  queue_delay_ms: number
  metrics: SecurityAuditMetrics
  last_processed_at: number
  last_error_code?: string
  endpoints: SecurityAuditEndpointHealth[]
  generated_at: number
}

export interface SecurityAuditEvent {
  id: number
  job_id: number
  request_id: string
  user_id: number
  username: string
  user_email: string
  api_key_id: number
  api_key_name: string
  group_id: number
  group_name: string
  provider: string
  endpoint: string
  protocol: string
  model: string
  prompt_hash: string
  redacted_preview: string
  prompt_length: number
  prompt_truncated: boolean
  prompt_available: boolean
  message_count: number
  source: 'prompt_guard' | 'sensitive_word' | 'upstream_policy' | string
  stage: string
  decision: string
  risk_level: string
  risk_score: number
  action: string
  safety: string
  categories: string[]
  matched_scanners: string[]
  guard_endpoint_id: string
  config_version: number
  chunk_total: number
  latency_ms: number
  error_code: string
  error_message: string
  created_at: number
  expires_at: number
}

export interface SecurityAuditEventDetail extends SecurityAuditEvent {
  full_prompt: string
}

export interface SecurityAuditEventFilter {
  source?: string
  stage?: string
  decision?: string
  risk_level?: string
  endpoint?: string
  request_id?: string
  prompt_hash?: string
  keyword?: string
  user_id?: number
  token_id?: number
  group_id?: number
  start_at?: number
  end_at?: number
}

export interface SecurityAuditBuiltinPolicy {
  config_version: number
  upstream_policy_enabled: boolean
  sensitive_word_audit_enabled: boolean
  check_sensitive_enabled: boolean
  check_sensitive_on_prompt_enabled: boolean
  sensitive_words: string
  sensitive_rules: string
  sensitive_rule_channel_ids: string
  uses_legacy_sensitive_words: boolean
  updated_at: number
  updated_by: number
}

export interface SecurityAuditBuiltinPolicyUpdate {
  expected_version: number
  upstream_policy_enabled: boolean
  sensitive_word_audit_enabled: boolean
  check_sensitive_enabled: boolean
  check_sensitive_on_prompt_enabled: boolean
  sensitive_rules: string
  sensitive_rule_channel_ids: string
}

export interface SecurityAuditEventPage {
  items: SecurityAuditEvent[]
  total: number
  page: number
  page_size: number
}

export interface SecurityAuditDeletePreview {
  matched_count: number
  snapshot_max_id: number
  filter_hash: string
  confirmation_token: string
  expires_at: number
}

export interface SecurityAuditDeleteResult {
  deleted_events: number
  deleted_jobs: number
}

export interface SecurityAuditProbeResult {
  endpoint_id: string
  healthy: boolean
  latency_ms: number
  status: string
  error_code?: string
  message?: string
}

export interface SecurityAuditGroup {
  id: number
  code: string
  name: string
  description?: string
}

export interface ApiEnvelope<T> {
  success: boolean
  message?: string
  data?: T
}
