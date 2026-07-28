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
import { api } from '@/lib/api'
import type {
  ApiEnvelope,
  SecurityAuditBuiltinPolicy,
  SecurityAuditBuiltinPolicyUpdate,
  SecurityAuditConfig,
  SecurityAuditConfigDraft,
  SecurityAuditConfigUpdate,
  SecurityAuditDeletePreview,
  SecurityAuditDeleteResult,
  SecurityAuditEndpointDraft,
  SecurityAuditEventDetail,
  SecurityAuditEventFilter,
  SecurityAuditEventPage,
  SecurityAuditGroup,
  SecurityAuditProbeResult,
  SecurityAuditRuntime,
} from './types'

const API_ROOT = '/api/security-audit'

function unwrap<T>(response: ApiEnvelope<T>): T {
  if (response.success === false || response.data === undefined) {
    throw new Error(response.message || 'Request failed')
  }
  return response.data
}

function cleanFilter(filter: SecurityAuditEventFilter) {
  return Object.fromEntries(
    Object.entries(filter).filter(([, value]) => {
      if (typeof value === 'string') return value.trim() !== ''
      if (typeof value === 'number') return value > 0
      return value != null
    })
  )
}

export function hasSecurityAuditEventFilter(filter: SecurityAuditEventFilter) {
  return Object.keys(cleanFilter(filter)).length > 0
}

type UnknownRecord = Record<string, unknown>

function asRecord(value: unknown): UnknownRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as UnknownRecord)
    : {}
}

function readValue(record: UnknownRecord, ...keys: string[]) {
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null) return record[key]
  }
  return undefined
}

function readString(record: UnknownRecord, ...keys: string[]) {
  const value = readValue(record, ...keys)
  return typeof value === 'string' ? value : ''
}

function readNumber(record: UnknownRecord, ...keys: string[]) {
  const value = readValue(record, ...keys)
  if (typeof value === 'number' && Number.isFinite(value)) return value
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    if (Number.isFinite(parsed)) return parsed
  }
  return 0
}

function readBoolean(record: UnknownRecord, ...keys: string[]) {
  const value = readValue(record, ...keys)
  if (typeof value === 'boolean') return value
  if (typeof value === 'number') return value !== 0
  if (typeof value === 'string') return value.toLowerCase() === 'true'
  return false
}

function normalizeMode(value: string): SecurityAuditRuntime['effective_mode'] {
  if (value === 'async_audit' || value === 'blocking') return value
  return 'off'
}

function normalizeQueue(value: unknown): SecurityAuditRuntime['queue'] {
  const queue = asRecord(value)
  return {
    queued: readNumber(queue, 'queued', 'Queued'),
    processing: readNumber(queue, 'processing', 'Processing'),
    retry: readNumber(queue, 'retry', 'Retry'),
    done: readNumber(queue, 'done', 'Done'),
    failed: readNumber(queue, 'failed', 'Failed'),
    active: readNumber(queue, 'active', 'Active'),
    capacity: readNumber(queue, 'capacity', 'Capacity'),
    oldest_queued_at: readNumber(queue, 'oldest_queued_at', 'OldestQueuedAt'),
  }
}

function normalizeMetrics(value: unknown): SecurityAuditRuntime['metrics'] {
  const metrics = asRecord(value)
  return {
    total: readNumber(metrics, 'total', 'Total'),
    allowed: readNumber(metrics, 'allowed', 'Allowed'),
    flagged: readNumber(metrics, 'flagged', 'Flagged'),
    blocked: readNumber(metrics, 'blocked', 'Blocked'),
    unavailable: readNumber(metrics, 'unavailable', 'Unavailable'),
    invalid: readNumber(metrics, 'invalid', 'Invalid'),
    timeouts: readNumber(metrics, 'timeouts', 'Timeouts'),
    failovers: readNumber(metrics, 'failovers', 'Failovers'),
    bulkhead_full: readNumber(metrics, 'bulkhead_full', 'BulkheadFull'),
    record_failed: readNumber(metrics, 'record_failed', 'RecordFailed'),
    enqueued: readNumber(metrics, 'enqueued', 'Enqueued'),
    dropped: readNumber(metrics, 'dropped', 'Dropped'),
    processed: readNumber(metrics, 'processed', 'Processed'),
    failed: readNumber(metrics, 'failed', 'Failed'),
  }
}

function normalizeEndpointHealth(value: unknown, fallbackId = '') {
  const endpoint = asRecord(value)
  return {
    id: readString(endpoint, 'id', 'Id') || fallbackId,
    name:
      readString(endpoint, 'name', 'Name') ||
      readString(endpoint, 'id', 'Id') ||
      fallbackId,
    enabled: readBoolean(endpoint, 'enabled', 'Enabled'),
    healthy: readBoolean(endpoint, 'healthy', 'Healthy', 'ok', 'Ok'),
    status: readString(endpoint, 'status', 'Status'),
    latency_ms: readNumber(endpoint, 'latency_ms', 'LatencyMs'),
    checked_at: readNumber(endpoint, 'checked_at', 'CheckedAt'),
    error_code: readString(endpoint, 'error_code', 'ErrorCode') || undefined,
  }
}

function normalizeEndpointHealthList(value: unknown) {
  if (Array.isArray(value)) {
    return value.map((endpoint) => normalizeEndpointHealth(endpoint))
  }
  return Object.entries(asRecord(value)).map(([id, endpoint]) =>
    normalizeEndpointHealth(endpoint, id)
  )
}

function normalizeRuntime(value: unknown): SecurityAuditRuntime {
  const runtime = asRecord(value)
  const processStatus =
    readString(runtime, 'process_status', 'ProcessStatus') ||
    (readBoolean(runtime, 'worker_running', 'WorkerRunning')
      ? 'running'
      : 'stopped')

  return {
    process_status: processStatus,
    effective_mode: normalizeMode(
      readString(runtime, 'effective_mode', 'EffectiveMode', 'mode', 'Mode')
    ),
    config_version: readNumber(runtime, 'config_version', 'ConfigVersion'),
    crypto_ready: readBoolean(runtime, 'crypto_ready', 'CryptoReady'),
    worker_total: readNumber(
      runtime,
      'worker_total',
      'WorkerTotal',
      'worker_count',
      'WorkerCount'
    ),
    worker_active: readNumber(runtime, 'worker_active', 'WorkerActive'),
    worker_heartbeat_at: readNumber(
      runtime,
      'worker_heartbeat_at',
      'WorkerHeartbeatAt'
    ),
    queue: normalizeQueue(readValue(runtime, 'queue', 'Queue')),
    queue_delay_ms: readNumber(runtime, 'queue_delay_ms', 'QueueDelayMs'),
    metrics: normalizeMetrics(readValue(runtime, 'metrics', 'Metrics')),
    last_processed_at: readNumber(
      runtime,
      'last_processed_at',
      'LastProcessedAt'
    ),
    last_error_code:
      readString(runtime, 'last_error_code', 'LastErrorCode') || undefined,
    endpoints: normalizeEndpointHealthList(
      readValue(runtime, 'endpoints', 'Endpoints')
    ),
    generated_at: readNumber(runtime, 'generated_at', 'GeneratedAt'),
  }
}

export function configToDraft(
  config: SecurityAuditConfig
): SecurityAuditConfigDraft {
  return {
    ...config,
    mode:
      config.effective_mode ||
      (config.blocking_enabled
        ? 'blocking'
        : config.enabled
          ? 'async_audit'
          : 'off'),
    scanners: config.scanners || [],
    group_ids: config.group_ids || [],
    // 数据库初始配置没有节点时，Go 的 nil slice 会序列化为 null；
    // 页面草稿必须把它归一化为空数组，避免首次打开独立页面崩溃。
    endpoints: (config.endpoints || []).map((endpoint) => ({
      ...endpoint,
      token_action: 'keep',
      token: '',
    })),
  }
}

function endpointToInput(endpoint: SecurityAuditEndpointDraft) {
  return {
    id: endpoint.id.trim(),
    name: endpoint.name.trim(),
    protocol: 'openai_compatible' as const,
    base_url: endpoint.base_url.trim(),
    model: endpoint.model.trim(),
    timeout_ms: endpoint.timeout_ms,
    input_limit: endpoint.input_limit,
    enabled: endpoint.enabled,
    token_action: endpoint.token_action,
    ...(endpoint.token_action === 'replace'
      ? { token: endpoint.token.trim() }
      : {}),
  }
}

function normalizeProbeResult(value: unknown): SecurityAuditProbeResult {
  const result = asRecord(value)
  return {
    endpoint_id: readString(result, 'endpoint_id', 'EndpointId'),
    healthy: readBoolean(result, 'healthy', 'Healthy', 'ok', 'Ok'),
    latency_ms: readNumber(result, 'latency_ms', 'LatencyMs'),
    status: readString(result, 'status', 'Status'),
    error_code: readString(result, 'error_code', 'ErrorCode') || undefined,
    message: readString(result, 'message', 'Message') || undefined,
  }
}

export function draftToConfigUpdate(
  draft: SecurityAuditConfigDraft
): SecurityAuditConfigUpdate {
  return {
    expected_version: draft.config_version,
    enabled: draft.mode !== 'off',
    blocking_enabled: draft.mode === 'blocking',
    store_pass_events: draft.store_pass_events,
    strategy: 'priority',
    worker_count: draft.worker_count,
    queue_capacity: draft.queue_capacity,
    retention_days: draft.retention_days,
    scanners: draft.scanners,
    all_groups: draft.all_groups,
    group_ids: draft.all_groups ? [] : draft.group_ids,
    endpoints: draft.endpoints.map(endpointToInput),
  }
}

export async function getSecurityAuditConfig() {
  const response = await api.get<ApiEnvelope<SecurityAuditConfig>>(
    `${API_ROOT}/config`,
    { disableDuplicate: true }
  )
  return unwrap(response.data)
}

export async function getSecurityAuditBuiltinPolicy() {
  const response = await api.get<ApiEnvelope<SecurityAuditBuiltinPolicy>>(
    `${API_ROOT}/builtin-policy`,
    { disableDuplicate: true }
  )
  return unwrap(response.data)
}

export async function updateSecurityAuditBuiltinPolicy(
  input: SecurityAuditBuiltinPolicyUpdate
) {
  const response = await api.put<ApiEnvelope<SecurityAuditBuiltinPolicy>>(
    `${API_ROOT}/builtin-policy`,
    input,
    { skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function updateSecurityAuditConfig(
  input: SecurityAuditConfigUpdate
) {
  const response = await api.put<ApiEnvelope<SecurityAuditConfig>>(
    `${API_ROOT}/config`,
    input,
    { skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function probeSecurityAuditEndpoint(
  endpoint: SecurityAuditEndpointDraft
) {
  const response = await api.post<ApiEnvelope<unknown>>(
    `${API_ROOT}/endpoints/probe`,
    {
      endpoint_id: endpoint.id.trim(),
      name: endpoint.name.trim(),
      base_url: endpoint.base_url.trim(),
      model: endpoint.model.trim(),
      timeout_ms: endpoint.timeout_ms,
      input_limit: endpoint.input_limit,
      token_action: endpoint.token_action,
      ...(endpoint.token_action === 'replace' && endpoint.token.trim() !== ''
        ? { token: endpoint.token.trim() }
        : {}),
    },
    { skipBusinessError: true }
  )
  return normalizeProbeResult(unwrap(response.data))
}

export async function getSecurityAuditRuntime() {
  const response = await api.get<ApiEnvelope<unknown>>(`${API_ROOT}/runtime`, {
    disableDuplicate: true,
  })
  return normalizeRuntime(unwrap(response.data))
}

export async function getSecurityAuditEvents(
  filter: SecurityAuditEventFilter,
  page: number,
  pageSize: number
) {
  const response = await api.get<ApiEnvelope<SecurityAuditEventPage>>(
    `${API_ROOT}/events`,
    {
      params: { ...cleanFilter(filter), page, page_size: pageSize },
      disableDuplicate: true,
    }
  )
  return unwrap(response.data)
}

export async function getSecurityAuditEvent(id: number) {
  const response = await api.get<ApiEnvelope<SecurityAuditEventDetail>>(
    `${API_ROOT}/events/${id}`,
    { disableDuplicate: true, skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function deleteSecurityAuditEvent(id: number) {
  const response = await api.delete<ApiEnvelope<SecurityAuditDeleteResult>>(
    `${API_ROOT}/events/${id}`,
    { skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function batchDeleteSecurityAuditEvents(ids: number[]) {
  const response = await api.post<ApiEnvelope<SecurityAuditDeleteResult>>(
    `${API_ROOT}/events/batch-delete`,
    { ids },
    { skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function previewSecurityAuditDelete(
  filter: SecurityAuditEventFilter
) {
  const response = await api.post<ApiEnvelope<SecurityAuditDeletePreview>>(
    `${API_ROOT}/events/delete-preview`,
    cleanFilter(filter),
    { skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function deleteSecurityAuditEventsByFilter(
  filter: SecurityAuditEventFilter,
  preview: SecurityAuditDeletePreview
) {
  const response = await api.post<ApiEnvelope<SecurityAuditDeleteResult>>(
    `${API_ROOT}/events/delete-by-filter`,
    {
      filter: cleanFilter(filter),
      confirmation_token: preview.confirmation_token,
      confirm: true,
    },
    { skipBusinessError: true }
  )
  return unwrap(response.data)
}

export async function getSecurityAuditGroups() {
  const response = await api.get<
    ApiEnvelope<
      Array<{
        id: number
        code: string
        name: string
        description?: string
      }>
    >
  >('/api/group/details')
  const groups = unwrap(response.data)
  return groups.map<SecurityAuditGroup>((group) => ({
    id: group.id,
    code: group.code,
    name: group.name,
    description: group.description,
  }))
}
