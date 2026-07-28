/*
Copyright (C) 2025 QuantumNous

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

import { API, extractGroupDetailsResponse } from '../../helpers';

const API_ROOT = '/api/security-audit';

const unwrap = (response) => {
  const payload = response?.data;
  if (!payload?.success) {
    throw new Error(payload?.message || 'Request failed');
  }
  return payload.data;
};

const requestConfig = {
  disableDuplicate: true,
  skipErrorHandler: true,
};

export const cleanSecurityAuditFilter = (filter = {}) =>
  Object.fromEntries(
    Object.entries(filter).filter(
      ([, value]) => value !== '' && value !== null && value !== undefined,
    ),
  );

export const configToDraft = (config) => ({
  ...config,
  mode: config?.effective_mode || 'off',
  scanners: config?.scanners || [],
  group_ids: config?.group_ids || [],
  endpoints: (config?.endpoints || []).map((endpoint) => ({
    ...endpoint,
    token_action: 'keep',
    token: '',
  })),
});

const endpointToPayload = (endpoint) => ({
  id: String(endpoint.id || '').trim(),
  name: String(endpoint.name || '').trim(),
  protocol: 'openai_compatible',
  base_url: String(endpoint.base_url || '').trim(),
  model: String(endpoint.model || '').trim(),
  timeout_ms: Number(endpoint.timeout_ms),
  input_limit: Number(endpoint.input_limit),
  enabled: endpoint.enabled === true,
  token_action: endpoint.token_action || 'keep',
  ...(endpoint.token_action === 'replace'
    ? { token: String(endpoint.token || '').trim() }
    : {}),
});

export const draftToUpdatePayload = (draft) => ({
  expected_version: draft.config_version,
  enabled: draft.mode !== 'off',
  blocking_enabled: draft.mode === 'blocking',
  store_pass_events: draft.store_pass_events === true,
  strategy: 'priority',
  worker_count: Number(draft.worker_count),
  queue_capacity: Number(draft.queue_capacity),
  retention_days: Number(draft.retention_days),
  scanners: draft.scanners || [],
  all_groups: draft.all_groups === true,
  group_ids: draft.all_groups ? [] : draft.group_ids || [],
  endpoints: (draft.endpoints || []).map(endpointToPayload),
});

export const getSecurityAuditConfig = async () =>
  unwrap(await API.get(`${API_ROOT}/config`, requestConfig));

export const getSecurityAuditBuiltinPolicy = async () =>
  unwrap(await API.get(`${API_ROOT}/builtin-policy`, requestConfig));

export const updateSecurityAuditBuiltinPolicy = async (policy) =>
  unwrap(
    await API.put(
      `${API_ROOT}/builtin-policy`,
      {
        expected_version: policy.config_version,
        upstream_policy_enabled: policy.upstream_policy_enabled === true,
        sensitive_word_audit_enabled:
          policy.sensitive_word_audit_enabled === true,
        check_sensitive_enabled: policy.check_sensitive_enabled === true,
        check_sensitive_on_prompt_enabled:
          policy.check_sensitive_on_prompt_enabled === true,
        sensitive_rules: policy.sensitive_rules || '{"rules":[]}',
        sensitive_rule_channel_ids: policy.sensitive_rule_channel_ids || '[]',
      },
      { skipErrorHandler: true },
    ),
  );

export const updateSecurityAuditConfig = async (draft) =>
  unwrap(
    await API.put(`${API_ROOT}/config`, draftToUpdatePayload(draft), {
      skipErrorHandler: true,
    }),
  );

export const getSecurityAuditRuntime = async () =>
  unwrap(await API.get(`${API_ROOT}/runtime`, requestConfig));

export const getSecurityAuditGroups = async () => {
  const response = await API.get('/api/group/details', requestConfig);
  if (!response?.data?.success) {
    throw new Error(response?.data?.message || 'Request failed');
  }
  return extractGroupDetailsResponse(response.data) || [];
};

export const getSecurityAuditEvents = async (filter, page, pageSize) =>
  unwrap(
    await API.get(`${API_ROOT}/events`, {
      ...requestConfig,
      params: {
        ...cleanSecurityAuditFilter(filter),
        page,
        page_size: pageSize,
      },
    }),
  );

export const getSecurityAuditEvent = async (id) =>
  unwrap(
    await API.get(`${API_ROOT}/events/${id}`, {
      ...requestConfig,
      skipErrorHandler: true,
    }),
  );

export const deleteSecurityAuditEvent = async (id) =>
  unwrap(
    await API.delete(`${API_ROOT}/events/${id}`, {
      skipErrorHandler: true,
    }),
  );

export const batchDeleteSecurityAuditEvents = async (ids) =>
  unwrap(
    await API.post(
      `${API_ROOT}/events/batch-delete`,
      { ids },
      { skipErrorHandler: true },
    ),
  );

export const previewSecurityAuditDelete = async (filter) =>
  unwrap(
    await API.post(
      `${API_ROOT}/events/delete-preview`,
      cleanSecurityAuditFilter(filter),
      { skipErrorHandler: true },
    ),
  );

export const deleteSecurityAuditEventsByFilter = async (filter, preview) =>
  unwrap(
    await API.post(
      `${API_ROOT}/events/delete-by-filter`,
      {
        filter: cleanSecurityAuditFilter(filter),
        confirmation_token: preview.confirmation_token,
        confirm: true,
      },
      { skipErrorHandler: true },
    ),
  );

export const probeSecurityAuditEndpoint = async (endpoint) => {
  const payload = endpointToPayload(endpoint);
  return unwrap(
    await API.post(
      `${API_ROOT}/endpoints/probe`,
      {
        endpoint_id: payload.id,
        name: payload.name,
        base_url: payload.base_url,
        model: payload.model,
        timeout_ms: payload.timeout_ms,
        input_limit: payload.input_limit,
        token_action: payload.token_action,
        ...(payload.token ? { token: payload.token } : {}),
      },
      { skipErrorHandler: true },
    ),
  );
};
