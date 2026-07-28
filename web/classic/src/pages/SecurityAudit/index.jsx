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

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import {
  Banner,
  Button,
  Card,
  Space,
  Spin,
  Tabs,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import {
  Activity,
  FileSearch,
  ListFilter,
  RefreshCw,
  Save,
  Server,
  ShieldCheck,
  SlidersHorizontal,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import SecureVerificationModal from '../../components/common/modals/SecureVerificationModal';
import { useSecureVerification } from '../../hooks/common/useSecureVerification';
import { showError } from '../../helpers';
import {
  configToDraft,
  getSecurityAuditConfig,
  getSecurityAuditGroups,
  getSecurityAuditRuntime,
  updateSecurityAuditConfig,
} from './api';
import BuiltinPolicyTab from './BuiltinPolicyTab';
import EndpointsTab from './EndpointsTab';
import EventsTab from './EventsTab';
import OverviewTab from './OverviewTab';
import PolicyTab from './PolicyTab';

const { Text, Title } = Typography;

const getErrorMessage = (error, fallback) =>
  error?.response?.data?.message || error?.message || fallback;

const validateDraft = (draft, runtime, t) => {
  if (!draft.scanners?.length) return t('请至少选择一个风险分类');
  if (!draft.all_groups && !draft.group_ids?.length) {
    return t('请选择至少一个用户分组，或启用全部分组');
  }
  if (draft.worker_count < 1 || draft.worker_count > 32) {
    return t('Worker 数量必须在 1 到 32 之间');
  }
  if (draft.queue_capacity < 1 || draft.queue_capacity > 100000) {
    return t('队列容量必须在 1 到 100000 之间');
  }
  if (draft.retention_days < 1 || draft.retention_days > 365) {
    return t('事件保留天数必须在 1 到 365 之间');
  }

  const ids = new Set();
  for (const endpoint of draft.endpoints || []) {
    const id = String(endpoint.id || '').trim();
    if (
      !id ||
      !String(endpoint.name || '').trim() ||
      !String(endpoint.base_url || '').trim() ||
      !String(endpoint.model || '').trim()
    ) {
      return t('每个 Guard 节点都必须填写 ID、名称、地址和模型');
    }
    if (ids.has(id)) return t('Guard 节点 ID 不能重复');
    ids.add(id);
    if (endpoint.timeout_ms < 100 || endpoint.timeout_ms > 30000) {
      return t('Guard 节点超时必须在 100 到 30000 毫秒之间');
    }
    if (endpoint.input_limit < 128 || endpoint.input_limit > 100000) {
      return t('单片字符数必须在 128 到 100000 之间');
    }
    if (
      endpoint.token_action === 'replace' &&
      !String(endpoint.token || '').trim()
    ) {
      return t('选择替换令牌后必须填写新的 Guard 令牌');
    }
  }

  if (draft.mode !== 'off') {
    if (!runtime?.crypto_ready) {
      return t('启用安全审计前必须显式配置稳定的 CRYPTO_SECRET');
    }
    const usableEndpoint = (draft.endpoints || []).some(
      (endpoint) => endpoint.enabled,
    );
    if (!usableEndpoint) {
      return t('启用安全审计前至少需要一个已启用的 Guard 节点');
    }
  }
  return '';
};

const SecurityAudit = () => {
  const { t } = useTranslation();
  const [activeTab, setActiveTab] = useState('overview');
  const [config, setConfig] = useState(null);
  const [draft, setDraft] = useState(null);
  const [runtime, setRuntime] = useState(null);
  const [groups, setGroups] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState('');
  const pendingSensitiveSuccess = useRef(null);

  const verification = useSecureVerification({
    onSuccess: (result) => {
      const callback = pendingSensitiveSuccess.current;
      pendingSensitiveSuccess.current = null;
      callback?.(result);
    },
    onError: () => {
      pendingSensitiveSuccess.current = null;
      setSaving(false);
    },
  });

  const runSensitive = useCallback(
    async (apiCall, onSuccess, options = {}) => {
      pendingSensitiveSuccess.current = onSuccess;
      try {
        const result = await verification.withVerification(apiCall, options);
        if (result !== null && result !== undefined) {
          const callback = pendingSensitiveSuccess.current;
          pendingSensitiveSuccess.current = null;
          callback?.(result);
        }
        return result;
      } catch (error) {
        pendingSensitiveSuccess.current = null;
        throw error;
      }
    },
    [verification.withVerification],
  );

  const loadAll = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const [nextConfig, nextRuntime, nextGroups] = await Promise.all([
        getSecurityAuditConfig(),
        getSecurityAuditRuntime(),
        getSecurityAuditGroups(),
      ]);
      setConfig(nextConfig);
      setDraft(configToDraft(nextConfig));
      setRuntime(nextRuntime);
      setGroups(nextGroups);
    } catch (error) {
      setLoadError(getErrorMessage(error, t('安全审计加载失败')));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      void getSecurityAuditRuntime()
        .then(setRuntime)
        .catch(() => {});
    }, 10000);
    return () => window.clearInterval(timer);
  }, []);

  const baseline = useMemo(
    () => (config ? configToDraft(config) : null),
    [config],
  );
  const dirty = Boolean(
    draft && baseline && JSON.stringify(draft) !== JSON.stringify(baseline),
  );

  const updateDraft = (patch) => {
    setDraft((current) => (current ? { ...current, ...patch } : current));
  };

  const applySavedConfig = (saved) => {
    setConfig(saved);
    setDraft(configToDraft(saved));
    setSaving(false);
    Toast.success({ content: t('安全审计配置已保存') });
    void getSecurityAuditRuntime()
      .then(setRuntime)
      .catch(() => {});
  };

  const applySavedBuiltinPolicy = (saved) => {
    const patch = {
      config_version: saved.config_version,
      upstream_policy_enabled: saved.upstream_policy_enabled,
      sensitive_word_audit_enabled: saved.sensitive_word_audit_enabled,
      updated_at: saved.updated_at,
      updated_by: saved.updated_by,
    };
    setConfig((current) => (current ? { ...current, ...patch } : current));
    setDraft((current) => (current ? { ...current, ...patch } : current));
    void getSecurityAuditRuntime()
      .then(setRuntime)
      .catch(() => {});
  };

  const saveConfig = async () => {
    if (!draft) return;
    const validationError = validateDraft(draft, runtime, t);
    if (validationError) {
      Toast.warning({ content: validationError });
      return;
    }
    setSaving(true);
    try {
      const result = await runSensitive(
        () => updateSecurityAuditConfig(draft),
        applySavedConfig,
        {
          title: t('验证安全审计配置变更'),
          description: t('此操作会改变请求安全边界和 Guard 凭据。'),
        },
      );
      if (result === null || result === undefined) setSaving(false);
    } catch (error) {
      setSaving(false);
      if (error?.response?.status === 409) {
        Toast.error({
          content: t('配置已被其他管理员更新，已重新加载最新版本'),
        });
        await loadAll();
        return;
      }
      showError(getErrorMessage(error, t('保存失败')));
    }
  };

  return (
    <>
      <div className='mx-auto mt-[60px] min-h-screen w-full max-w-[1600px] px-2 pb-8 lg:min-h-0'>
        <Card bodyStyle={{ padding: 16 }}>
          <div className='mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between'>
            <div>
              <div className='flex items-center gap-2'>
                <ShieldCheck size={24} color='var(--semi-color-primary)' />
                <Title heading={3} className='m-0'>
                  {t('安全审计')}
                </Title>
              </div>
              <Text type='tertiary' className='mt-1 block'>
                {t(
                  '统一管理本地屏蔽词、上游安全策略和 Qwen3Guard 提示词审计。',
                )}
              </Text>
            </div>
            <Space wrap>
              <Button
                icon={<RefreshCw size={15} />}
                loading={loading}
                onClick={() => void loadAll()}
              >
                {t('刷新')}
              </Button>
              {activeTab !== 'builtin-policy' ? (
                <Button
                  type='primary'
                  icon={<Save size={15} />}
                  loading={saving}
                  disabled={!dirty || !draft}
                  onClick={() => void saveConfig()}
                >
                  {t('保存更改')}
                </Button>
              ) : null}
            </Space>
          </div>

          {loadError ? (
            <Banner
              type='danger'
              description={loadError}
              closeIcon={null}
              className='mb-4'
            />
          ) : null}

          <Spin spinning={loading && !draft}>
            {draft ? (
              <Tabs type='line' activeKey={activeTab} onChange={setActiveTab}>
                <Tabs.TabPane
                  tab={
                    <Space spacing={6}>
                      <Activity size={15} />
                      {t('概览')}
                    </Space>
                  }
                  itemKey='overview'
                >
                  <div className='pt-4'>
                    <OverviewTab
                      config={draft}
                      runtime={runtime}
                      loading={!runtime}
                    />
                  </div>
                </Tabs.TabPane>
                <Tabs.TabPane
                  tab={
                    <Space spacing={6}>
                      <FileSearch size={15} />
                      {t('审计事件')}
                    </Space>
                  }
                  itemKey='events'
                >
                  <div className='pt-4'>
                    <EventsTab
                      endpoints={draft.endpoints}
                      runSensitive={runSensitive}
                    />
                  </div>
                </Tabs.TabPane>
                <Tabs.TabPane
                  tab={
                    <Space spacing={6}>
                      <ListFilter size={15} />
                      {t('内置策略')}
                    </Space>
                  }
                  itemKey='builtin-policy'
                >
                  <div className='pt-4'>
                    <BuiltinPolicyTab
                      runSensitive={runSensitive}
                      onSaved={applySavedBuiltinPolicy}
                    />
                  </div>
                </Tabs.TabPane>
                <Tabs.TabPane
                  tab={
                    <Space spacing={6}>
                      <Server size={15} />
                      {t('Guard 节点')}
                    </Space>
                  }
                  itemKey='endpoints'
                >
                  <div className='pt-4'>
                    <EndpointsTab
                      endpoints={draft.endpoints}
                      onChange={(endpoints) => updateDraft({ endpoints })}
                      runSensitive={runSensitive}
                    />
                  </div>
                </Tabs.TabPane>
                <Tabs.TabPane
                  tab={
                    <Space spacing={6}>
                      <SlidersHorizontal size={15} />
                      {t('审计策略')}
                    </Space>
                  }
                  itemKey='policy'
                >
                  <div className='pt-4'>
                    <PolicyTab
                      draft={draft}
                      groups={groups}
                      groupsLoading={loading}
                      onChange={updateDraft}
                    />
                  </div>
                </Tabs.TabPane>
              </Tabs>
            ) : (
              <div className='min-h-72' />
            )}
          </Spin>
        </Card>
      </div>

      <SecureVerificationModal
        visible={verification.isModalVisible}
        verificationMethods={verification.verificationMethods}
        verificationState={verification.verificationState}
        onVerify={verification.executeVerification}
        onCancel={() => {
          pendingSensitiveSuccess.current = null;
          setSaving(false);
          verification.cancelVerification();
        }}
        onCodeChange={verification.setVerificationCode}
        onMethodSwitch={verification.switchVerificationMethod}
        title={verification.verificationState.title}
        description={verification.verificationState.description}
      />
    </>
  );
};

export default SecurityAudit;
