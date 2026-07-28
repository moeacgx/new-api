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

import React, { useCallback, useEffect, useState } from 'react';
import {
  Banner,
  Button,
  Card,
  Space,
  Spin,
  Switch,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { useTranslation } from 'react-i18next';
import SettingsSensitiveWords from '../Setting/Operation/SettingsSensitiveWords';
import {
  getSecurityAuditBuiltinPolicy,
  updateSecurityAuditBuiltinPolicy,
} from './api';

const { Text } = Typography;

const getErrorMessage = (error, fallback) =>
  error?.response?.data?.message || error?.message || fallback;

const BuiltinPolicyTab = ({ runSensitive, onSaved }) => {
  const { t } = useTranslation();
  const [baseline, setBaseline] = useState(null);
  const [draft, setDraft] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState('');

  const loadPolicy = useCallback(async () => {
    setLoading(true);
    setLoadError('');
    try {
      const policy = await getSecurityAuditBuiltinPolicy();
      setBaseline(policy);
      setDraft(policy);
    } catch (error) {
      setLoadError(getErrorMessage(error, t('内置安全策略加载失败')));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    void loadPolicy();
  }, [loadPolicy]);

  const switchesDirty = Boolean(
    draft &&
      baseline &&
      (draft.upstream_policy_enabled !== baseline.upstream_policy_enabled ||
        draft.sensitive_word_audit_enabled !==
          baseline.sensitive_word_audit_enabled),
  );

  const applySavedPolicy = (policy) => {
    setBaseline(policy);
    setDraft(policy);
    onSaved?.(policy);
    Toast.success({ content: t('内置安全策略已保存') });
  };

  const savePolicy = async (values) => {
    if (!draft) return;
    setSaving(true);
    try {
      await runSensitive(
        () =>
          updateSecurityAuditBuiltinPolicy({
            ...draft,
            check_sensitive_enabled: values.CheckSensitiveEnabled,
            check_sensitive_on_prompt_enabled:
              values.CheckSensitiveOnPromptEnabled,
            sensitive_rules: values.SensitiveRules,
            sensitive_rule_channel_ids: values.SensitiveRuleChannelIds,
          }),
        applySavedPolicy,
        {
          title: t('验证内置安全策略变更'),
          description: t('此操作会改变本地屏蔽词过滤和上游策略事件采集。'),
        },
      );
    } catch (error) {
      if (error?.response?.status === 409) {
        Toast.error({
          content: t('配置已被其他管理员更新，已重新加载最新版本'),
        });
        await loadPolicy();
      } else {
        Toast.error({
          content: getErrorMessage(error, t('内置安全策略保存失败')),
        });
      }
    } finally {
      setSaving(false);
    }
  };

  if (loadError) {
    return (
      <Banner
        type='danger'
        closeIcon={null}
        description={
          <Space wrap>
            <span>{loadError}</span>
            <Button size='small' onClick={() => void loadPolicy()}>
              {t('重试')}
            </Button>
          </Space>
        }
      />
    );
  }

  return (
    <Spin spinning={loading && !draft}>
      {draft ? (
        <div className='space-y-4'>
          <Banner
            type='info'
            closeIcon={null}
            description={t(
              'Guard 节点不是必需项：屏蔽词在本机运行，上游返回精确的 cyber_policy 错误码时也会被识别。',
            )}
          />

          <Card title={t('内置安全策略')} bodyStyle={{ padding: 16 }}>
            <Text type='tertiary' size='small'>
              {t('选择哪些无需 Guard 节点的检测结果写入统一审计事件。')}
            </Text>
            <div className='mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2'>
              <div className='rounded-lg border border-[var(--semi-color-border)] p-4'>
                <Space align='start'>
                  <Switch
                    checked={draft.upstream_policy_enabled}
                    onChange={(enabled) =>
                      setDraft((current) => ({
                        ...current,
                        upstream_policy_enabled: enabled,
                      }))
                    }
                  />
                  <div>
                    <Text strong>{t('识别上游安全策略事件')}</Text>
                    <Text type='tertiary' size='small' className='mt-1 block'>
                      {t(
                        '记录 HTTP、流式响应和 Realtime 上游返回的精确 cyber_policy 拒绝。',
                      )}
                    </Text>
                  </div>
                </Space>
              </div>
              <div className='rounded-lg border border-[var(--semi-color-border)] p-4'>
                <Space align='start'>
                  <Switch
                    checked={draft.sensitive_word_audit_enabled}
                    onChange={(enabled) =>
                      setDraft((current) => ({
                        ...current,
                        sensitive_word_audit_enabled: enabled,
                      }))
                    }
                  />
                  <div>
                    <Text strong>{t('记录屏蔽词事件')}</Text>
                    <Text type='tertiary' size='small' className='mt-1 block'>
                      {t(
                        '请求、返回或 Realtime 命中屏蔽词时，去重后写入统一审计事件。',
                      )}
                    </Text>
                  </div>
                </Space>
              </div>
            </div>
          </Card>

          {draft.uses_legacy_sensitive_words ? (
            <Banner
              type='warning'
              closeIcon={null}
              description={t(
                '检测到旧版屏蔽词：页面已将其显示为结构化阻断规则，保存时会保留原始数据并启用结构化规则。',
              )}
            />
          ) : null}

          <Card
            title={t('屏蔽词过滤')}
            headerExtraContent={
              <Text type='tertiary' size='small'>
                {t('原系统设置中的规则已迁移到这里，继续使用同一份配置。')}
              </Text>
            }
            bodyStyle={{ padding: 16 }}
          >
            <SettingsSensitiveWords
              options={{
                CheckSensitiveEnabled: draft.check_sensitive_enabled,
                CheckSensitiveOnPromptEnabled:
                  draft.check_sensitive_on_prompt_enabled,
                SensitiveWords: draft.sensitive_words,
                SensitiveRules: draft.sensitive_rules,
                SensitiveRuleChannelIds: draft.sensitive_rule_channel_ids,
              }}
              externalDirty={switchesDirty}
              saving={saving}
              onSave={savePolicy}
              onResetExternal={() => setDraft(baseline)}
            />
          </Card>
        </div>
      ) : (
        <div className='min-h-72' />
      )}
    </Spin>
  );
};

export default BuiltinPolicyTab;
