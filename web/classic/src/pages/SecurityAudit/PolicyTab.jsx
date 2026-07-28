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

import React from 'react';
import {
  Banner,
  Card,
  Checkbox,
  InputNumber,
  Select,
  Space,
  Spin,
  Switch,
  Typography,
} from '@douyinfe/semi-ui';
import { useTranslation } from 'react-i18next';
import { MODE_OPTIONS, SECURITY_AUDIT_SCANNERS } from './constants';

const { Text } = Typography;

const PolicyTab = ({ draft, groups, groupsLoading, onChange }) => {
  const { t } = useTranslation();

  const toggleScanner = (scanner, checked) => {
    const selected = new Set(draft.scanners || []);
    if (checked) selected.add(scanner);
    else selected.delete(scanner);
    onChange({
      scanners: SECURITY_AUDIT_SCANNERS.map((item) => item.value).filter(
        (item) => selected.has(item),
      ),
    });
  };

  const updateEndpointRuntime = (index, patch) => {
    onChange({
      endpoints: (draft.endpoints || []).map((endpoint, endpointIndex) =>
        endpointIndex === index ? { ...endpoint, ...patch } : endpoint,
      ),
    });
  };

  return (
    <div className='space-y-4'>
      <Card title={t('审计模式')} bodyStyle={{ padding: 16 }}>
        <div className='grid grid-cols-1 gap-4 lg:grid-cols-[minmax(240px,360px)_1fr]'>
          <label className='space-y-1'>
            <Text type='tertiary' size='small'>
              {t('运行模式')}
            </Text>
            <Select
              value={draft.mode}
              style={{ width: '100%' }}
              onChange={(mode) => onChange({ mode })}
            >
              {MODE_OPTIONS.map((option) => (
                <Select.Option key={option.value} value={option.value}>
                  {t(option.label)}
                </Select.Option>
              ))}
            </Select>
          </label>
          <Banner
            type={draft.mode === 'blocking' ? 'warning' : 'info'}
            description={
              draft.mode === 'off'
                ? t(
                    '关闭时不执行 Guard 检查；内置屏蔽词和上游安全策略仍可独立运行并记录事件。',
                  )
                : draft.mode === 'async_audit'
                  ? t('异步审计不影响主请求，审计任务由数据库队列处理。')
                  : t(
                      '同步阻断在渠道分配和计费前执行，Guard 故障时按失败关闭处理。',
                    )
            }
          />
        </div>
      </Card>

      <Card title={t('分组范围')} bodyStyle={{ padding: 16 }}>
        <Space>
          <Switch
            checked={draft.all_groups}
            onChange={(checked) =>
              onChange({
                all_groups: checked,
                group_ids: checked ? [] : draft.group_ids,
              })
            }
          />
          <Text>{t('覆盖全部用户分组')}</Text>
        </Space>
        {!draft.all_groups ? (
          <Spin spinning={groupsLoading}>
            <Select
              className='mt-4'
              multiple
              filter
              value={draft.group_ids || []}
              style={{ width: '100%' }}
              placeholder={t('选择需要审计的用户分组')}
              onChange={(values) =>
                onChange({
                  group_ids: (Array.isArray(values) ? values : [])
                    .map(Number)
                    .filter((value) => value > 0),
                })
              }
            >
              {(groups || [])
                .filter((group) => group.id)
                .map((group) => (
                  <Select.Option key={group.id} value={group.id}>
                    {group.name || group.code} ({group.code})
                  </Select.Option>
                ))}
            </Select>
          </Spin>
        ) : null}
      </Card>

      <Card title={t('风险分类')} bodyStyle={{ padding: 16 }}>
        <Text type='tertiary' size='small'>
          {t('选中的分类命中后会标记事件；同步模式下会阻断请求。')}
        </Text>
        <div className='mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3'>
          {SECURITY_AUDIT_SCANNERS.map((scanner) => (
            <div
              key={scanner.value}
              className='rounded-lg border border-[var(--semi-color-border)] p-3'
            >
              <Checkbox
                checked={(draft.scanners || []).includes(scanner.value)}
                onChange={(event) =>
                  toggleScanner(scanner.value, event.target.checked)
                }
              >
                {t(scanner.label)}
              </Checkbox>
              <Text
                type='tertiary'
                size='small'
                className='mt-1 block break-all'
              >
                {scanner.value}
              </Text>
            </div>
          ))}
        </div>
      </Card>

      <Card title={t('保存与保留策略')} bodyStyle={{ padding: 16 }}>
        <div className='grid grid-cols-1 gap-4 lg:grid-cols-2'>
          <div className='rounded-lg border border-[var(--semi-color-border)] p-4'>
            <Space align='start'>
              <Switch
                checked={draft.store_pass_events}
                onChange={(checked) => onChange({ store_pass_events: checked })}
              />
              <div>
                <Text strong>{t('保存 Safe 事件')}</Text>
                <Text type='tertiary' size='small' className='mt-1 block'>
                  {t('默认不保存通过事件，以减少敏感数据持久化。')}
                </Text>
              </div>
            </Space>
          </div>
          <label className='space-y-1'>
            <Text type='tertiary' size='small'>
              {t('事件保留天数')}
            </Text>
            <InputNumber
              value={draft.retention_days}
              min={1}
              max={365}
              style={{ width: '100%' }}
              onChange={(value) => onChange({ retention_days: value })}
            />
            <Text type='tertiary' size='small'>
              {t('到期事件和关联任务会由后台分批清理。')}
            </Text>
          </label>
        </div>
      </Card>

      <Card title={t('Guard 节点')} bodyStyle={{ padding: 16 }}>
        {(draft.endpoints || []).length === 0 ? (
          <Text type='tertiary'>{t('尚未配置 Guard 节点')}</Text>
        ) : (
          <div className='grid grid-cols-1 gap-4 xl:grid-cols-2'>
            {(draft.endpoints || []).map((endpoint, index) => (
              <div
                key={endpoint.id}
                className='rounded-lg border border-[var(--semi-color-border)] p-4'
              >
                <Text strong>{endpoint.name || endpoint.id}</Text>
                <div className='mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2'>
                  <label className='space-y-1'>
                    <Text type='tertiary' size='small'>
                      {t('超时时间（毫秒）')}
                    </Text>
                    <InputNumber
                      value={endpoint.timeout_ms}
                      min={100}
                      max={30000}
                      step={100}
                      style={{ width: '100%' }}
                      onChange={(value) =>
                        updateEndpointRuntime(index, { timeout_ms: value })
                      }
                    />
                  </label>
                  <label className='space-y-1'>
                    <Text type='tertiary' size='small'>
                      {t('单片字符数')}
                    </Text>
                    <InputNumber
                      value={endpoint.input_limit}
                      min={128}
                      max={100000}
                      step={128}
                      style={{ width: '100%' }}
                      onChange={(value) =>
                        updateEndpointRuntime(index, { input_limit: value })
                      }
                    />
                  </label>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title={t('Worker 与队列')} bodyStyle={{ padding: 16 }}>
        <div className='grid grid-cols-1 gap-4 md:grid-cols-2'>
          <label className='space-y-1'>
            <Text type='tertiary' size='small'>
              {t('Worker 数量')}
            </Text>
            <InputNumber
              value={draft.worker_count}
              min={1}
              max={32}
              style={{ width: '100%' }}
              onChange={(value) => onChange({ worker_count: value })}
            />
          </label>
          <label className='space-y-1'>
            <Text type='tertiary' size='small'>
              {t('队列容量')}
            </Text>
            <InputNumber
              value={draft.queue_capacity}
              min={1}
              max={100000}
              step={1024}
              style={{ width: '100%' }}
              onChange={(value) => onChange({ queue_capacity: value })}
            />
          </label>
        </div>
        <Text type='tertiary' size='small' className='mt-3 block'>
          {t('Redis 仅用于可选唤醒；数据库队列承担任务正确性。')}
        </Text>
      </Card>
    </div>
  );
};

export default PolicyTab;
