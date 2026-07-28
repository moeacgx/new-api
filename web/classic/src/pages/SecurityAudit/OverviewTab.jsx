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
  Progress,
  Spin,
  Tag,
  Typography,
} from '@douyinfe/semi-ui';
import {
  Activity,
  Clock3,
  Database,
  KeyRound,
  Server,
  ShieldCheck,
  TriangleAlert,
  UsersRound,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { timestamp2string } from '../../helpers';
import { getModeLabel } from './constants';

const { Text } = Typography;

const valueOf = (object, lower, upper, fallback = 0) =>
  object?.[lower] ?? object?.[upper] ?? fallback;

const METRIC_ICON_CLASS = {
  blue: 'bg-blue-50 text-blue-600',
  green: 'bg-green-50 text-green-600',
  violet: 'bg-violet-50 text-violet-600',
  orange: 'bg-orange-50 text-orange-600',
};

const MetricCard = ({ icon, label, value, hint, color = 'blue' }) => (
  <Card bodyStyle={{ padding: 16 }}>
    <div className='flex items-start justify-between gap-3'>
      <div className='min-w-0'>
        <Text type='tertiary' size='small'>
          {label}
        </Text>
        <div className='mt-2 text-2xl font-semibold'>{value}</div>
        {hint ? (
          <Text type='tertiary' size='small' className='mt-1 block'>
            {hint}
          </Text>
        ) : null}
      </div>
      <div
        className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${METRIC_ICON_CLASS[color] || METRIC_ICON_CLASS.blue}`}
      >
        {icon}
      </div>
    </div>
  </Card>
);

const OverviewTab = ({ config, runtime, loading }) => {
  const { t } = useTranslation();
  const queue = runtime?.queue || {};
  const metrics = runtime?.metrics || {};
  const active = Number(valueOf(queue, 'active', 'Active'));
  const capacity = Number(valueOf(queue, 'capacity', 'Capacity'));
  const total = Number(metrics.total || 0);
  const errors =
    Number(metrics.unavailable || 0) + Number(metrics.invalid || 0);
  const errorRate = total > 0 ? (errors / total) * 100 : 0;
  const capacityRate =
    capacity > 0 ? Math.min(100, (active / capacity) * 100) : 0;
  const endpointHealthById = new Map(
    Array.isArray(runtime?.endpoints)
      ? runtime.endpoints.map((endpoint) => [endpoint.id, endpoint])
      : Object.entries(runtime?.endpoints || {}).map(([id, endpoint]) => [
          id,
          { id, ...endpoint },
        ]),
  );

  return (
    <Spin spinning={loading}>
      <div className='space-y-4'>
        {!runtime?.crypto_ready && config.mode !== 'off' ? (
          <Banner
            type='danger'
            icon={<TriangleAlert size={18} />}
            description={t(
              'CRYPTO_SECRET 未就绪，安全审计不能可靠保存提示词或节点令牌。',
            )}
          />
        ) : null}

        <div className='grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4'>
          <MetricCard
            icon={<ShieldCheck size={20} />}
            label={t('Guard 模式')}
            value={getModeLabel(runtime?.effective_mode || config.mode, t)}
            hint={`${t('配置版本')} ${runtime?.config_version || config.config_version}`}
            color='blue'
          />
          <MetricCard
            icon={<UsersRound size={20} />}
            label={t('Worker 状态')}
            value={`${runtime?.worker_active || 0} / ${runtime?.worker_total || config.worker_count}`}
            hint={
              runtime?.process_status === 'running' ? t('运行中') : t('已停止')
            }
            color='green'
          />
          <MetricCard
            icon={<Database size={20} />}
            label={t('队列占用')}
            value={`${active} / ${capacity}`}
            hint={`${t('排队')} ${valueOf(queue, 'queued', 'Queued')} · ${t('重试')} ${valueOf(queue, 'retry', 'Retry')}`}
            color='violet'
          />
          <MetricCard
            icon={<Clock3 size={20} />}
            label={t('队列延迟')}
            value={`${runtime?.queue_delay_ms || 0} ms`}
            hint={
              runtime?.last_processed_at
                ? `${t('最近处理')} ${timestamp2string(runtime.last_processed_at)}`
                : t('暂无处理记录')
            }
            color='orange'
          />
        </div>

        <Card title={t('内置安全策略')} bodyStyle={{ padding: 16 }}>
          <div className='flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between'>
            <Text type='tertiary' size='small'>
              {t('无需配置 Guard 节点，内置检测也可以独立运行。')}
            </Text>
            <div className='flex flex-wrap gap-2'>
              <Tag
                color={config.sensitive_word_audit_enabled ? 'green' : 'grey'}
              >
                {t('屏蔽词事件')} ·
                {config.sensitive_word_audit_enabled
                  ? t('已启用')
                  : t('已禁用')}
              </Tag>
              <Tag color={config.upstream_policy_enabled ? 'green' : 'grey'}>
                {t('上游安全策略')} ·
                {config.upstream_policy_enabled ? t('已启用') : t('已禁用')}
              </Tag>
            </div>
          </div>
        </Card>

        <div className='grid grid-cols-1 gap-3 lg:grid-cols-2'>
          <Card title={t('队列容量')} bodyStyle={{ padding: 16 }}>
            <Progress
              percent={capacityRate}
              showInfo
              format={() => `${active} / ${capacity}`}
              stroke='var(--semi-color-primary)'
            />
            <div className='mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4'>
              {[
                ['排队', valueOf(queue, 'queued', 'Queued')],
                ['处理中', valueOf(queue, 'processing', 'Processing')],
                ['已完成', valueOf(queue, 'done', 'Done')],
                ['失败', valueOf(queue, 'failed', 'Failed')],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className='rounded-lg bg-[var(--semi-color-fill-0)] p-3'
                >
                  <Text type='tertiary' size='small'>
                    {t(label)}
                  </Text>
                  <div className='mt-1 text-lg font-semibold'>{value}</div>
                </div>
              ))}
            </div>
          </Card>

          <Card title={t('运行指标')} bodyStyle={{ padding: 16 }}>
            <div className='flex items-center justify-between gap-4'>
              <div>
                <Text type='tertiary' size='small'>
                  {t('错误率')}
                </Text>
                <div className='mt-1 text-2xl font-semibold'>
                  {errorRate.toFixed(2)}%
                </div>
              </div>
              <Activity size={28} color='var(--semi-color-primary)' />
            </div>
            <div className='mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4'>
              {[
                ['允许', metrics.allowed || 0],
                ['标记', metrics.flagged || 0],
                ['阻断', metrics.blocked || 0],
                ['丢弃', metrics.dropped || 0],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className='rounded-lg bg-[var(--semi-color-fill-0)] p-3'
                >
                  <Text type='tertiary' size='small'>
                    {t(label)}
                  </Text>
                  <div className='mt-1 text-lg font-semibold'>{value}</div>
                </div>
              ))}
            </div>
            {runtime?.last_error_code ? (
              <Text type='danger' size='small' className='mt-3 block'>
                {t('最近错误')}：{runtime.last_error_code}
              </Text>
            ) : null}
          </Card>
        </div>

        <Card title={t('Guard 节点健康度')} bodyStyle={{ padding: 16 }}>
          {config.endpoints.length === 0 ? (
            <div className='flex min-h-32 flex-col items-center justify-center text-center'>
              <Server size={30} color='var(--semi-color-text-2)' />
              <Text type='tertiary' className='mt-2'>
                {t('尚未配置 Guard 节点')}
              </Text>
            </div>
          ) : (
            <div className='grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3'>
              {config.endpoints.map((endpoint) => {
                const health = endpointHealthById.get(endpoint.id);
                const isHealthy = health?.healthy ?? health?.ok;
                const hasProbeResult =
                  health &&
                  (health.status
                    ? health.status !== 'unprobed'
                    : typeof isHealthy === 'boolean');
                return (
                  <div
                    key={endpoint.id}
                    className='rounded-xl border border-[var(--semi-color-border)] p-4'
                  >
                    <div className='flex items-center justify-between gap-3'>
                      <div className='min-w-0'>
                        <Text strong ellipsis={{ showTooltip: true }}>
                          {endpoint.name || endpoint.id}
                        </Text>
                        <Text
                          type='tertiary'
                          size='small'
                          className='mt-1 block'
                        >
                          {endpoint.model}
                        </Text>
                      </div>
                      <Tag
                        color={
                          !endpoint.enabled
                            ? 'grey'
                            : isHealthy
                              ? 'green'
                              : hasProbeResult
                                ? 'red'
                                : 'light-blue'
                        }
                      >
                        {!endpoint.enabled
                          ? t('已停用')
                          : isHealthy
                            ? t('健康')
                            : hasProbeResult
                              ? t('异常')
                              : t('未探测')}
                      </Tag>
                    </div>
                    <div className='mt-3 flex items-center justify-between'>
                      <Text type='tertiary' size='small'>
                        {health?.latency_ms != null
                          ? `${health.latency_ms} ms`
                          : '-'}
                      </Text>
                      <div className='flex items-center gap-1'>
                        <KeyRound size={14} color='var(--semi-color-text-2)' />
                        <Text type='tertiary' size='small'>
                          {endpoint.has_token ? t('令牌已配置') : t('令牌缺失')}
                        </Text>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </Card>
      </div>
    </Spin>
  );
};

export default OverviewTab;
