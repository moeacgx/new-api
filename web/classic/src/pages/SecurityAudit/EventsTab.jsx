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

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Banner,
  Button,
  Card,
  Empty,
  Input,
  InputNumber,
  Modal,
  Pagination,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Toast,
  Typography,
} from '@douyinfe/semi-ui';
import { Eye, Filter, RefreshCw, Search, Trash2 } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { showError, timestamp2string } from '../../helpers';
import {
  batchDeleteSecurityAuditEvents,
  cleanSecurityAuditFilter,
  deleteSecurityAuditEvent,
  deleteSecurityAuditEventsByFilter,
  getSecurityAuditEvent,
  getSecurityAuditEvents,
  previewSecurityAuditDelete,
} from './api';
import { getDecisionColor, getRiskColor } from './constants';

const { Text } = Typography;

const EMPTY_FILTER = {
  keyword: '',
  source: '',
  stage: '',
  decision: '',
  risk_level: '',
  endpoint: '',
  user_id: undefined,
  token_id: undefined,
  group_id: undefined,
};

const getSourceLabel = (source, t) => {
  switch (source) {
    case 'sensitive_word':
      return t('屏蔽词');
    case 'upstream_policy':
      return t('上游安全策略');
    case 'prompt_guard':
      return t('Prompt Guard');
    default:
      return source || t('Prompt Guard');
  }
};

const getSourceColor = (source) => {
  switch (source) {
    case 'sensitive_word':
      return 'amber';
    case 'upstream_policy':
      return 'violet';
    default:
      return 'blue';
  }
};

const getStageLabel = (stage, t) => {
  switch (stage) {
    case 'request':
      return t('请求');
    case 'response':
      return t('返回');
    case 'response_stream':
      return t('流式返回');
    case 'realtime_request':
      return t('Realtime 请求');
    case 'realtime_response':
      return t('Realtime 返回');
    case 'task_response':
      return t('任务返回');
    case 'http':
      return t('HTTP 请求');
    case 'realtime':
      return t('Realtime 请求');
    case 'async_worker':
      return t('异步 Worker');
    default:
      return stage || '-';
  }
};

const EventsTab = ({ endpoints, runSensitive }) => {
  const { t } = useTranslation();
  const [filter, setFilter] = useState(EMPTY_FILTER);
  const [appliedFilter, setAppliedFilter] = useState(EMPTY_FILTER);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [selectedRowKeys, setSelectedRowKeys] = useState([]);
  const [detail, setDetail] = useState(null);
  const [detailVisible, setDetailVisible] = useState(false);

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const result = await getSecurityAuditEvents(
        appliedFilter,
        page,
        pageSize,
      );
      setEvents(result?.items || []);
      setTotal(Number(result?.total || 0));
      setSelectedRowKeys([]);
    } catch (error) {
      showError(error?.message || t('审计事件加载失败'));
    } finally {
      setLoading(false);
    }
  }, [appliedFilter, page, pageSize, refreshKey, t]);

  useEffect(() => {
    void loadEvents();
  }, [loadEvents]);

  const refresh = () => setRefreshKey((value) => value + 1);

  const applyFilter = () => {
    setPage(1);
    setAppliedFilter({ ...filter });
  };

  const resetFilter = () => {
    setFilter({ ...EMPTY_FILTER });
    setAppliedFilter({ ...EMPTY_FILTER });
    setPage(1);
  };

  const openDetail = (event) => {
    void runSensitive(
      () => getSecurityAuditEvent(event.id),
      (result) => {
        setDetail(result);
        setDetailVisible(true);
      },
      {
        title: t('查看审计事件详情'),
        description: t('审计详情可能包含临时解密的提示词，请验证身份后查看。'),
      },
    ).catch((error) => showError(error?.message || t('详情加载失败')));
  };

  const removeOne = (event) => {
    Modal.confirm({
      title: t('删除审计事件'),
      content: t('该操作会同时清理关联的已完成任务，且无法撤销。'),
      okType: 'danger',
      onOk: () =>
        runSensitive(
          () => deleteSecurityAuditEvent(event.id),
          (result) => {
            Toast.success({
              content: t('已删除 {{count}} 条审计事件', {
                count: result?.deleted_events || 0,
              }),
            });
            refresh();
          },
          {
            title: t('验证删除操作'),
            description: t('删除安全审计事件需要再次验证身份。'),
          },
        ).catch((error) => showError(error?.message || t('删除失败'))),
    });
  };

  const batchRemove = () => {
    if (selectedRowKeys.length === 0) return;
    const ids = selectedRowKeys.map(Number).filter((id) => id > 0);
    Modal.confirm({
      title: t('批量删除审计事件'),
      content: t('确定删除选中的 {{count}} 条审计事件吗？', {
        count: ids.length,
      }),
      okType: 'danger',
      onOk: () =>
        runSensitive(
          () => batchDeleteSecurityAuditEvents(ids),
          (result) => {
            Toast.success({
              content: t('已删除 {{count}} 条审计事件', {
                count: result?.deleted_events || 0,
              }),
            });
            refresh();
          },
          {
            title: t('验证批量删除'),
            description: t('批量删除安全审计事件需要再次验证身份。'),
          },
        ).catch((error) => showError(error?.message || t('删除失败'))),
    });
  };

  const confirmFilteredDelete = (preview, filterSnapshot) => {
    Modal.confirm({
      title: t('按筛选删除审计事件'),
      content: (
        <div className='space-y-2'>
          <div>
            {t('预览匹配 {{count}} 条事件，仅删除预览时已存在的数据。', {
              count: preview?.matched_count || 0,
            })}
          </div>
          <Text type='tertiary' size='small'>
            {t('确认令牌五分钟内有效；事件变化后必须重新预览。')}
          </Text>
        </div>
      ),
      okType: 'danger',
      okText: t('确认删除'),
      onOk: () =>
        runSensitive(
          () => deleteSecurityAuditEventsByFilter(filterSnapshot, preview),
          (result) => {
            Toast.success({
              content: t('已删除 {{count}} 条审计事件', {
                count: result?.deleted_events || 0,
              }),
            });
            refresh();
          },
          {
            title: t('验证按筛选删除'),
            description: t('这是不可撤销的批量操作，请再次验证身份。'),
          },
        ).catch((error) => showError(error?.message || t('删除失败'))),
    });
  };

  const previewFilteredDelete = () => {
    const filterSnapshot = cleanSecurityAuditFilter(appliedFilter);
    if (Object.keys(filterSnapshot).length === 0) {
      Toast.warning({ content: t('请至少设置一个筛选条件') });
      return;
    }
    void runSensitive(
      () => previewSecurityAuditDelete(filterSnapshot),
      (preview) => confirmFilteredDelete(preview, filterSnapshot),
      {
        title: t('验证删除预览'),
        description: t('按筛选删除前需要验证身份并生成一次性预览。'),
      },
    ).catch((error) => showError(error?.message || t('删除预览失败')));
  };

  const columns = useMemo(
    () => [
      {
        title: t('时间'),
        dataIndex: 'created_at',
        width: 170,
        render: (value) => (value ? timestamp2string(value) : '-'),
      },
      {
        title: t('判定'),
        dataIndex: 'decision',
        width: 100,
        render: (value) => (
          <Tag color={getDecisionColor(value)}>{value || '-'}</Tag>
        ),
      },
      {
        title: t('风险等级'),
        dataIndex: 'risk_level',
        width: 110,
        render: (value) => (
          <Tag color={getRiskColor(value)}>{value || '-'}</Tag>
        ),
      },
      {
        title: t('审计来源'),
        dataIndex: 'source',
        width: 160,
        render: (value, record) => (
          <div className='space-y-1'>
            <Tag color={getSourceColor(value)}>{getSourceLabel(value, t)}</Tag>
            <Text type='tertiary' size='small' className='block'>
              {getStageLabel(record.stage, t)}
            </Text>
          </div>
        ),
      },
      {
        title: t('脱敏预览'),
        dataIndex: 'redacted_preview',
        width: 360,
        render: (value, record) => (
          <Text ellipsis={{ showTooltip: true, rows: 2 }}>
            {record.prompt_available === false
              ? t('未保存提示词正文')
              : value || '-'}
          </Text>
        ),
      },
      {
        title: t('用户'),
        dataIndex: 'username',
        width: 140,
        render: (value, record) => value || `#${record.user_id || '-'}`,
      },
      {
        title: t('模型'),
        dataIndex: 'model',
        width: 180,
        render: (value) => (
          <Text ellipsis={{ showTooltip: true }}>{value || '-'}</Text>
        ),
      },
      {
        title: t('Guard 节点'),
        dataIndex: 'guard_endpoint_id',
        width: 140,
        render: (value) => value || '-',
      },
      {
        title: t('延迟'),
        dataIndex: 'latency_ms',
        width: 90,
        render: (value) => `${value || 0} ms`,
      },
      {
        title: t('操作'),
        dataIndex: 'operate',
        fixed: 'right',
        width: 130,
        render: (_, record) => (
          <Space spacing={4}>
            <Button
              size='small'
              theme='borderless'
              icon={<Eye size={15} />}
              aria-label={t('查看详情')}
              onClick={() => openDetail(record)}
            />
            <Button
              size='small'
              theme='borderless'
              type='danger'
              icon={<Trash2 size={15} />}
              aria-label={t('删除')}
              onClick={() => removeOne(record)}
            />
          </Space>
        ),
      },
    ],
    [t],
  );

  return (
    <div className='space-y-4'>
      <Card bodyStyle={{ padding: 16 }}>
        <div className='grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4'>
          <Input
            prefix={<Search size={15} />}
            value={filter.keyword}
            placeholder={t('搜索脱敏预览')}
            onChange={(value) =>
              setFilter((current) => ({ ...current, keyword: value }))
            }
            onEnterPress={applyFilter}
          />
          <Select
            value={filter.source || undefined}
            placeholder={t('审计来源')}
            showClear
            onChange={(value) =>
              setFilter((current) => ({ ...current, source: value || '' }))
            }
          >
            <Select.Option value='prompt_guard'>
              {t('Prompt Guard')}
            </Select.Option>
            <Select.Option value='sensitive_word'>{t('屏蔽词')}</Select.Option>
            <Select.Option value='upstream_policy'>
              {t('上游安全策略')}
            </Select.Option>
          </Select>
          <Select
            value={filter.stage || undefined}
            placeholder={t('处理阶段')}
            showClear
            onChange={(value) =>
              setFilter((current) => ({ ...current, stage: value || '' }))
            }
          >
            {[
              'request',
              'response',
              'response_stream',
              'realtime_request',
              'realtime_response',
              'task_response',
              'http',
              'realtime',
              'async_worker',
            ].map((value) => (
              <Select.Option key={value} value={value}>
                {getStageLabel(value, t)}
              </Select.Option>
            ))}
          </Select>
          <Select
            value={filter.decision || undefined}
            placeholder={t('判定结果')}
            showClear
            onChange={(value) =>
              setFilter((current) => ({ ...current, decision: value || '' }))
            }
          >
            <Select.Option value='pass'>{t('允许')}</Select.Option>
            <Select.Option value='flag'>{t('标记')}</Select.Option>
            <Select.Option value='critical'>{t('阻断')}</Select.Option>
            <Select.Option value='error'>{t('错误')}</Select.Option>
          </Select>
          <Select
            value={filter.risk_level || undefined}
            placeholder={t('风险等级')}
            showClear
            onChange={(value) =>
              setFilter((current) => ({ ...current, risk_level: value || '' }))
            }
          >
            {['safe', 'low', 'medium', 'high', 'critical'].map((value) => (
              <Select.Option key={value} value={value}>
                {value}
              </Select.Option>
            ))}
          </Select>
          <Select
            value={filter.endpoint || undefined}
            placeholder={t('Guard 节点')}
            showClear
            filter
            onChange={(value) =>
              setFilter((current) => ({ ...current, endpoint: value || '' }))
            }
          >
            {(endpoints || []).map((endpoint) => (
              <Select.Option key={endpoint.id} value={endpoint.id}>
                {endpoint.name || endpoint.id}
              </Select.Option>
            ))}
          </Select>
          <InputNumber
            value={filter.user_id}
            min={1}
            placeholder={t('用户 ID')}
            style={{ width: '100%' }}
            onChange={(value) =>
              setFilter((current) => ({ ...current, user_id: value }))
            }
          />
          <InputNumber
            value={filter.token_id}
            min={1}
            placeholder={t('令牌 ID')}
            style={{ width: '100%' }}
            onChange={(value) =>
              setFilter((current) => ({ ...current, token_id: value }))
            }
          />
          <InputNumber
            value={filter.group_id}
            min={1}
            placeholder={t('分组 ID')}
            style={{ width: '100%' }}
            onChange={(value) =>
              setFilter((current) => ({ ...current, group_id: value }))
            }
          />
          <Space wrap>
            <Button
              type='primary'
              icon={<Filter size={15} />}
              onClick={applyFilter}
            >
              {t('筛选')}
            </Button>
            <Button onClick={resetFilter}>{t('重置')}</Button>
          </Space>
        </div>
      </Card>

      <Card
        title={t('审计事件')}
        headerExtraContent={
          <Space wrap>
            <Button
              type='danger'
              theme='outline'
              icon={<Trash2 size={15} />}
              disabled={selectedRowKeys.length === 0}
              onClick={batchRemove}
            >
              {t('删除选中')}
            </Button>
            <Button
              type='danger'
              theme='outline'
              onClick={previewFilteredDelete}
            >
              {t('按筛选删除')}
            </Button>
            <Button
              icon={<RefreshCw size={15} />}
              loading={loading}
              onClick={refresh}
            >
              {t('刷新')}
            </Button>
          </Space>
        }
        bodyStyle={{ padding: 0 }}
      >
        <Spin spinning={loading}>
          <Table
            rowKey='id'
            columns={columns}
            dataSource={events}
            pagination={false}
            scroll={{ x: 1610 }}
            rowSelection={{
              selectedRowKeys,
              onChange: (keys) => setSelectedRowKeys(keys),
            }}
            empty={<Empty description={t('暂无审计事件')} />}
          />
          <div className='flex flex-col gap-3 border-t border-[var(--semi-color-border)] p-4 sm:flex-row sm:items-center sm:justify-between'>
            <Text type='tertiary' size='small'>
              {t('共 {{count}} 条', { count: total })}
            </Text>
            <Pagination
              currentPage={page}
              pageSize={pageSize}
              total={total}
              showSizeChanger
              pageSizeOpts={[20, 50, 100]}
              onPageChange={setPage}
              onPageSizeChange={(size) => {
                setPageSize(size);
                setPage(1);
              }}
            />
          </div>
        </Spin>
      </Card>

      <Modal
        title={t('审计事件详情')}
        visible={detailVisible}
        onCancel={() => {
          setDetailVisible(false);
          setDetail(null);
        }}
        footer={
          <Button
            type='primary'
            onClick={() => {
              setDetailVisible(false);
              setDetail(null);
            }}
          >
            {t('关闭')}
          </Button>
        }
        width={820}
        style={{ maxWidth: '94vw' }}
      >
        {detail ? (
          <div className='space-y-4'>
            <div className='grid grid-cols-1 gap-3 sm:grid-cols-2'>
              {[
                ['请求 ID', detail.request_id || '-'],
                ['提示词哈希', detail.prompt_hash || '-'],
                ['用户', detail.username || `#${detail.user_id || '-'}`],
                ['模型', detail.model || '-'],
                ['审计来源', getSourceLabel(detail.source, t)],
                ['处理阶段', getStageLabel(detail.stage, t)],
                ['判定', detail.decision || '-'],
                ['风险等级', detail.risk_level || '-'],
                ['风险分数', detail.risk_score ?? '-'],
                ['字符数', detail.prompt_length || 0],
                ['分片数', detail.chunk_total || 0],
              ].map(([label, value]) => (
                <div
                  key={label}
                  className='rounded-lg bg-[var(--semi-color-fill-0)] p-3'
                >
                  <Text type='tertiary' size='small'>
                    {t(label)}
                  </Text>
                  <div className='mt-1 break-all'>{value}</div>
                </div>
              ))}
            </div>
            <div>
              <Text strong>{t('风险分类')}</Text>
              <div className='mt-2 flex flex-wrap gap-2'>
                {(detail.categories || []).length > 0 ? (
                  detail.categories.map((category) => (
                    <Tag key={category} color='orange'>
                      {category}
                    </Tag>
                  ))
                ) : (
                  <Text type='tertiary'>-</Text>
                )}
              </div>
            </div>
            {detail.prompt_available && detail.full_prompt ? (
              <div>
                <Text strong>{t('完整提示词')}</Text>
                <pre className='mt-2 max-h-[45vh] overflow-auto whitespace-pre-wrap break-words rounded-xl border border-[var(--semi-color-border)] bg-[var(--semi-color-fill-0)] p-4 text-sm'>
                  {detail.full_prompt}
                </pre>
                {detail.prompt_truncated ? (
                  <Text type='warning' size='small' className='mt-2 block'>
                    {t('该提示词已按持久化上限截断。')}
                  </Text>
                ) : null}
              </div>
            ) : (
              <Banner
                type='info'
                closeIcon={null}
                description={t(
                  '未保存提示词正文。加密存储不可用时，事件仅保留不可逆哈希、长度、来源和技术元数据。',
                )}
              />
            )}
          </div>
        ) : null}
      </Modal>
    </div>
  );
};

export default EventsTab;
