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
import {
  Activity01Icon,
  AlertCircleIcon,
  Clock01Icon,
  Database01Icon,
  ServerStack01Icon,
} from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useTranslation } from 'react-i18next'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Skeleton } from '@/components/ui/skeleton'
import {
  formatAuditInteger,
  formatAuditTime,
  SecurityAuditModeBadge,
} from './shared'
import type { SecurityAuditConfigDraft, SecurityAuditRuntime } from './types'

function StatCard({
  title,
  value,
  description,
  icon,
}: {
  title: string
  value: React.ReactNode
  description: string
  icon: typeof Activity01Icon
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center justify-between gap-3'>
          <span>{title}</span>
          <HugeiconsIcon icon={icon} strokeWidth={2} />
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>{value}</CardContent>
    </Card>
  )
}

export function SecurityAuditOverviewView({
  config,
  runtime,
  loading,
}: {
  config: SecurityAuditConfigDraft
  runtime?: SecurityAuditRuntime
  loading: boolean
}) {
  const { t } = useTranslation()

  if (loading && !runtime) {
    return (
      <div className='grid gap-4 md:grid-cols-2 xl:grid-cols-4'>
        {Array.from({ length: 4 }, (_, index) => (
          <Skeleton key={index} className='h-40 rounded-xl' />
        ))}
      </div>
    )
  }

  const queue = runtime?.queue
  const metrics = runtime?.metrics
  const utilization = queue?.capacity
    ? Math.min(100, Math.round((queue.active / queue.capacity) * 100))
    : 0
  const errorCount = (metrics?.unavailable ?? 0) + (metrics?.invalid ?? 0)
  const errorRate = metrics?.total
    ? `${((errorCount / metrics.total) * 100).toFixed(2)}%`
    : '0.00%'

  return (
    <div className='flex flex-col gap-4'>
      {!runtime?.crypto_ready && (
        <Alert>
          <HugeiconsIcon icon={AlertCircleIcon} strokeWidth={2} />
          <AlertTitle>
            {t('Encrypted prompt storage is unavailable')}
          </AlertTitle>
          <AlertDescription>
            {t(
              'Prompt Guard and Guard token storage require CRYPTO_SECRET. Built-in detections continue to work and save metadata without recoverable prompt text.'
            )}
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>{t('Built-in detections')}</CardTitle>
          <CardDescription>
            {t('These detections run without a configured Guard node.')}
          </CardDescription>
        </CardHeader>
        <CardContent className='flex flex-wrap gap-2'>
          <Badge
            variant={
              config.sensitive_word_audit_enabled ? 'default' : 'secondary'
            }
          >
            {t('Sensitive word events')}:{' '}
            {config.sensitive_word_audit_enabled ? t('Enabled') : t('Disabled')}
          </Badge>
          <Badge
            variant={config.upstream_policy_enabled ? 'default' : 'secondary'}
          >
            {t('Upstream policy events')}:{' '}
            {config.upstream_policy_enabled ? t('Enabled') : t('Disabled')}
          </Badge>
        </CardContent>
      </Card>

      <div className='grid gap-4 md:grid-cols-2 xl:grid-cols-4'>
        <StatCard
          title={t('Prompt Guard mode')}
          value={<SecurityAuditModeBadge mode={config.mode} t={t} />}
          description={t('Current optional Guard request gate behavior')}
          icon={Activity01Icon}
        />
        <StatCard
          title={t('Workers')}
          value={
            <div className='flex items-center gap-2'>
              <span className='text-2xl font-semibold tabular-nums'>
                {formatAuditInteger(
                  runtime?.worker_total ?? config.worker_count
                )}
              </span>
              <Badge
                variant={
                  runtime?.process_status === 'running'
                    ? 'default'
                    : 'secondary'
                }
              >
                {runtime?.process_status === 'running'
                  ? t('Running')
                  : t('Stopped')}
              </Badge>
            </div>
          }
          description={t('Background audit workers')}
          icon={ServerStack01Icon}
        />
        <StatCard
          title={t('Queue')}
          value={
            <div className='flex flex-col gap-2'>
              <span className='text-2xl font-semibold tabular-nums'>
                {formatAuditInteger(queue?.active)} /{' '}
                {formatAuditInteger(queue?.capacity ?? config.queue_capacity)}
              </span>
              <Progress value={utilization} aria-label={t('Queue usage')} />
            </div>
          }
          description={t('{{percent}}% queue utilization', {
            percent: utilization,
          })}
          icon={Database01Icon}
        />
        <StatCard
          title={t('Guard error rate')}
          value={
            <span className='text-2xl font-semibold tabular-nums'>
              {errorRate}
            </span>
          }
          description={t('{{count}} failed audit attempts', {
            count: formatAuditInteger(errorCount),
          })}
          icon={Clock01Icon}
        />
      </div>

      <div className='grid gap-4 xl:grid-cols-2'>
        <Card>
          <CardHeader>
            <CardTitle>{t('Queue status')}</CardTitle>
            <CardDescription>
              {t('Database-backed queue state and processing totals')}
            </CardDescription>
          </CardHeader>
          <CardContent className='grid gap-4 sm:grid-cols-3'>
            {[
              [t('Queued'), queue?.queued],
              [t('Processing'), queue?.processing],
              [t('Retrying'), queue?.retry],
              [t('Completed'), queue?.done],
              [t('Failed'), queue?.failed],
              [
                t('Oldest queued'),
                formatAuditTime(queue?.oldest_queued_at ?? 0),
              ],
            ].map(([label, value]) => (
              <div key={String(label)} className='flex flex-col gap-1'>
                <span className='text-muted-foreground text-xs'>{label}</span>
                <span className='font-medium tabular-nums'>
                  {typeof value === 'number'
                    ? formatAuditInteger(value)
                    : value}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t('Guard node health')}</CardTitle>
            <CardDescription>
              {t('Latest health status for configured Guard nodes')}
            </CardDescription>
          </CardHeader>
          <CardContent className='flex flex-col gap-3'>
            {(runtime?.endpoints ?? []).length === 0 ? (
              <p className='text-muted-foreground text-sm'>
                {t('No Guard health data is available yet.')}
              </p>
            ) : (
              runtime?.endpoints.map((endpoint) => (
                <div
                  key={endpoint.id}
                  className='flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3'
                >
                  <div className='min-w-0'>
                    <p className='truncate font-medium'>{endpoint.name}</p>
                    <p className='text-muted-foreground text-xs'>
                      {formatAuditTime(endpoint.checked_at)} ·{' '}
                      {t('{{latency}} ms', { latency: endpoint.latency_ms })}
                    </p>
                  </div>
                  <Badge variant={endpoint.healthy ? 'default' : 'destructive'}>
                    {endpoint.healthy ? t('Healthy') : t('Unavailable')}
                  </Badge>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
