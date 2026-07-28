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
import { useEffect, useMemo, useState } from 'react'
import axios from 'axios'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Activity01Icon,
  Audit01Icon,
  FilterIcon,
  FloppyDiskIcon,
  RefreshIcon,
  SecurityCheckIcon,
  ServerStack01Icon,
} from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { Spinner } from '@/components/ui/spinner'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SectionPageLayout } from '@/components/layout'
import {
  SecureVerificationDialog,
  useSecureVerification,
} from '@/features/auth/secure-verification'
import {
  configToDraft,
  draftToConfigUpdate,
  getSecurityAuditConfig,
  getSecurityAuditGroups,
  getSecurityAuditRuntime,
  updateSecurityAuditConfig,
} from './api'
import { SecurityAuditBuiltinPolicyView } from './builtin-policy-view'
import { SecurityAuditEndpointsView } from './endpoints-view'
import { SecurityAuditEventsView } from './events-view'
import { SecurityAuditOverviewView } from './overview-view'
import { SecurityAuditPolicyView } from './policy-view'
import type {
  SecurityAuditBuiltinPolicy,
  SecurityAuditConfigDraft,
} from './types'

type SecurityAuditTab =
  | 'overview'
  | 'events'
  | 'builtin-policy'
  | 'endpoints'
  | 'policy'

function comparableGuardDraft(draft: SecurityAuditConfigDraft) {
  return {
    mode: draft.mode,
    enabled: draft.enabled,
    blocking_enabled: draft.blocking_enabled,
    store_pass_events: draft.store_pass_events,
    strategy: draft.strategy,
    worker_count: draft.worker_count,
    queue_capacity: draft.queue_capacity,
    retention_days: draft.retention_days,
    scanners: draft.scanners,
    all_groups: draft.all_groups,
    group_ids: draft.group_ids,
    endpoints: draft.endpoints,
  }
}

function validateDraft(
  draft: SecurityAuditConfigDraft,
  t: (key: string) => string,
  cryptoReady?: boolean
) {
  if (draft.scanners.length === 0)
    return t('Select at least one risk category.')
  if (!draft.all_groups && draft.group_ids.length === 0) {
    return t('Select at least one user group or enable all groups.')
  }
  if (draft.worker_count < 1 || draft.worker_count > 32) {
    return t('Worker count must be between 1 and 32.')
  }
  if (draft.queue_capacity < 1 || draft.queue_capacity > 100000) {
    return t('Queue capacity must be between 1 and 100000.')
  }
  if (draft.retention_days < 1 || draft.retention_days > 365) {
    return t('Retention days must be between 1 and 365.')
  }
  const endpointIds = new Set<string>()
  for (const endpoint of draft.endpoints) {
    if (
      !endpoint.id.trim() ||
      !endpoint.name.trim() ||
      !endpoint.base_url.trim() ||
      !endpoint.model.trim()
    ) {
      return t('Every Guard node requires an ID, name, Base URL, and model.')
    }
    const endpointId = endpoint.id.trim()
    if (endpointIds.has(endpointId)) {
      return `${t('Duplicate')}: ${t('Node ID')}`
    }
    endpointIds.add(endpointId)
    if (endpoint.timeout_ms < 100 || endpoint.timeout_ms > 30000) {
      return t('Guard node timeout must be between 100 and 30000 ms.')
    }
    if (endpoint.input_limit < 128 || endpoint.input_limit > 100000) {
      return t(
        'Guard node chunk size must be between 128 and 100000 characters.'
      )
    }
    if (endpoint.token_action === 'replace' && !endpoint.token.trim()) {
      return t('Enter the replacement token for every node marked Replace.')
    }
  }
  if (
    draft.mode !== 'off' &&
    !draft.endpoints.some((endpoint) => endpoint.enabled)
  ) {
    return t('Enable at least one Guard node before turning on security audit.')
  }
  if (draft.mode !== 'off' && cryptoReady === false) {
    return t(
      'Configure a stable CRYPTO_SECRET before enabling audit or saving Guard tokens.'
    )
  }
  return null
}

export function SecurityAudit() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<SecurityAuditTab>('overview')
  const [draft, setDraft] = useState<SecurityAuditConfigDraft | null>(null)
  const [saving, setSaving] = useState(false)

  const configQuery = useQuery({
    queryKey: ['security-audit', 'config'],
    queryFn: getSecurityAuditConfig,
    staleTime: 15_000,
  })
  const runtimeQuery = useQuery({
    queryKey: ['security-audit', 'runtime'],
    queryFn: getSecurityAuditRuntime,
    refetchInterval: 10_000,
  })
  const groupsQuery = useQuery({
    queryKey: ['security-audit', 'groups'],
    queryFn: getSecurityAuditGroups,
    staleTime: 60_000,
  })

  useEffect(() => {
    if (configQuery.data) setDraft(configToDraft(configQuery.data))
  }, [configQuery.data])

  const verification = useSecureVerification()
  const baseline = useMemo(
    () => (configQuery.data ? configToDraft(configQuery.data) : null),
    [configQuery.data]
  )
  const dirty = Boolean(
    draft &&
    baseline &&
    JSON.stringify(comparableGuardDraft(draft)) !==
      JSON.stringify(comparableGuardDraft(baseline))
  )

  const updateDraft = (patch: Partial<SecurityAuditConfigDraft>) => {
    setDraft((current) => (current ? { ...current, ...patch } : current))
  }

  const save = async () => {
    if (!draft) return
    const validationError = validateDraft(
      draft,
      t,
      runtimeQuery.data?.crypto_ready
    )
    if (validationError) {
      toast.error(validationError)
      return
    }

    await verification.withVerification(
      async () => {
        setSaving(true)
        try {
          const updated = await updateSecurityAuditConfig(
            draftToConfigUpdate(draft)
          )
          queryClient.setQueryData(['security-audit', 'config'], updated)
          setDraft(configToDraft(updated))
          await queryClient.invalidateQueries({
            queryKey: ['security-audit', 'runtime'],
          })
          toast.success(t('Security audit configuration saved'))
          return updated
        } catch (error) {
          if (axios.isAxiosError(error) && error.response?.status === 409) {
            await configQuery.refetch()
            toast.error(
              t(
                'The configuration changed on the server. Latest values were reloaded; review and save again.'
              )
            )
          }
          throw error
        } finally {
          setSaving(false)
        }
      },
      {
        title: t('Verify security audit configuration change'),
        description: t(
          'This operation changes the request security boundary and Guard credentials.'
        ),
      }
    )
  }

  const refresh = async () => {
    await Promise.all([
      configQuery.refetch(),
      runtimeQuery.refetch(),
      groupsQuery.refetch(),
      queryClient.invalidateQueries({
        queryKey: ['security-audit', 'builtin-policy'],
      }),
    ])
  }

  const handleBuiltinPolicySaved = (policy: SecurityAuditBuiltinPolicy) => {
    setDraft((current) =>
      current
        ? {
            ...current,
            config_version: policy.config_version,
            updated_at: policy.updated_at,
            updated_by: policy.updated_by,
            upstream_policy_enabled: policy.upstream_policy_enabled,
            sensitive_word_audit_enabled: policy.sensitive_word_audit_enabled,
          }
        : current
    )
  }

  const tabs: Array<{
    value: SecurityAuditTab
    label: string
    icon: typeof Activity01Icon
  }> = [
    { value: 'overview', label: t('Overview'), icon: Activity01Icon },
    { value: 'events', label: t('Audit events'), icon: Audit01Icon },
    {
      value: 'builtin-policy',
      label: t('Built-in policy'),
      icon: FilterIcon,
    },
    { value: 'endpoints', label: t('Guard nodes'), icon: ServerStack01Icon },
    { value: 'policy', label: t('Audit policy'), icon: SecurityCheckIcon },
  ]

  return (
    <>
      <SectionPageLayout>
        <SectionPageLayout.Title>{t('Security Audit')}</SectionPageLayout.Title>
        <SectionPageLayout.Actions>
          <Button
            variant='outline'
            size='sm'
            onClick={() => void refresh()}
            disabled={
              configQuery.isFetching ||
              runtimeQuery.isFetching ||
              groupsQuery.isFetching
            }
          >
            {configQuery.isFetching || runtimeQuery.isFetching ? (
              <Spinner data-icon='inline-start' />
            ) : (
              <HugeiconsIcon
                icon={RefreshIcon}
                strokeWidth={2}
                data-icon='inline-start'
              />
            )}
            {t('Refresh')}
          </Button>
          {tab !== 'builtin-policy' ? (
            <Button
              size='sm'
              onClick={() => void save()}
              disabled={!dirty || saving || !draft}
            >
              {saving ? (
                <Spinner data-icon='inline-start' />
              ) : (
                <HugeiconsIcon
                  icon={FloppyDiskIcon}
                  strokeWidth={2}
                  data-icon='inline-start'
                />
              )}
              {t('Save changes')}
            </Button>
          ) : null}
        </SectionPageLayout.Actions>
        <SectionPageLayout.Content>
          {configQuery.isError ? (
            <Alert variant='destructive'>
              <AlertTitle>{t('Failed to load security audit')}</AlertTitle>
              <AlertDescription className='flex flex-wrap items-center gap-2'>
                <span>{t('Check your Root permissions and try again.')}</span>
                <Button
                  variant='outline'
                  size='sm'
                  onClick={() => void configQuery.refetch()}
                >
                  {t('Retry')}
                </Button>
              </AlertDescription>
            </Alert>
          ) : !draft ? (
            <div className='flex flex-col gap-4'>
              <Skeleton className='h-10 w-full max-w-xl' />
              <Skeleton className='h-80 w-full rounded-xl' />
            </div>
          ) : (
            <Tabs
              value={tab}
              onValueChange={(value) => setTab(value as SecurityAuditTab)}
              className='min-w-0'
            >
              <div className='flex min-w-0 flex-col gap-4'>
                <div className='-mx-1 max-w-full overflow-x-auto px-1 pb-1'>
                  <TabsList variant='line' aria-label={t('Security Audit')}>
                    {tabs.map((item) => (
                      <TabsTrigger key={item.value} value={item.value}>
                        <HugeiconsIcon
                          icon={item.icon}
                          strokeWidth={2}
                          data-icon='inline-start'
                        />
                        {item.label}
                      </TabsTrigger>
                    ))}
                  </TabsList>
                </div>
                <TabsContent value='overview'>
                  <SecurityAuditOverviewView
                    config={draft}
                    runtime={runtimeQuery.data}
                    loading={runtimeQuery.isLoading}
                  />
                </TabsContent>
                <TabsContent value='events'>
                  <SecurityAuditEventsView
                    endpoints={draft.endpoints}
                    runSensitive={verification.withVerification}
                  />
                </TabsContent>
                <TabsContent value='builtin-policy'>
                  <SecurityAuditBuiltinPolicyView
                    runSensitive={verification.withVerification}
                    onSaved={handleBuiltinPolicySaved}
                  />
                </TabsContent>
                <TabsContent value='endpoints'>
                  <SecurityAuditEndpointsView
                    endpoints={draft.endpoints}
                    onChange={(endpoints) => updateDraft({ endpoints })}
                    runSensitive={verification.withVerification}
                  />
                </TabsContent>
                <TabsContent value='policy'>
                  <SecurityAuditPolicyView
                    draft={draft}
                    groups={groupsQuery.data ?? []}
                    groupsLoading={groupsQuery.isLoading}
                    onChange={updateDraft}
                  />
                </TabsContent>
              </div>
            </Tabs>
          )}
        </SectionPageLayout.Content>
      </SectionPageLayout>

      <SecureVerificationDialog
        open={verification.open}
        onOpenChange={(open) => {
          if (!open) verification.cancel()
        }}
        methods={verification.methods}
        state={verification.state}
        onVerify={async (method, code) => {
          await verification.executeVerification(method, code)
        }}
        onCancel={verification.cancel}
        onCodeChange={verification.setCode}
        onMethodChange={verification.switchMethod}
      />
    </>
  )
}
