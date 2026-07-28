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
import { useEffect, useState } from 'react'
import axios from 'axios'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
} from '@/components/ui/field'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import {
  SensitiveWordsSection,
  type SensitiveFormValues,
} from '@/features/system-settings/request-limits/sensitive-words-section'
import {
  getSecurityAuditBuiltinPolicy,
  updateSecurityAuditBuiltinPolicy,
} from './api'
import type { SensitiveActionRunner } from './shared'
import type { SecurityAuditBuiltinPolicy } from './types'

type BuiltinPolicyViewProps = {
  runSensitive: SensitiveActionRunner
  onSaved: (policy: SecurityAuditBuiltinPolicy) => void
}

export function SecurityAuditBuiltinPolicyView({
  runSensitive,
  onSaved,
}: BuiltinPolicyViewProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState<SecurityAuditBuiltinPolicy | null>(null)
  const [saving, setSaving] = useState(false)

  const policyQuery = useQuery({
    queryKey: ['security-audit', 'builtin-policy'],
    queryFn: getSecurityAuditBuiltinPolicy,
    staleTime: 15_000,
  })

  useEffect(() => {
    if (policyQuery.data) setDraft(policyQuery.data)
  }, [policyQuery.data])

  const policySwitchesDirty = Boolean(
    draft &&
    policyQuery.data &&
    (draft.upstream_policy_enabled !==
      policyQuery.data.upstream_policy_enabled ||
      draft.sensitive_word_audit_enabled !==
        policyQuery.data.sensitive_word_audit_enabled)
  )

  const resetPolicySwitches = () => {
    if (policyQuery.data) setDraft(policyQuery.data)
  }

  const savePolicy = async (values: SensitiveFormValues) => {
    if (!draft) return

    try {
      await runSensitive(
        async () => {
          setSaving(true)
          try {
            const updated = await updateSecurityAuditBuiltinPolicy({
              expected_version: draft.config_version,
              upstream_policy_enabled: draft.upstream_policy_enabled,
              sensitive_word_audit_enabled: draft.sensitive_word_audit_enabled,
              check_sensitive_enabled: values.CheckSensitiveEnabled,
              check_sensitive_on_prompt_enabled:
                values.CheckSensitiveOnPromptEnabled,
              sensitive_rules: values.SensitiveRules || '{"rules":[]}',
              sensitive_rule_channel_ids:
                values.SensitiveRuleChannelIds || '[]',
            })
            queryClient.setQueryData(
              ['security-audit', 'builtin-policy'],
              updated
            )
            setDraft(updated)
            onSaved(updated)
            await queryClient.invalidateQueries({
              queryKey: ['security-audit', 'runtime'],
            })
            toast.success(t('Built-in safety policy saved'))
            return updated
          } finally {
            setSaving(false)
          }
        },
        {
          title: t('Verify built-in safety policy change'),
          description: t(
            'This operation changes local filtering and upstream policy event collection.'
          ),
        }
      )
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 409) {
        await policyQuery.refetch()
        toast.error(
          t(
            'The configuration changed on the server. Latest values were reloaded; review and save again.'
          )
        )
        return
      }
      toast.error(t('Failed to save built-in safety policy'))
    }
  }

  if (policyQuery.isError) {
    return (
      <Alert variant='destructive'>
        <AlertTitle>{t('Failed to load built-in safety policy')}</AlertTitle>
        <AlertDescription className='flex flex-wrap items-center gap-2'>
          <span>{t('Check your Root permissions and try again.')}</span>
          <Button
            variant='outline'
            size='sm'
            onClick={() => void policyQuery.refetch()}
          >
            {t('Retry')}
          </Button>
        </AlertDescription>
      </Alert>
    )
  }

  if (!draft) {
    return (
      <div className='flex flex-col gap-4'>
        <Skeleton className='h-44 w-full rounded-xl' />
        <Skeleton className='h-96 w-full rounded-xl' />
      </div>
    )
  }

  const sensitiveValues: SensitiveFormValues = {
    CheckSensitiveEnabled: draft.check_sensitive_enabled,
    CheckSensitiveOnPromptEnabled: draft.check_sensitive_on_prompt_enabled,
    SensitiveWords: draft.sensitive_words,
    SensitiveRules: draft.sensitive_rules,
    SensitiveRuleChannelIds: draft.sensitive_rule_channel_ids,
  }

  return (
    <div className='flex flex-col gap-4'>
      <Alert>
        <AlertTitle>{t('Guard nodes are optional')}</AlertTitle>
        <AlertDescription>
          {t(
            'Sensitive word filtering runs locally, and upstream policy events are recognized from exact cyber_policy error codes even when no Guard node is configured.'
          )}
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle>{t('Built-in safety policy')}</CardTitle>
          <CardDescription>
            {t(
              'Choose which built-in detections are recorded in the unified audit event list.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <FieldGroup>
            <Field orientation='horizontal'>
              <FieldContent>
                <FieldLabel htmlFor='audit-upstream-policy-enabled'>
                  {t('Recognize upstream policy events')}
                </FieldLabel>
                <FieldDescription>
                  {t(
                    'Record exact cyber_policy rejections returned by HTTP, streaming, or Realtime upstreams.'
                  )}
                </FieldDescription>
              </FieldContent>
              <Switch
                id='audit-upstream-policy-enabled'
                checked={draft.upstream_policy_enabled}
                onCheckedChange={(upstreamPolicyEnabled) =>
                  setDraft((current) =>
                    current
                      ? {
                          ...current,
                          upstream_policy_enabled: upstreamPolicyEnabled,
                        }
                      : current
                  )
                }
              />
            </Field>
            <Field orientation='horizontal'>
              <FieldContent>
                <FieldLabel htmlFor='audit-sensitive-events-enabled'>
                  {t('Record sensitive word events')}
                </FieldLabel>
                <FieldDescription>
                  {t(
                    'Write one unified event for each deduplicated request, response, or Realtime sensitive-word match.'
                  )}
                </FieldDescription>
              </FieldContent>
              <Switch
                id='audit-sensitive-events-enabled'
                checked={draft.sensitive_word_audit_enabled}
                onCheckedChange={(sensitiveWordAuditEnabled) =>
                  setDraft((current) =>
                    current
                      ? {
                          ...current,
                          sensitive_word_audit_enabled:
                            sensitiveWordAuditEnabled,
                        }
                      : current
                  )
                }
              />
            </Field>
          </FieldGroup>
        </CardContent>
      </Card>

      {draft.uses_legacy_sensitive_words ? (
        <Alert>
          <AlertTitle>{t('Legacy sensitive words detected')}</AlertTitle>
          <AlertDescription>
            {t(
              'They are shown as a structured blocking rule. Saving keeps the legacy data intact and switches the active editor to structured rules.'
            )}
          </AlertDescription>
        </Alert>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle>{t('Sensitive word filtering')}</CardTitle>
          <CardDescription>
            {t(
              'These existing rules were moved from System Settings and continue using the same stored configuration.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SensitiveWordsSection
            defaultValues={sensitiveValues}
            inlineActions
            hideTitle
            externalDirty={policySwitchesDirty}
            isSaving={saving}
            onSaveValues={savePolicy}
            onResetExternal={resetPolicySwitches}
          />
        </CardContent>
      </Card>
    </div>
  )
}
