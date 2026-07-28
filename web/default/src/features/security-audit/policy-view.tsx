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
import { AlertCircleIcon } from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useTranslation } from 'react-i18next'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Field,
  FieldContent,
  FieldDescription,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
  FieldTitle,
} from '@/components/ui/field'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { ToggleGroup, ToggleGroupItem } from '@/components/ui/toggle-group'
import {
  SECURITY_AUDIT_SCANNERS,
  type SecurityAuditConfigDraft,
  type SecurityAuditEndpointDraft,
  type SecurityAuditGroup,
  type SecurityAuditMode,
  type SecurityAuditScanner,
} from './types'

const SCANNER_LABELS: Record<SecurityAuditScanner, string> = {
  violent: 'Violence',
  non_violent_illegal_acts: 'Non-violent illegal acts',
  sexual_content_or_sexual_acts: 'Sexual content or sexual acts',
  pii: 'Personal data and privacy',
  suicide_and_self_harm: 'Suicide and self-harm',
  unethical_acts: 'Unethical acts',
  politically_sensitive_topics: 'Politically sensitive topics',
  copyright_violation: 'Copyright violation',
  jailbreak: 'Jailbreak and prompt injection',
}

function parseInteger(value: string, fallback: number) {
  const parsed = Number.parseInt(value, 10)
  return Number.isFinite(parsed) ? parsed : fallback
}

export function SecurityAuditPolicyView({
  draft,
  groups,
  groupsLoading,
  onChange,
}: {
  draft: SecurityAuditConfigDraft
  groups: SecurityAuditGroup[]
  groupsLoading: boolean
  onChange: (patch: Partial<SecurityAuditConfigDraft>) => void
}) {
  const { t } = useTranslation()

  const setMode = (values: unknown) => {
    if (!Array.isArray(values)) return
    const value = values[0]
    if (value === 'off' || value === 'async_audit' || value === 'blocking') {
      onChange({ mode: value as SecurityAuditMode })
    }
  }

  const toggleScanner = (scanner: SecurityAuditScanner, checked: boolean) => {
    const next = checked
      ? [...new Set([...draft.scanners, scanner])]
      : draft.scanners.filter((item) => item !== scanner)
    onChange({ scanners: next })
  }

  const toggleGroup = (groupId: number, checked: boolean) => {
    const next = checked
      ? [...new Set([...draft.group_ids, groupId])].sort((a, b) => a - b)
      : draft.group_ids.filter((item) => item !== groupId)
    onChange({ group_ids: next })
  }

  const updateEndpointRuntime = (
    index: number,
    patch: Pick<
      Partial<SecurityAuditEndpointDraft>,
      'timeout_ms' | 'input_limit'
    >
  ) => {
    onChange({
      endpoints: draft.endpoints.map((endpoint, endpointIndex) =>
        endpointIndex === index ? { ...endpoint, ...patch } : endpoint
      ),
    })
  }

  return (
    <div className='grid gap-4 xl:grid-cols-2'>
      <div className='flex flex-col gap-4'>
        <FieldSet className='rounded-xl border p-4'>
          <FieldLegend>{t('Prompt Guard mode')}</FieldLegend>
          <FieldDescription>
            {t(
              'Choose whether requests bypass Guard, audit asynchronously, or block until Guard returns. Built-in policies remain independent.'
            )}
          </FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel id='security-audit-mode'>{t('Mode')}</FieldLabel>
              <ToggleGroup
                aria-labelledby='security-audit-mode'
                value={[draft.mode]}
                onValueChange={setMode}
                spacing={2}
                className='flex-wrap justify-start'
              >
                <ToggleGroupItem value='off'>{t('Off')}</ToggleGroupItem>
                <ToggleGroupItem value='async_audit'>
                  {t('Async audit')}
                </ToggleGroupItem>
                <ToggleGroupItem value='blocking'>
                  {t('Blocking')}
                </ToggleGroupItem>
              </ToggleGroup>
            </Field>
            <Field orientation='horizontal'>
              <FieldContent>
                <FieldTitle>{t('Save Safe events')}</FieldTitle>
                <FieldDescription>
                  {t(
                    'Disabled by default to reduce encrypted data retention and storage usage.'
                  )}
                </FieldDescription>
              </FieldContent>
              <Switch
                checked={draft.store_pass_events}
                onCheckedChange={(checked) =>
                  onChange({ store_pass_events: checked })
                }
                aria-label={t('Save Safe events')}
              />
            </Field>
          </FieldGroup>
        </FieldSet>

        {draft.mode === 'blocking' && (
          <Alert>
            <HugeiconsIcon icon={AlertCircleIcon} strokeWidth={2} />
            <AlertTitle>{t('Blocking mode is fail-closed')}</AlertTitle>
            <AlertDescription>
              {t(
                'Guard timeouts, unavailable nodes, and invalid responses reject the request before channel selection and billing.'
              )}
            </AlertDescription>
          </Alert>
        )}

        <FieldSet className='rounded-xl border p-4'>
          <FieldLegend>{t('Risk categories')}</FieldLegend>
          <FieldDescription>
            {t('Select the Qwen3Guard categories that produce a risk event.')}
          </FieldDescription>
          <FieldGroup className='gap-3'>
            {SECURITY_AUDIT_SCANNERS.map((scanner) => (
              <Field key={scanner} orientation='horizontal'>
                <Checkbox
                  id={`security-audit-scanner-${scanner}`}
                  checked={draft.scanners.includes(scanner)}
                  onCheckedChange={(checked) =>
                    toggleScanner(scanner, checked === true)
                  }
                />
                <FieldLabel
                  htmlFor={`security-audit-scanner-${scanner}`}
                  className='font-normal'
                >
                  {t(SCANNER_LABELS[scanner])}
                </FieldLabel>
              </Field>
            ))}
          </FieldGroup>
        </FieldSet>
      </div>

      <div className='flex flex-col gap-4'>
        <FieldSet className='rounded-xl border p-4'>
          <FieldLegend>{t('Group scope')}</FieldLegend>
          <FieldDescription>
            {t('Audit all user groups or only selected stable group IDs.')}
          </FieldDescription>
          <FieldGroup>
            <Field orientation='horizontal'>
              <FieldContent>
                <FieldTitle>{t('All user groups')}</FieldTitle>
                <FieldDescription>
                  {t('New groups are included automatically when enabled.')}
                </FieldDescription>
              </FieldContent>
              <Switch
                checked={draft.all_groups}
                onCheckedChange={(checked) => onChange({ all_groups: checked })}
                aria-label={t('All user groups')}
              />
            </Field>
            {!draft.all_groups && (
              <FieldSet>
                <FieldLegend variant='label'>
                  {t('Selected groups')}
                </FieldLegend>
                <FieldGroup className='gap-3'>
                  {groupsLoading ? (
                    <FieldDescription>
                      {t('Loading groups...')}
                    </FieldDescription>
                  ) : groups.length === 0 ? (
                    <FieldDescription>
                      {t('No user groups are available.')}
                    </FieldDescription>
                  ) : (
                    groups.map((group) => (
                      <Field key={group.id} orientation='horizontal'>
                        <Checkbox
                          id={`security-audit-group-${group.id}`}
                          checked={draft.group_ids.includes(group.id)}
                          onCheckedChange={(checked) =>
                            toggleGroup(group.id, checked === true)
                          }
                        />
                        <FieldContent>
                          <FieldLabel
                            htmlFor={`security-audit-group-${group.id}`}
                            className='font-normal'
                          >
                            {group.name}
                          </FieldLabel>
                          <FieldDescription>
                            {group.code} · ID {group.id}
                          </FieldDescription>
                        </FieldContent>
                      </Field>
                    ))
                  )}
                </FieldGroup>
              </FieldSet>
            )}
          </FieldGroup>
        </FieldSet>

        <FieldSet className='rounded-xl border p-4'>
          <FieldLegend>{t('Runtime and retention')}</FieldLegend>
          <FieldDescription>
            {t('Changes apply after the configuration version is saved.')}
          </FieldDescription>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor='security-audit-worker-count'>
                {t('Worker count')}
              </FieldLabel>
              <Input
                id='security-audit-worker-count'
                type='number'
                min={1}
                max={32}
                value={draft.worker_count}
                onChange={(event) =>
                  onChange({
                    worker_count: parseInteger(
                      event.target.value,
                      draft.worker_count
                    ),
                  })
                }
              />
              <FieldDescription>{t('Allowed range: 1–32')}</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor='security-audit-queue-capacity'>
                {t('Queue capacity')}
              </FieldLabel>
              <Input
                id='security-audit-queue-capacity'
                type='number'
                min={1}
                max={100000}
                value={draft.queue_capacity}
                onChange={(event) =>
                  onChange({
                    queue_capacity: parseInteger(
                      event.target.value,
                      draft.queue_capacity
                    ),
                  })
                }
              />
              <FieldDescription>
                {t('Maximum active database-backed audit tasks')}
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor='security-audit-retention-days'>
                {t('Retention days')}
              </FieldLabel>
              <Input
                id='security-audit-retention-days'
                type='number'
                min={1}
                max={365}
                value={draft.retention_days}
                onChange={(event) =>
                  onChange({
                    retention_days: parseInteger(
                      event.target.value,
                      draft.retention_days
                    ),
                  })
                }
              />
              <FieldDescription>
                {t('Encrypted tasks and events expire after this period.')}
              </FieldDescription>
            </Field>
            {draft.endpoints.length === 0 ? (
              <Field>
                <FieldDescription>{t('No Guard nodes')}</FieldDescription>
              </Field>
            ) : (
              draft.endpoints.map((endpoint, index) => (
                <FieldSet key={endpoint.id} className='rounded-lg border p-3'>
                  <FieldLegend variant='label'>
                    {endpoint.name || endpoint.id}
                  </FieldLegend>
                  <FieldGroup className='grid gap-4 sm:grid-cols-2'>
                    <Field>
                      <FieldLabel
                        htmlFor={`security-audit-endpoint-timeout-${index}`}
                      >
                        {t('Timeout (ms)')}
                      </FieldLabel>
                      <Input
                        id={`security-audit-endpoint-timeout-${index}`}
                        type='number'
                        min={100}
                        max={30000}
                        value={endpoint.timeout_ms}
                        onChange={(event) =>
                          updateEndpointRuntime(index, {
                            timeout_ms: parseInteger(
                              event.target.value,
                              endpoint.timeout_ms
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field>
                      <FieldLabel
                        htmlFor={`security-audit-endpoint-input-limit-${index}`}
                      >
                        {t('Chunk size (Unicode characters)')}
                      </FieldLabel>
                      <Input
                        id={`security-audit-endpoint-input-limit-${index}`}
                        type='number'
                        min={128}
                        max={100000}
                        value={endpoint.input_limit}
                        onChange={(event) =>
                          updateEndpointRuntime(index, {
                            input_limit: parseInteger(
                              event.target.value,
                              endpoint.input_limit
                            ),
                          })
                        }
                      />
                    </Field>
                  </FieldGroup>
                </FieldSet>
              ))
            )}
          </FieldGroup>
        </FieldSet>
      </div>
    </div>
  )
}
