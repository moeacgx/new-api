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
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const root = dirname(fileURLToPath(import.meta.url))
const readSource = (...parts: string[]) =>
  readFileSync(resolve(root, ...parts), 'utf8')

describe('unified security audit management page', () => {
  test('uses the dedicated Root built-in policy API', () => {
    const api = readSource('api.ts')
    const view = readSource('builtin-policy-view.tsx')

    assert.match(api, /getSecurityAuditBuiltinPolicy/)
    assert.match(api, /updateSecurityAuditBuiltinPolicy/)
    assert.match(api, /\$\{API_ROOT\}\/builtin-policy/)
    assert.match(view, /expected_version:\s*draft\.config_version/)
  })

  test('keeps built-in policy as a first-class audit tab', () => {
    const page = readSource('index.tsx')
    const systemRegistry = readSource(
      '..',
      'system-settings',
      'security',
      'section-registry.tsx'
    )

    assert.match(page, /value:\s*'builtin-policy'/)
    assert.match(page, /SecurityAuditBuiltinPolicyView/)
    assert.doesNotMatch(systemRegistry, /id:\s*'sensitive-words'/)
  })

  test('shows event source, stage, and unavailable prompt state', () => {
    const events = readSource('events-view.tsx')

    assert.match(events, /draftFilter\.source/)
    assert.match(events, /draftFilter\.stage/)
    assert.match(events, /detail\.prompt_available/)
    assert.match(events, /Prompt content was not stored/)
  })

  test('saves migrated sensitive-word rules atomically', () => {
    const view = readSource('builtin-policy-view.tsx')
    const editor = readSource(
      '..',
      'system-settings',
      'request-limits',
      'sensitive-words-section.tsx'
    )

    assert.match(view, /sensitive_rules:\s*values\.SensitiveRules/)
    assert.match(view, /sensitive_rule_channel_ids:/)
    assert.match(editor, /onSaveValues/)
    assert.match(editor, /inlineActions/)
    assert.doesNotMatch(editor, /\}, \[defaultValues\]\)/)
  })
})
