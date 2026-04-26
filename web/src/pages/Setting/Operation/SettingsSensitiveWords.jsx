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

import React, { useEffect, useState, useRef } from 'react';
import { Button, Col, Form, Row, Spin, Tag } from '@douyinfe/semi-ui';
import {
  compareObjects,
  API,
  showError,
  showSuccess,
  showWarning,
} from '../../../helpers';
import { useTranslation } from 'react-i18next';

const defaultSensitiveRules = {
  global: [],
  group_rules: [],
  model_rules: [],
};

const normalizeWords = (value) => {
  if (!value) return [];
  const seen = new Set();
  return value
    .split('\n')
    .map((item) => item.trim())
    .filter((item) => item)
    .filter((item) => {
      const lowered = item.toLowerCase();
      if (seen.has(lowered)) return false;
      seen.add(lowered);
      return true;
    });
};

const stringifyWords = (words) => {
  if (!Array.isArray(words) || words.length === 0) return '';
  return words.join('\n');
};

const parseSensitiveRules = (raw) => {
  if (!raw || !String(raw).trim()) {
    return { ...defaultSensitiveRules };
  }
  const trimmed = String(raw).trim();
  if (!trimmed.startsWith('{')) {
    return {
      ...defaultSensitiveRules,
      global: normalizeWords(trimmed),
    };
  }
  try {
    const parsed = JSON.parse(trimmed);
    return {
      global: Array.isArray(parsed.global) ? parsed.global : [],
      group_rules: Array.isArray(parsed.group_rules) ? parsed.group_rules : [],
      model_rules: Array.isArray(parsed.model_rules) ? parsed.model_rules : [],
    };
  } catch {
    return {
      ...defaultSensitiveRules,
      global: normalizeWords(trimmed),
    };
  }
};

const buildSensitiveRulesPayload = (state) => {
  const payload = {
    global: normalizeWords(state.SensitiveWordsGlobal),
    group_rules: state.SensitiveWordsGroupRules.map((rule) => ({
      group: (rule.group || '').trim(),
      words: normalizeWords(rule.words || ''),
    })).filter((rule) => rule.group && rule.words.length > 0),
    model_rules: state.SensitiveWordsModelRules.map((rule) => ({
      model: (rule.model || '').trim(),
      words: normalizeWords(rule.words || ''),
    })).filter((rule) => rule.model && rule.words.length > 0),
  };
  return JSON.stringify(payload);
};

export default function SettingsSensitiveWords(props) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [inputs, setInputs] = useState({
    CheckSensitiveEnabled: false,
    CheckSensitiveOnPromptEnabled: false,
    SensitiveWords: '',
    SensitiveWordsGlobal: '',
    SensitiveWordsGroupRules: [],
    SensitiveWordsModelRules: [],
  });
  const refForm = useRef();
  const [inputsRow, setInputsRow] = useState(inputs);

  const updateInputState = (patch) => {
    setInputs((prev) => ({
      ...prev,
      ...patch,
    }));
  };

  const updateGroupRule = (index, patch) => {
    const next = [...inputs.SensitiveWordsGroupRules];
    next[index] = { ...next[index], ...patch };
    updateInputState({ SensitiveWordsGroupRules: next });
  };

  const updateModelRule = (index, patch) => {
    const next = [...inputs.SensitiveWordsModelRules];
    next[index] = { ...next[index], ...patch };
    updateInputState({ SensitiveWordsModelRules: next });
  };

  function onSubmit() {
    const serializedSensitiveWords = buildSensitiveRulesPayload(inputs);
    const compareSource = {
      ...inputs,
      SensitiveWords: serializedSensitiveWords,
    };
    const compareTarget = {
      ...inputsRow,
      SensitiveWords: inputsRow.SensitiveWords,
    };
    const updateArray = compareObjects(compareSource, compareTarget).filter((item) =>
      ['CheckSensitiveEnabled', 'CheckSensitiveOnPromptEnabled', 'SensitiveWords'].includes(item.key),
    );
    if (!updateArray.length) return showWarning(t('你似乎并没有修改什么'));
    const requestQueue = updateArray.map((item) => {
      let value = '';
      if (item.key === 'SensitiveWords') {
        value = serializedSensitiveWords;
      } else if (typeof compareSource[item.key] === 'boolean') {
        value = String(compareSource[item.key]);
      } else {
        value = compareSource[item.key];
      }
      return API.put('/api/option/', {
        key: item.key,
        value,
      });
    });
    setLoading(true);
    Promise.all(requestQueue)
      .then((res) => {
        if (requestQueue.length === 1) {
          if (res.includes(undefined)) return;
        } else if (requestQueue.length > 1) {
          if (res.includes(undefined)) return showError(t('部分保存失败，请重试'));
        }
        showSuccess(t('保存成功'));
        props.refresh();
      })
      .catch(() => {
        showError(t('保存失败，请重试'));
      })
      .finally(() => {
        setLoading(false);
      });
  }

  useEffect(() => {
    const currentInputs = {
      CheckSensitiveEnabled: false,
      CheckSensitiveOnPromptEnabled: false,
      SensitiveWords: '',
      SensitiveWordsGlobal: '',
      SensitiveWordsGroupRules: [],
      SensitiveWordsModelRules: [],
    };
    for (let key in props.options) {
      if (Object.prototype.hasOwnProperty.call(currentInputs, key)) {
        currentInputs[key] = props.options[key];
      }
    }
    const parsed = parseSensitiveRules(currentInputs.SensitiveWords || '');
    currentInputs.SensitiveWords = currentInputs.SensitiveWords || '';
    currentInputs.SensitiveWordsGlobal = stringifyWords(parsed.global);
    currentInputs.SensitiveWordsGroupRules = parsed.group_rules.map((rule) => ({
      group: rule.group || '',
      words: stringifyWords(rule.words || []),
    }));
    currentInputs.SensitiveWordsModelRules = parsed.model_rules.map((rule) => ({
      model: rule.model || '',
      words: stringifyWords(rule.words || []),
    }));
    setInputs(currentInputs);
    setInputsRow(structuredClone(currentInputs));
    // Defer setValues to next tick so dynamic group/model rule fields are rendered first
    setTimeout(() => {
      if (refForm.current) {
        refForm.current.setValues(currentInputs);
      }
    }, 0);
  }, [props.options]);

  return (
    <>
      <Spin spinning={loading}>
        <Form
          values={inputs}
          getFormApi={(formAPI) => (refForm.current = formAPI)}
          style={{ marginBottom: 15 }}
        >
          <Form.Section text={t('屏蔽词过滤设置')}>
            <Row gutter={16}>
              <Col xs={24} sm={12} md={8} lg={8} xl={8}>
                <Form.Switch
                  field={'CheckSensitiveEnabled'}
                  label={t('启用屏蔽词过滤功能')}
                  size='default'
                  checkedText='｜'
                  uncheckedText='〇'
                  onChange={(value) => updateInputState({ CheckSensitiveEnabled: value })}
                />
              </Col>
              <Col xs={24} sm={12} md={8} lg={8} xl={8}>
                <Form.Switch
                  field={'CheckSensitiveOnPromptEnabled'}
                  label={t('启用 Prompt 检查')}
                  size='default'
                  checkedText='｜'
                  uncheckedText='〇'
                  onChange={(value) => updateInputState({ CheckSensitiveOnPromptEnabled: value })}
                />
              </Col>
            </Row>
            <Row>
              <Col xs={24} sm={24} md={10} lg={10} xl={10}>
                <Form.TextArea
                  label={t('全局默认屏蔽词')}
                  extraText={t('一行一个，所有分组和模型都会生效')}
                  placeholder={t('一行一个屏蔽词，不需要符号分割')}
                  field={'SensitiveWordsGlobal'}
                  onChange={(value) => updateInputState({ SensitiveWordsGlobal: value })}
                  style={{ fontFamily: 'JetBrains Mono, Consolas' }}
                  autosize={{ minRows: 6, maxRows: 12 }}
                />
              </Col>
            </Row>

            <Row style={{ marginTop: 16 }}>
              <Tag color='blue'>{t('分组屏蔽词')}</Tag>
            </Row>
            {inputs.SensitiveWordsGroupRules.map((rule, index) => (
              <Row gutter={12} key={`group-rule-${index}`} style={{ marginTop: 12 }}>
                <Col xs={24} sm={8} md={6} lg={6} xl={6}>
                  <div className='semi-form-field-label-text' style={{ marginBottom: 4, fontWeight: 600 }}>{t('分组')}</div>
                  <input
                    className='semi-input'
                    style={{ width: '100%', padding: '5px 12px', borderRadius: 6, border: '1px solid var(--semi-color-border)', background: 'var(--semi-color-fill-0)', fontSize: 14, lineHeight: '32px', boxSizing: 'border-box' }}
                    placeholder={t('例如：Codex专用')}
                    value={rule.group || ''}
                    onChange={(e) => updateGroupRule(index, { group: e.target.value })}
                  />
                </Col>
                <Col xs={24} sm={16} md={12} lg={12} xl={12}>
                  <div className='semi-form-field-label-text' style={{ marginBottom: 4, fontWeight: 600 }}>{t('屏蔽词')}</div>
                  <textarea
                    className='semi-input'
                    style={{ width: '100%', padding: '5px 12px', borderRadius: 6, border: '1px solid var(--semi-color-border)', background: 'var(--semi-color-fill-0)', fontSize: 14, minHeight: 100, fontFamily: 'JetBrains Mono, Consolas', resize: 'vertical', boxSizing: 'border-box' }}
                    placeholder={t('一行一个屏蔽词，不需要符号分割')}
                    value={rule.words || ''}
                    onChange={(e) => updateGroupRule(index, { words: e.target.value })}
                  />
                </Col>
                <Col xs={24} sm={24} md={4} lg={4} xl={4} style={{ display: 'flex', alignItems: 'end' }}>
                  <Button
                    type='danger'
                    theme='borderless'
                    onClick={() => updateInputState({
                      SensitiveWordsGroupRules: inputs.SensitiveWordsGroupRules.filter((_, i) => i !== index),
                    })}
                  >
                    {t('删除')}
                  </Button>
                </Col>
              </Row>
            ))}
            <Row style={{ marginTop: 8 }}>
              <Button
                theme='light'
                onClick={() => updateInputState({
                  SensitiveWordsGroupRules: [
                    ...inputs.SensitiveWordsGroupRules,
                    { group: '', words: '' },
                  ],
                })}
              >
                {t('新增分组规则')}
              </Button>
            </Row>

            <Row style={{ marginTop: 20 }}>
              <Tag color='green'>{t('模型单独屏蔽词')}</Tag>
            </Row>
            {inputs.SensitiveWordsModelRules.map((rule, index) => (
              <Row gutter={12} key={`model-rule-${index}`} style={{ marginTop: 12 }}>
                <Col xs={24} sm={8} md={6} lg={6} xl={6}>
                  <div className='semi-form-field-label-text' style={{ marginBottom: 4, fontWeight: 600 }}>{t('模型')}</div>
                  <input
                    className='semi-input'
                    style={{ width: '100%', padding: '5px 12px', borderRadius: 6, border: '1px solid var(--semi-color-border)', background: 'var(--semi-color-fill-0)', fontSize: 14, lineHeight: '32px', boxSizing: 'border-box' }}
                    placeholder={t('例如：gpt-5.5')}
                    value={rule.model || ''}
                    onChange={(e) => updateModelRule(index, { model: e.target.value })}
                  />
                </Col>
                <Col xs={24} sm={16} md={12} lg={12} xl={12}>
                  <div className='semi-form-field-label-text' style={{ marginBottom: 4, fontWeight: 600 }}>{t('屏蔽词')}</div>
                  <textarea
                    className='semi-input'
                    style={{ width: '100%', padding: '5px 12px', borderRadius: 6, border: '1px solid var(--semi-color-border)', background: 'var(--semi-color-fill-0)', fontSize: 14, minHeight: 100, fontFamily: 'JetBrains Mono, Consolas', resize: 'vertical', boxSizing: 'border-box' }}
                    placeholder={t('一行一个屏蔽词，不需要符号分割')}
                    value={rule.words || ''}
                    onChange={(e) => updateModelRule(index, { words: e.target.value })}
                  />
                </Col>
                <Col xs={24} sm={24} md={4} lg={4} xl={4} style={{ display: 'flex', alignItems: 'end' }}>
                  <Button
                    type='danger'
                    theme='borderless'
                    onClick={() => updateInputState({
                      SensitiveWordsModelRules: inputs.SensitiveWordsModelRules.filter((_, i) => i !== index),
                    })}
                  >
                    {t('删除')}
                  </Button>
                </Col>
              </Row>
            ))}
            <Row style={{ marginTop: 8 }}>
              <Button
                theme='light'
                onClick={() => updateInputState({
                  SensitiveWordsModelRules: [
                    ...inputs.SensitiveWordsModelRules,
                    { model: '', words: '' },
                  ],
                })}
              >
                {t('新增模型规则')}
              </Button>
            </Row>

            <Row style={{ marginTop: 16 }}>
              <Button size='default' onClick={onSubmit}>
                {t('保存屏蔽词过滤设置')}
              </Button>
            </Row>
          </Form.Section>
        </Form>
      </Spin>
    </>
  );
}
