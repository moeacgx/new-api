package service

import (
	"errors"
	"strings"

	"github.com/QuantumNous/new-api/dto"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/setting"
)

func CheckSensitiveMessages(messages []dto.Message, group string, model string) ([]string, error) {
	if len(messages) == 0 {
		return nil, nil
	}

	for _, message := range messages {
		arrayContent := message.ParseContent()
		for _, m := range arrayContent {
			if m.Type == "image_url" {
				// TODO: check image url
				continue
			}
			if m.Text == "" {
				continue
			}
			if ok, words := SensitiveWordContains(m.Text, group, model); ok {
				return words, errors.New("sensitive words detected")
			}
		}
	}
	return nil, nil
}

func CheckSensitiveText(text string, group string, model string) (bool, []string) {
	words := setting.GetEffectiveSensitiveWords(group, model)
	contains, matched := SensitiveWordContains(text, group, model)
	logger.SysLog("sensitive-check text group=" + group + " model=" + model + " words=" + strings.Join(words, ",") + " text=" + text)
	if contains {
		logger.SysLog("sensitive-check matched=" + strings.Join(matched, ","))
	}
	return contains, matched
}

// SensitiveWordContains 是否包含敏感词，返回是否包含敏感词和敏感词列表
func SensitiveWordContains(text string, group string, model string) (bool, []string) {
	words := setting.GetEffectiveSensitiveWords(group, model)
	if len(words) == 0 {
		return false, nil
	}
	if len(text) == 0 {
		return false, nil
	}
	checkText := strings.ToLower(text)
	return AcSearch(checkText, words, true)
}

// SensitiveWordReplace 敏感词替换，返回是否包含敏感词和替换后的文本
func SensitiveWordReplace(text string, returnImmediately bool, group string, model string) (bool, []string, string) {
	words := setting.GetEffectiveSensitiveWords(group, model)
	if len(words) == 0 {
		return false, nil, text
	}
	checkText := strings.ToLower(text)
	m := getOrBuildAC(words)
	hits := m.MultiPatternSearch([]rune(checkText), returnImmediately)
	if len(hits) > 0 {
		matched := make([]string, 0, len(hits))
		var builder strings.Builder
		builder.Grow(len(text))
		lastPos := 0

		for _, hit := range hits {
			pos := hit.Pos
			word := string(hit.Word)
			builder.WriteString(text[lastPos:pos])
			builder.WriteString("**###**")
			lastPos = pos + len(word)
			matched = append(matched, word)
		}
		builder.WriteString(text[lastPos:])
		return true, matched, builder.String()
	}
	return false, nil, text
}
