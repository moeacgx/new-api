package setting

import (
	"encoding/json"
	"sort"
	"strings"
)

var CheckSensitiveEnabled = true
var CheckSensitiveOnPromptEnabled = true

//var CheckSensitiveOnCompletionEnabled = true

// StopOnSensitiveEnabled 如果检测到敏感词，是否立刻停止生成，否则替换敏感词
var StopOnSensitiveEnabled = true

// StreamCacheQueueLength 流模式缓存队列长度，0表示无缓存
var StreamCacheQueueLength = 0

// SensitiveWords 敏感词
// var SensitiveWords []string
var SensitiveWords = []string{
	"test_sensitive",
}

type SensitiveRuleScope struct {
	Group string   `json:"group,omitempty"`
	Model string   `json:"model,omitempty"`
	Words []string `json:"words,omitempty"`
}

type SensitiveRuleConfig struct {
	Global     []string             `json:"global,omitempty"`
	GroupRules []SensitiveRuleScope `json:"group_rules,omitempty"`
	ModelRules []SensitiveRuleScope `json:"model_rules,omitempty"`
}

func normalizeSensitiveWords(words []string) []string {
	if len(words) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(words))
	result := make([]string, 0, len(words))
	for _, word := range words {
		word = strings.TrimSpace(word)
		if word == "" {
			continue
		}
		lower := strings.ToLower(word)
		if _, ok := seen[lower]; ok {
			continue
		}
		seen[lower] = struct{}{}
		result = append(result, lower)
	}
	sort.Strings(result)
	return result
}

func normalizeSensitiveRuleScopes(rules []SensitiveRuleScope, field string) []SensitiveRuleScope {
	if len(rules) == 0 {
		return []SensitiveRuleScope{}
	}
	result := make([]SensitiveRuleScope, 0, len(rules))
	for _, rule := range rules {
		words := normalizeSensitiveWords(rule.Words)
		if len(words) == 0 {
			continue
		}
		entry := SensitiveRuleScope{Words: words}
		switch field {
		case "group":
			entry.Group = strings.TrimSpace(rule.Group)
			if entry.Group == "" {
				continue
			}
		case "model":
			entry.Model = strings.TrimSpace(rule.Model)
			if entry.Model == "" {
				continue
			}
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if field == "group" {
			return result[i].Group < result[j].Group
		}
		return result[i].Model < result[j].Model
	})
	return result
}

func normalizeSensitiveRuleConfig(cfg SensitiveRuleConfig) SensitiveRuleConfig {
	return SensitiveRuleConfig{
		Global:     normalizeSensitiveWords(cfg.Global),
		GroupRules: normalizeSensitiveRuleScopes(cfg.GroupRules, "group"),
		ModelRules: normalizeSensitiveRuleScopes(cfg.ModelRules, "model"),
	}
}

func SensitiveWordsToString() string {
	return strings.Join(SensitiveWords, "\n")
}

func SensitiveWordsConfigToJSONString() string {
	cfg := normalizeSensitiveRuleConfig(SensitiveRuleConfig{
		Global: SensitiveWords,
	})
	b, err := json.Marshal(cfg)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func SensitiveWordsFromString(s string) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		SensitiveWords = []string{}
		return
	}
	if strings.HasPrefix(trimmed, "{") {
		var cfg SensitiveRuleConfig
		if err := json.Unmarshal([]byte(trimmed), &cfg); err == nil {
			cfg = normalizeSensitiveRuleConfig(cfg)
			SensitiveWords = cfg.Global
			return
		}
	}
	SensitiveWords = []string{}
	sw := strings.Split(trimmed, "\n")
	for _, w := range sw {
		w = strings.TrimSpace(w)
		if w != "" {
			SensitiveWords = append(SensitiveWords, strings.ToLower(w))
		}
	}
	SensitiveWords = normalizeSensitiveWords(SensitiveWords)
}

func ParseSensitiveRuleConfig(raw string) SensitiveRuleConfig {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return SensitiveRuleConfig{Global: normalizeSensitiveWords(SensitiveWords)}
	}
	if strings.HasPrefix(trimmed, "{") {
		var cfg SensitiveRuleConfig
		if err := json.Unmarshal([]byte(trimmed), &cfg); err == nil {
			return normalizeSensitiveRuleConfig(cfg)
		}
	}
	return SensitiveRuleConfig{Global: normalizeSensitiveWords(strings.Split(trimmed, "\n"))}
}

func GetEffectiveSensitiveWords(group string, model string) []string {
	cfg := ParseSensitiveRuleConfig(SensitiveWordsConfigToJSONString())
	result := append([]string{}, cfg.Global...)
	seen := make(map[string]struct{}, len(result))
	for _, word := range result {
		seen[word] = struct{}{}
	}
	for _, rule := range cfg.GroupRules {
		if rule.Group != group {
			continue
		}
		for _, word := range rule.Words {
			if _, ok := seen[word]; ok {
				continue
			}
			seen[word] = struct{}{}
			result = append(result, word)
		}
	}
	for _, rule := range cfg.ModelRules {
		if rule.Model != model {
			continue
		}
		for _, word := range rule.Words {
			if _, ok := seen[word]; ok {
				continue
			}
			seen[word] = struct{}{}
			result = append(result, word)
		}
	}
	return result
}

func ShouldCheckPromptSensitive() bool {
	return CheckSensitiveEnabled && CheckSensitiveOnPromptEnabled
}

//func ShouldCheckCompletionSensitive() bool {
//	return CheckSensitiveEnabled && CheckSensitiveOnCompletionEnabled
//}
