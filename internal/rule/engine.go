package rule

import (
	"context"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/example/ai-audit-gateway/internal/audit"
)

type Definition struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
	Weight   int    `json:"weight"`
	Regex    bool   `json:"regex"`
}

type compiledRule struct {
	definition Definition
	re         *regexp.Regexp
}

type ahoNode struct {
	next  map[byte]int
	fail  int
	terms []int
}

type Snapshot struct {
	rules []compiledRule
	aho   []ahoNode
}

type Engine struct{ current atomic.Pointer[Snapshot] }

func New(definitions []Definition) (*Engine, error) {
	engine := &Engine{}
	if err := engine.Replace(definitions); err != nil {
		return nil, err
	}
	return engine, nil
}

func (e *Engine) Replace(definitions []Definition) error {
	rules := make([]compiledRule, 0, len(definitions))
	for _, definition := range definitions {
		if definition.Pattern == "" {
			continue
		}
		if definition.Weight <= 0 {
			definition.Weight = 10
		}
		if definition.Severity == "" {
			definition.Severity = "medium"
		}
		if definition.Action == "" {
			definition.Action = "monitor"
		}
		compiled := compiledRule{definition: definition}
		if definition.Regex {
			re, err := regexp.Compile(definition.Pattern)
			if err != nil {
				return err
			}
			compiled.re = re
		}
		rules = append(rules, compiled)
	}
	snapshot := &Snapshot{rules: rules}
	buildAho(snapshot)
	e.current.Store(snapshot)
	return nil
}

func (e *Engine) Audit(_ context.Context, input audit.Input) audit.Result {
	result := audit.Result{}
	snapshot := e.current.Load()
	if snapshot == nil {
		return result
	}
	text := strings.ToLower(input.Text)
	for _, index := range ahoMatches(snapshot.aho, []byte(text)) {
		item := snapshot.rules[index]
		result.Matches = append(result.Matches, toMatch(item))
		result.Score += item.definition.Weight
	}
	for _, item := range snapshot.rules {
		if item.re == nil || !item.re.MatchString(text) {
			continue
		}
		result.Matches = append(result.Matches, toMatch(item))
		result.Score += item.definition.Weight
	}
	if result.Score > 100 {
		result.Score = 100
	}
	return result
}

func toMatch(item compiledRule) audit.Match {
	return audit.Match{RuleID: item.definition.ID, Name: item.definition.Name, Severity: item.definition.Severity, Action: item.definition.Action, Weight: item.definition.Weight, Evidence: item.definition.Pattern}
}

func buildAho(snapshot *Snapshot) {
	snapshot.aho = []ahoNode{{next: map[byte]int{}}}
	for index, item := range snapshot.rules {
		if item.re != nil {
			continue
		}
		state := 0
		for _, char := range []byte(strings.ToLower(item.definition.Pattern)) {
			next, ok := snapshot.aho[state].next[char]
			if !ok {
				next = len(snapshot.aho)
				snapshot.aho[state].next[char] = next
				snapshot.aho = append(snapshot.aho, ahoNode{next: map[byte]int{}})
			}
			state = next
		}
		snapshot.aho[state].terms = append(snapshot.aho[state].terms, index)
	}
	queue := make([]int, 0)
	for _, state := range snapshot.aho[0].next {
		queue = append(queue, state)
	}
	for len(queue) > 0 {
		state := queue[0]
		queue = queue[1:]
		for char, next := range snapshot.aho[state].next {
			queue = append(queue, next)
			fallback := snapshot.aho[state].fail
			for fallback != 0 {
				if target, ok := snapshot.aho[fallback].next[char]; ok {
					fallback = target
					goto found
				}
				fallback = snapshot.aho[fallback].fail
			}
			if target, ok := snapshot.aho[0].next[char]; ok {
				fallback = target
			}
		found:
			snapshot.aho[next].fail = fallback
			snapshot.aho[next].terms = append(snapshot.aho[next].terms, snapshot.aho[fallback].terms...)
		}
	}
}

func ahoMatches(nodes []ahoNode, text []byte) []int {
	if len(nodes) == 0 {
		return nil
	}
	state := 0
	seen := make(map[int]struct{})
	matches := make([]int, 0)
	for _, char := range text {
		for state != 0 {
			if next, ok := nodes[state].next[char]; ok {
				state = next
				goto matched
			}
			state = nodes[state].fail
		}
		if next, ok := nodes[0].next[char]; ok {
			state = next
		}
	matched:
		for _, index := range nodes[state].terms {
			if _, ok := seen[index]; !ok {
				seen[index] = struct{}{}
				matches = append(matches, index)
			}
		}
	}
	return matches
}
