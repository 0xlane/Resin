package subexport

import (
	"strings"
	"testing"
)

func TestUnescapeYAMLUnicode_PreservesEmoji(t *testing.T) {
	input := "name: \"风萧萧机场/\\U0001F1FA\\U0001F1F8US-iz佬赞助\"\n"
	got := unescapeYAMLUnicode(input)
	if !strings.Contains(got, "🇺🇸US-iz佬赞助") {
		t.Fatalf("expected emoji-preserved output, got %q", got)
	}
	if strings.Contains(got, `\U0001F1FA`) {
		t.Fatalf("expected unicode escape to be removed, got %q", got)
	}
}
