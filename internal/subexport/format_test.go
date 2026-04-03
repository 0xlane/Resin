package subexport

import "testing"

func TestDetectFormat_ExplicitQuery(t *testing.T) {
	tests := []struct {
		query string
		want  OutputFormat
	}{
		{"clash", FormatClash},
		{"Clash", FormatClash},
		{"CLASH", FormatClash},
		{"singbox", FormatSingBox},
		{"sing-box", FormatSingBox},
		{"SingBox", FormatSingBox},
		{"unknown", FormatClash},
		{"", FormatClash}, // empty falls through to UA, but UA empty → Clash
	}
	for _, tt := range tests {
		t.Run("query="+tt.query, func(t *testing.T) {
			got := DetectFormat(tt.query, "")
			if got != tt.want {
				t.Fatalf("DetectFormat(%q, \"\") = %d, want %d", tt.query, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_UserAgent(t *testing.T) {
	tests := []struct {
		ua   string
		want OutputFormat
	}{
		{"sing-box/1.12.0", FormatSingBox},
		{"Sing-Box/1.0", FormatSingBox},
		{"ClashForAndroid/2.5.12", FormatClash},
		{"clash-verge/1.0", FormatClash},
		{"Stash/2.4.0", FormatClash},
		{"ClashMeta/1.18.0", FormatClash},
		{"Mozilla/5.0", FormatClash},
		{"curl/8.0", FormatClash},
		{"", FormatClash},
	}
	for _, tt := range tests {
		t.Run("ua="+tt.ua, func(t *testing.T) {
			got := DetectFormat("", tt.ua)
			if got != tt.want {
				t.Fatalf("DetectFormat(\"\", %q) = %d, want %d", tt.ua, got, tt.want)
			}
		})
	}
}

func TestDetectFormat_QueryOverridesUA(t *testing.T) {
	// Explicit format=clash should override sing-box UA.
	got := DetectFormat("clash", "sing-box/1.12.0")
	if got != FormatClash {
		t.Fatalf("expected Clash when query overrides UA, got %d", got)
	}
	// Explicit format=singbox should override Clash UA.
	got = DetectFormat("singbox", "ClashForAndroid/2.5.12")
	if got != FormatSingBox {
		t.Fatalf("expected SingBox when query overrides UA, got %d", got)
	}
}
