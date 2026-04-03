package subexport

import "strings"

// OutputFormat represents the subscription export format.
type OutputFormat int

const (
	FormatClash   OutputFormat = iota
	FormatSingBox
)

// DetectFormat determines the output format from an explicit query parameter
// or User-Agent header. Clash is used as the default when neither is decisive.
func DetectFormat(queryFormat, userAgent string) OutputFormat {
	if queryFormat != "" {
		switch strings.ToLower(strings.TrimSpace(queryFormat)) {
		case "singbox", "sing-box":
			return FormatSingBox
		default:
			return FormatClash
		}
	}

	ua := strings.ToLower(userAgent)
	if strings.HasPrefix(ua, "sing-box") {
		return FormatSingBox
	}
	// Clash-family clients: Clash, ClashMeta, ClashForAndroid, clash-verge, Stash (iOS).
	// All default to Clash output regardless, so no need to enumerate every variant.
	return FormatClash
}
