package subexport

import "encoding/json"

// FormatSingbox wraps outbound configs into a sing-box subscription JSON document.
// Each outbound's "tag" field is replaced with the provided display name.
func FormatSingbox(outbounds []json.RawMessage, displayNames []string) ([]byte, error) {
	items := make([]json.RawMessage, 0, len(outbounds))
	for i, raw := range outbounds {
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if i < len(displayNames) && displayNames[i] != "" {
			obj["tag"] = displayNames[i]
		}
		encoded, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		items = append(items, encoded)
	}
	doc := struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}{
		Outbounds: items,
	}
	return json.MarshalIndent(doc, "", "  ")
}
