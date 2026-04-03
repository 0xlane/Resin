package subexport

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/Resinat/Resin/internal/node"
	"github.com/Resinat/Resin/internal/platform"
	"github.com/Resinat/Resin/internal/topology"
	"gopkg.in/yaml.v3"
)

// ExportParams holds input parameters for the subscription export.
type ExportParams struct {
	PlatformName string
	Format       OutputFormat
}

// nodeItem pairs a raw config with its display name for sorting/rendering.
type nodeItem struct {
	DisplayName string
	RawOptions  json.RawMessage
}

// Export produces a subscription document from healthy nodes in the given platform.
// Returns the Content-Type and serialised body.
func Export(params ExportParams, pool *topology.GlobalNodePool) (contentType string, body []byte, err error) {
	platName := params.PlatformName
	if platName == "" {
		platName = platform.DefaultPlatformName
	}

	plat, ok := pool.GetPlatformByName(platName)
	if !ok {
		return "", nil, fmt.Errorf("platform not found: %s", platName)
	}

	// Collect healthy nodes from the platform's routable view.
	var items []nodeItem
	plat.View().Range(func(h node.Hash) bool {
		entry, ok := pool.GetEntry(h)
		if !ok {
			return true
		}
		displayName := pool.ResolveNodeDisplayTag(h)
		if displayName == "" {
			displayName = h.Hex()[:12]
		}
		items = append(items, nodeItem{
			DisplayName: displayName,
			RawOptions:  append(json.RawMessage(nil), entry.RawOptions...),
		})
		return true
	})

	// Sort alphabetically by display name for deterministic output.
	sort.Slice(items, func(i, j int) bool {
		return items[i].DisplayName < items[j].DisplayName
	})

	switch params.Format {
	case FormatSingBox:
		return formatSingBoxOutput(items)
	default:
		return formatClashOutput(items)
	}
}

func formatClashOutput(items []nodeItem) (string, []byte, error) {
	proxies := make([]map[string]any, 0, len(items))
	for _, item := range items {
		clash, ok := ConvertSingboxToClash(item.RawOptions, item.DisplayName)
		if !ok {
			continue
		}
		proxies = append(proxies, clash)
	}

	doc := map[string]any{
		"proxies": proxies,
	}
	body, err := yaml.Marshal(doc)
	if err != nil {
		return "", nil, fmt.Errorf("marshal clash yaml: %w", err)
	}
	return "text/yaml; charset=utf-8", body, nil
}

func formatSingBoxOutput(items []nodeItem) (string, []byte, error) {
	outbounds := make([]json.RawMessage, len(items))
	displayNames := make([]string, len(items))
	for i, item := range items {
		outbounds[i] = item.RawOptions
		displayNames[i] = item.DisplayName
	}
	body, err := FormatSingbox(outbounds, displayNames)
	if err != nil {
		return "", nil, fmt.Errorf("marshal singbox json: %w", err)
	}
	return "application/json; charset=utf-8", body, nil
}
