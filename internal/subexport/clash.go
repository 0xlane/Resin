package subexport

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
)

// ConvertSingboxToClash converts a sing-box outbound JSON into a Clash proxy map.
// displayName is used as the Clash "name" field.
// Returns (nil, false) for unsupported outbound types.
func ConvertSingboxToClash(raw json.RawMessage, displayName string) (map[string]any, bool) {
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}

	nodeType := getString(obj, "type")
	server := getString(obj, "server")
	port := getNumber(obj, "server_port")
	if server == "" || port == 0 {
		return nil, false
	}

	var clash map[string]any
	var ok bool

	switch nodeType {
	case "shadowsocks":
		clash, ok = reverseSSToClash(obj, server, port)
	case "vmess":
		clash, ok = reverseVmessToClash(obj, server, port)
	case "vless":
		clash, ok = reverseVlessToClash(obj, server, port)
	case "trojan":
		clash, ok = reverseTrojanToClash(obj, server, port)
	case "hysteria2":
		clash, ok = reverseHysteria2ToClash(obj, server, port)
	case "hysteria":
		clash, ok = reverseHysteriaToClash(obj, server, port)
	case "socks":
		clash, ok = reverseSocksToClash(obj, server, port)
	case "http":
		clash, ok = reverseHTTPToClash(obj, server, port)
	case "wireguard":
		clash, ok = reverseWireguardToClash(obj, server, port)
	case "tuic":
		clash, ok = reverseTuicToClash(obj, server, port)
	case "anytls":
		clash, ok = reverseAnytlsToClash(obj, server, port)
	default:
		return nil, false
	}
	if !ok {
		return nil, false
	}

	clash["name"] = displayName
	reverseDialFields(obj, clash)
	return clash, true
}

// --- per-protocol converters ---

func reverseSSToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	method := getString(obj, "method")
	password := getString(obj, "password")
	if method == "" || password == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":     "ss",
		"server":   server,
		"port":     port,
		"cipher":   method,
		"password": password,
	}
	if plugin := getString(obj, "plugin"); plugin != "" {
		clash["plugin"] = plugin
		if pluginOpts := getString(obj, "plugin_opts"); pluginOpts != "" {
			clash["plugin-opts-string"] = pluginOpts
		}
	}
	return clash, true
}

func reverseVmessToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	uuid := getString(obj, "uuid")
	if uuid == "" {
		return nil, false
	}
	security := getString(obj, "security")
	if security == "" {
		security = "auto"
	}
	clash := map[string]any{
		"type":   "vmess",
		"server": server,
		"port":   port,
		"uuid":   uuid,
		"cipher": security,
	}
	if alterID := getNumber(obj, "alter_id"); alterID > 0 {
		clash["alterId"] = alterID
	} else {
		clash["alterId"] = 0
	}
	reverseTLSToClash(obj, clash, "tls")
	reverseTransportToClash(obj, clash)
	return clash, true
}

func reverseVlessToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	uuid := getString(obj, "uuid")
	if uuid == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":   "vless",
		"server": server,
		"port":   port,
		"uuid":   uuid,
	}
	if flow := getString(obj, "flow"); flow != "" {
		clash["flow"] = flow
	}
	reverseTLSToClash(obj, clash, "tls")
	reverseVLESSRealityToClash(obj, clash)
	reverseTransportToClash(obj, clash)
	return clash, true
}

func reverseTrojanToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	password := getString(obj, "password")
	if password == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":     "trojan",
		"server":   server,
		"port":     port,
		"password": password,
	}
	// Trojan TLS: reverse from the tls sub-object.
	if tlsObj := getMap(obj, "tls"); tlsObj != nil {
		if getBool(tlsObj, "enabled") {
			clash["tls"] = true
		}
		if sni := getString(tlsObj, "server_name"); sni != "" {
			clash["sni"] = sni
		}
		if getBool(tlsObj, "insecure") {
			clash["skip-cert-verify"] = true
		}
		if alpn := getStringSlice(tlsObj, "alpn"); len(alpn) > 0 {
			clash["alpn"] = alpn
		}
		reverseUTLSToClash(tlsObj, clash)
	}
	reverseTransportToClash(obj, clash)
	return clash, true
}

func reverseHysteria2ToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	password := getString(obj, "password")
	if password == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":     "hysteria2",
		"server":   server,
		"port":     port,
		"password": password,
	}
	reverseTLSFieldsInline(obj, clash)
	if ports := getStringSlice(obj, "server_ports"); len(ports) > 0 {
		clash["ports"] = formatHysteriaPortListForClash(ports)
	}
	if up := getNumber(obj, "up_mbps"); up > 0 {
		clash["up"] = up
	}
	if down := getNumber(obj, "down_mbps"); down > 0 {
		clash["down"] = down
	}
	if hopInterval := getString(obj, "hop_interval"); hopInterval != "" {
		clash["hop-interval"] = hopInterval
	}
	if obfsObj := getMap(obj, "obfs"); obfsObj != nil {
		if obfsType := getString(obfsObj, "type"); obfsType != "" {
			clash["obfs"] = obfsType
		}
		if obfsPassword := getString(obfsObj, "password"); obfsPassword != "" {
			clash["obfs-password"] = obfsPassword
		}
	}
	return clash, true
}

func reverseHysteriaToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	clash := map[string]any{
		"type":   "hysteria",
		"server": server,
		"port":   port,
	}
	if authStr := getString(obj, "auth_str"); authStr != "" {
		clash["auth-str"] = authStr
	}
	if up := getString(obj, "up"); up != "" {
		clash["up"] = up
	}
	if down := getString(obj, "down"); down != "" {
		clash["down"] = down
	}
	if obfs := getString(obj, "obfs"); obfs != "" {
		clash["obfs"] = obfs
	}
	if ports := getStringSlice(obj, "server_ports"); len(ports) > 0 {
		clash["ports"] = formatHysteriaPortListForClash(ports)
	}
	if recvWindowConn := getNumber(obj, "recv_window_conn"); recvWindowConn > 0 {
		clash["recv-window-conn"] = recvWindowConn
	}
	if recvWindow := getNumber(obj, "recv_window"); recvWindow > 0 {
		clash["recv-window"] = recvWindow
	}
	if v := getBoolPtr(obj, "disable_mtu_discovery"); v != nil {
		clash["disable-mtu-discovery"] = *v
	}
	if hopInterval := getString(obj, "hop_interval"); hopInterval != "" {
		clash["hop-interval"] = hopInterval
	}
	if network := getString(obj, "network"); strings.EqualFold(network, "udp") {
		clash["protocol"] = "udp"
	}
	reverseTLSFieldsInline(obj, clash)
	return clash, true
}

func reverseSocksToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	clash := map[string]any{
		"type":   "socks5",
		"server": server,
		"port":   port,
	}
	if version := getString(obj, "version"); version != "" {
		switch version {
		case "4":
			clash["type"] = "socks4"
		case "4a":
			clash["type"] = "socks4a"
		}
	}
	if username := getString(obj, "username"); username != "" {
		clash["username"] = username
	}
	if password := getString(obj, "password"); password != "" {
		clash["password"] = password
	}
	if network := getString(obj, "network"); network == "tcp" {
		clash["udp"] = false
	}
	return clash, true
}

func reverseHTTPToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	clash := map[string]any{
		"type":   "http",
		"server": server,
		"port":   port,
	}
	if username := getString(obj, "username"); username != "" {
		clash["username"] = username
	}
	if password := getString(obj, "password"); password != "" {
		clash["password"] = password
	}
	if headers := getMap(obj, "headers"); headers != nil {
		clash["headers"] = headers
	}
	if tlsObj := getMap(obj, "tls"); tlsObj != nil {
		if getBool(tlsObj, "enabled") {
			clash["tls"] = true
		}
		if sni := getString(tlsObj, "server_name"); sni != "" {
			clash["sni"] = sni
		}
		if getBool(tlsObj, "insecure") {
			clash["skip-cert-verify"] = true
		}
	}
	return clash, true
}

func reverseWireguardToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	privateKey := getString(obj, "private_key")
	if privateKey == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":   "wireguard",
		"server": server,
		"port":   port,
	}
	clash["private-key"] = privateKey

	// Prefer peer_public_key (legacy flat format), fall back to peers[0].
	publicKey := getString(obj, "peer_public_key")
	if publicKey == "" {
		if peers := getSlice(obj, "peers"); len(peers) > 0 {
			if peer, ok := peers[0].(map[string]any); ok {
				publicKey = getString(peer, "public_key")
				if allowedIPs := getStringSlice(peer, "allowed_ips"); len(allowedIPs) > 0 {
					clash["allowed-ips"] = allowedIPs
				}
				if preSharedKey := getString(peer, "pre_shared_key"); preSharedKey != "" {
					clash["pre-shared-key"] = preSharedKey
				}
				if reserved := getUint8Array(peer, "reserved"); len(reserved) > 0 {
					clash["reserved"] = reserved
				}
			}
		}
	} else {
		if peers := getSlice(obj, "peers"); len(peers) > 0 {
			if peer, ok := peers[0].(map[string]any); ok {
				if allowedIPs := getStringSlice(peer, "allowed_ips"); len(allowedIPs) > 0 {
					clash["allowed-ips"] = allowedIPs
				}
			}
		}
		if preSharedKey := getString(obj, "pre_shared_key"); preSharedKey != "" {
			clash["pre-shared-key"] = preSharedKey
		}
		if reserved := getUint8Array(obj, "reserved"); len(reserved) > 0 {
			clash["reserved"] = reserved
		}
	}
	if publicKey != "" {
		clash["public-key"] = publicKey
	}

	if localAddress := getStringSlice(obj, "local_address"); len(localAddress) > 0 {
		var ipv4, ipv6 []string
		for _, addr := range localAddress {
			if strings.Contains(addr, ":") {
				ipv6 = append(ipv6, addr)
			} else {
				ipv4 = append(ipv4, addr)
			}
		}
		if len(ipv4) > 0 {
			clash["ip"] = ipv4[0]
		}
		if len(ipv6) > 0 {
			clash["ipv6"] = ipv6[0]
		}
	}
	if mtu := getNumber(obj, "mtu"); mtu > 0 {
		clash["mtu"] = mtu
	}
	if network := getString(obj, "network"); network == "tcp" {
		clash["udp"] = false
	}
	return clash, true
}

func reverseTuicToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	uuid := getString(obj, "uuid")
	if uuid == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":   "tuic",
		"server": server,
		"port":   port,
		"uuid":   uuid,
	}
	if password := getString(obj, "password"); password != "" {
		clash["password"] = password
	}
	if cc := getString(obj, "congestion_control"); cc != "" {
		clash["congestion-controller"] = cc
	}
	if relayMode := getString(obj, "udp_relay_mode"); relayMode != "" {
		clash["udp-relay-mode"] = relayMode
	}
	if zeroRTT := getBoolPtr(obj, "zero_rtt_handshake"); zeroRTT != nil && *zeroRTT {
		clash["reduce-rtt"] = true
	}
	if heartbeat := getString(obj, "heartbeat"); heartbeat != "" {
		clash["heartbeat-interval"] = heartbeat
	}
	reverseTLSFieldsInline(obj, clash)
	if tlsObj := getMap(obj, "tls"); tlsObj != nil {
		if getBool(tlsObj, "disable_sni") {
			clash["disable-sni"] = true
		}
	}
	return clash, true
}

func reverseAnytlsToClash(obj map[string]any, server string, port uint64) (map[string]any, bool) {
	password := getString(obj, "password")
	if password == "" {
		return nil, false
	}
	clash := map[string]any{
		"type":     "anytls",
		"server":   server,
		"port":     port,
		"password": password,
	}
	reverseTLSFieldsInline(obj, clash)
	if interval := getString(obj, "idle_session_check_interval"); interval != "" {
		clash["idle-session-check-interval"] = interval
	}
	if timeout := getString(obj, "idle_session_timeout"); timeout != "" {
		clash["idle-session-timeout"] = timeout
	}
	if minIdle := getNumber(obj, "min_idle_session"); minIdle > 0 {
		clash["min-idle-session"] = minIdle
	}
	return clash, true
}

// --- shared reverse helpers ---

// reverseTLSToClash reverses setTLSFromClash for protocols that use a top-level
// "tls" boolean in Clash (vmess, vless).
func reverseTLSToClash(obj map[string]any, clash map[string]any, _ string) {
	tlsObj := getMap(obj, "tls")
	if tlsObj == nil {
		return
	}
	if v := getBoolPtr(tlsObj, "enabled"); v != nil {
		clash["tls"] = *v
	}
	if sni := getString(tlsObj, "server_name"); sni != "" {
		clash["servername"] = sni
	}
	if v := getBoolPtr(tlsObj, "insecure"); v != nil {
		clash["skip-cert-verify"] = *v
	}
	if alpn := getStringSlice(tlsObj, "alpn"); len(alpn) > 0 {
		clash["alpn"] = alpn
	}
	reverseUTLSToClash(tlsObj, clash)
	reverseTLSCertificateToClash(tlsObj, clash)
}

// reverseTLSFieldsInline is for protocols where TLS fields are placed directly
// in the Clash proxy map (hysteria2, hysteria, tuic, anytls).
func reverseTLSFieldsInline(obj map[string]any, clash map[string]any) {
	tlsObj := getMap(obj, "tls")
	if tlsObj == nil {
		return
	}
	if sni := getString(tlsObj, "server_name"); sni != "" {
		clash["sni"] = sni
	}
	if getBool(tlsObj, "insecure") {
		clash["skip-cert-verify"] = true
	}
	if alpn := getStringSlice(tlsObj, "alpn"); len(alpn) > 0 {
		clash["alpn"] = alpn
	}
	reverseUTLSToClash(tlsObj, clash)
	reverseTLSCertificateToClash(tlsObj, clash)
}

func reverseUTLSToClash(tlsObj map[string]any, clash map[string]any) {
	utls := getMap(tlsObj, "utls")
	if utls == nil {
		return
	}
	if getBool(utls, "enabled") {
		if fp := getString(utls, "fingerprint"); fp != "" {
			clash["client-fingerprint"] = fp
		}
	}
}

func reverseTLSCertificateToClash(tlsObj map[string]any, clash map[string]any) {
	if certPath := getString(tlsObj, "certificate_path"); certPath != "" {
		clash["ca"] = certPath
	}
	if certs := getStringSlice(tlsObj, "certificate"); len(certs) > 0 {
		clash["ca-str"] = certs[0]
	}
}

func reverseVLESSRealityToClash(obj map[string]any, clash map[string]any) {
	tlsObj := getMap(obj, "tls")
	if tlsObj == nil {
		return
	}
	reality := getMap(tlsObj, "reality")
	if reality == nil {
		return
	}
	realityOpts := map[string]any{}
	if publicKey := getString(reality, "public_key"); publicKey != "" {
		realityOpts["public-key"] = publicKey
	}
	if shortID := getString(reality, "short_id"); shortID != "" {
		realityOpts["short-id"] = shortID
	}
	if len(realityOpts) > 0 {
		clash["reality-opts"] = realityOpts
	}
}

// reverseTransportToClash reverses setV2RayTransportFromClash.
func reverseTransportToClash(obj map[string]any, clash map[string]any) {
	transport := getMap(obj, "transport")
	if transport == nil {
		return
	}

	tType := getString(transport, "type")
	switch tType {
	case "ws":
		clash["network"] = "ws"
		wsOpts := map[string]any{}
		if path := getString(transport, "path"); path != "" {
			// Reconstruct early-data query parameters when present.
			if ed := getNumber(transport, "max_early_data"); ed > 0 {
				path = fmt.Sprintf("%s?ed=%d", path, uint64(ed))
				if eh := getString(transport, "early_data_header_name"); eh != "" && eh != "Sec-WebSocket-Protocol" {
					path = fmt.Sprintf("%s&eh=%s", path, eh)
				}
			}
			wsOpts["path"] = path
		}
		if headers := getMap(transport, "headers"); headers != nil && len(headers) > 0 {
			wsOpts["headers"] = headers
		}
		if len(wsOpts) > 0 {
			clash["ws-opts"] = wsOpts
		}
	case "grpc":
		clash["network"] = "grpc"
		grpcOpts := map[string]any{}
		if serviceName := getString(transport, "service_name"); serviceName != "" {
			grpcOpts["grpc-service-name"] = serviceName
		}
		if len(grpcOpts) > 0 {
			clash["grpc-opts"] = grpcOpts
		}
	case "http":
		clash["network"] = "h2"
		h2Opts := map[string]any{}
		if path := getString(transport, "path"); path != "" {
			h2Opts["path"] = path
		}
		if hosts := getStringSlice(transport, "host"); len(hosts) > 0 {
			h2Opts["host"] = hosts
		}
		if len(h2Opts) > 0 {
			clash["h2-opts"] = h2Opts
		}
	case "quic":
		clash["network"] = "quic"
	case "httpupgrade":
		clash["network"] = "httpupgrade"
		opts := map[string]any{}
		if path := getString(transport, "path"); path != "" {
			opts["path"] = path
		}
		if host := getString(transport, "host"); host != "" {
			opts["host"] = host
		}
		if headers := getMap(transport, "headers"); headers != nil && len(headers) > 0 {
			opts["headers"] = headers
		}
		if len(opts) > 0 {
			clash["http-upgrade-opts"] = opts
		}
	}
}

// reverseDialFields reverses applyClashDialFields.
func reverseDialFields(obj map[string]any, clash map[string]any) {
	if detour := getString(obj, "detour"); detour != "" {
		clash["dialer-proxy"] = detour
	}
	if bindInterface := getString(obj, "bind_interface"); bindInterface != "" {
		clash["interface-name"] = bindInterface
	}
	if routingMark := getNumber(obj, "routing_mark"); routingMark > 0 {
		clash["routing-mark"] = routingMark
	}
	if v := getBoolPtr(obj, "tcp_fast_open"); v != nil {
		clash["tfo"] = *v
	}
	if v := getBoolPtr(obj, "tcp_multi_path"); v != nil {
		clash["mptcp"] = *v
	}
	if v := getBoolPtr(obj, "udp_fragment"); v != nil {
		clash["udp-fragment"] = *v
	}
	if ds := getString(obj, "domain_strategy"); ds != "" {
		if ipVersion := reverseDomainStrategy(ds); ipVersion != "" {
			clash["ip-version"] = ipVersion
		}
	}
}

func reverseDomainStrategy(ds string) string {
	switch ds {
	case "ipv4_only":
		return "ipv4"
	case "ipv6_only":
		return "ipv6"
	case "prefer_ipv4":
		return "prefer-ipv4"
	case "prefer_ipv6":
		return "prefer-ipv6"
	default:
		return ""
	}
}

func formatHysteriaPortListForClash(ports []string) string {
	if len(ports) == 0 {
		return ""
	}
	formatted := make([]string, 0, len(ports))
	for _, port := range ports {
		formatted = append(formatted, strings.ReplaceAll(port, ":", "-"))
	}
	return strings.Join(formatted, ",")
}

// --- JSON accessor helpers ---

func getString(obj map[string]any, key string) string {
	v, ok := obj[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprint(v)
	}
	return s
}

func getNumber(obj map[string]any, key string) uint64 {
	v, ok := obj[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		if n < 0 {
			return 0
		}
		return uint64(math.Round(n))
	case json.Number:
		i, err := n.Int64()
		if err == nil && i >= 0 {
			return uint64(i)
		}
		return 0
	case int:
		if n < 0 {
			return 0
		}
		return uint64(n)
	case int64:
		if n < 0 {
			return 0
		}
		return uint64(n)
	case uint64:
		return n
	default:
		return 0
	}
}

func getBool(obj map[string]any, key string) bool {
	v, ok := obj[key]
	if !ok || v == nil {
		return false
	}
	b, ok := v.(bool)
	return ok && b
}

func getBoolPtr(obj map[string]any, key string) *bool {
	v, ok := obj[key]
	if !ok || v == nil {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

func getMap(obj map[string]any, key string) map[string]any {
	v, ok := obj[key]
	if !ok || v == nil {
		return nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	return m
}

func getSlice(obj map[string]any, key string) []any {
	v, ok := obj[key]
	if !ok || v == nil {
		return nil
	}
	s, ok := v.([]any)
	if !ok {
		return nil
	}
	return s
}

func getStringSlice(obj map[string]any, key string) []string {
	v, ok := obj[key]
	if !ok || v == nil {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return nil
	}
}

func getUint8Array(obj map[string]any, key string) []uint8 {
	items := getSlice(obj, key)
	if len(items) == 0 {
		return nil
	}
	result := make([]uint8, 0, len(items))
	for _, item := range items {
		switch n := item.(type) {
		case float64:
			if n >= 0 && n <= 255 {
				result = append(result, uint8(n))
			}
		}
	}
	return result
}
