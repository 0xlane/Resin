package subexport

import (
	"encoding/json"
	"testing"
)

func TestConvertSingboxToClash_Vmess(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "vmess",
		"tag": "original-tag",
		"server": "example.com",
		"server_port": 443,
		"uuid": "aaaa-bbbb-cccc",
		"security": "auto",
		"alter_id": 0,
		"tls": {
			"enabled": true,
			"server_name": "sni.example.com",
			"insecure": true,
			"alpn": ["h2", "http/1.1"],
			"utls": {"enabled": true, "fingerprint": "chrome"}
		},
		"transport": {
			"type": "ws",
			"path": "/ws-path",
			"headers": {"Host": "ws.example.com"}
		}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "My Sub/Node 1")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "name", "My Sub/Node 1")
	assertString(t, clash, "type", "vmess")
	assertString(t, clash, "server", "example.com")
	assertUint(t, clash, "port", 443)
	assertString(t, clash, "uuid", "aaaa-bbbb-cccc")
	assertString(t, clash, "cipher", "auto")
	assertBool(t, clash, "tls", true)
	assertString(t, clash, "servername", "sni.example.com")
	assertBool(t, clash, "skip-cert-verify", true)
	assertString(t, clash, "client-fingerprint", "chrome")
	assertString(t, clash, "network", "ws")

	wsOpts, ok := clash["ws-opts"].(map[string]any)
	if !ok {
		t.Fatal("ws-opts missing")
	}
	if wsOpts["path"] != "/ws-path" {
		t.Fatalf("ws-opts path: got %v", wsOpts["path"])
	}
}

func TestConvertSingboxToClash_Vless(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "vless",
		"tag": "tag",
		"server": "vless.example.com",
		"server_port": 8443,
		"uuid": "vless-uuid",
		"flow": "xtls-rprx-vision",
		"tls": {"enabled": true, "server_name": "sni.example.com"}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "Display Name")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "vless")
	assertString(t, clash, "uuid", "vless-uuid")
	assertString(t, clash, "flow", "xtls-rprx-vision")
	assertBool(t, clash, "tls", true)
}

func TestConvertSingboxToClash_Trojan(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "trojan",
		"tag": "tag",
		"server": "trojan.example.com",
		"server_port": 443,
		"password": "trojan-pass",
		"tls": {"enabled": true, "server_name": "trojan.example.com"}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "Trojan Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "trojan")
	assertString(t, clash, "password", "trojan-pass")
	assertBool(t, clash, "tls", true)
}

func TestConvertSingboxToClash_Shadowsocks(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "shadowsocks",
		"tag": "tag",
		"server": "ss.example.com",
		"server_port": 8388,
		"method": "aes-256-gcm",
		"password": "ss-pass",
		"plugin": "obfs-local",
		"plugin_opts": "obfs=http;obfs-host=example.com"
	}`)

	clash, ok := ConvertSingboxToClash(raw, "SS Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "ss")
	assertString(t, clash, "cipher", "aes-256-gcm")
	assertString(t, clash, "password", "ss-pass")
	assertString(t, clash, "plugin", "obfs-local")
}

func TestConvertSingboxToClash_Hysteria2(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "hysteria2",
		"tag": "tag",
		"server": "hy2.example.com",
		"server_port": 443,
		"password": "hy2-pass",
		"up_mbps": 100,
		"down_mbps": 200,
		"tls": {"enabled": true, "server_name": "hy2.example.com"},
		"obfs": {"type": "salamander", "password": "obfs-pass"}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "HY2 Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "hysteria2")
	assertString(t, clash, "password", "hy2-pass")
	assertString(t, clash, "obfs", "salamander")
	assertString(t, clash, "obfs-password", "obfs-pass")
}

func TestConvertSingboxToClash_Socks(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "socks",
		"tag": "tag",
		"server": "socks.example.com",
		"server_port": 1080,
		"username": "user",
		"password": "pass"
	}`)

	clash, ok := ConvertSingboxToClash(raw, "SOCKS Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "socks5")
	assertString(t, clash, "username", "user")
}

func TestConvertSingboxToClash_Wireguard(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "wireguard",
		"tag": "tag",
		"server": "wg.example.com",
		"server_port": 51820,
		"private_key": "priv-key",
		"peer_public_key": "pub-key",
		"local_address": ["10.0.0.2/32", "fd00::2/128"],
		"reserved": [1, 2, 3],
		"mtu": 1420
	}`)

	clash, ok := ConvertSingboxToClash(raw, "WG Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "wireguard")
	assertString(t, clash, "private-key", "priv-key")
	assertString(t, clash, "public-key", "pub-key")
	assertString(t, clash, "ip", "10.0.0.2/32")
	assertString(t, clash, "ipv6", "fd00::2/128")
}

func TestConvertSingboxToClash_Tuic(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "tuic",
		"tag": "tag",
		"server": "tuic.example.com",
		"server_port": 443,
		"uuid": "tuic-uuid",
		"password": "tuic-pass",
		"congestion_control": "bbr",
		"tls": {"enabled": true, "server_name": "tuic.example.com"}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "TUIC Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "tuic")
	assertString(t, clash, "uuid", "tuic-uuid")
	assertString(t, clash, "congestion-controller", "bbr")
}

func TestConvertSingboxToClash_Anytls(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "anytls",
		"tag": "tag",
		"server": "anytls.example.com",
		"server_port": 443,
		"password": "anytls-pass",
		"tls": {"enabled": true, "server_name": "anytls.example.com"}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "AnyTLS Node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "type", "anytls")
	assertString(t, clash, "password", "anytls-pass")
}

func TestConvertSingboxToClash_UnsupportedType(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "shadowtls",
		"tag": "tag",
		"server": "example.com",
		"server_port": 443
	}`)
	_, ok := ConvertSingboxToClash(raw, "node")
	if ok {
		t.Fatal("expected unsupported type to return false")
	}
}

func TestConvertSingboxToClash_DialFields(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "trojan",
		"tag": "tag",
		"server": "example.com",
		"server_port": 443,
		"password": "pass",
		"tls": {"enabled": true},
		"detour": "warp",
		"tcp_fast_open": true,
		"domain_strategy": "ipv4_only"
	}`)

	clash, ok := ConvertSingboxToClash(raw, "node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "dialer-proxy", "warp")
	assertBool(t, clash, "tfo", true)
	assertString(t, clash, "ip-version", "ipv4")
}

func TestConvertSingboxToClash_GrpcTransport(t *testing.T) {
	raw := json.RawMessage(`{
		"type": "vless",
		"tag": "tag",
		"server": "example.com",
		"server_port": 443,
		"uuid": "uuid",
		"tls": {"enabled": true},
		"transport": {"type": "grpc", "service_name": "my-grpc"}
	}`)

	clash, ok := ConvertSingboxToClash(raw, "node")
	if !ok {
		t.Fatal("conversion failed")
	}
	assertString(t, clash, "network", "grpc")
	grpcOpts, ok := clash["grpc-opts"].(map[string]any)
	if !ok {
		t.Fatal("grpc-opts missing")
	}
	if grpcOpts["grpc-service-name"] != "my-grpc" {
		t.Fatalf("grpc-service-name: got %v", grpcOpts["grpc-service-name"])
	}
}

// --- test helpers ---

func assertString(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	s, ok := got.(string)
	if !ok {
		t.Fatalf("key %q: want string, got %T", key, got)
	}
	if s != want {
		t.Fatalf("key %q: got %q, want %q", key, s, want)
	}
}

func assertUint(t *testing.T, m map[string]any, key string, want uint64) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	n, ok := got.(uint64)
	if !ok {
		t.Fatalf("key %q: want uint64, got %T (%v)", key, got, got)
	}
	if n != want {
		t.Fatalf("key %q: got %d, want %d", key, n, want)
	}
}

func assertBool(t *testing.T, m map[string]any, key string, want bool) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Fatalf("key %q missing", key)
	}
	b, ok := got.(bool)
	if !ok {
		t.Fatalf("key %q: want bool, got %T", key, got)
	}
	if b != want {
		t.Fatalf("key %q: got %v, want %v", key, b, want)
	}
}
