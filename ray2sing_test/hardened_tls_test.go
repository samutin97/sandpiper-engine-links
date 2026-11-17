package ray2sing_test

import (
	"encoding/hex"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
)

// a made-up certificate SHA-256, written with colons as Hysteria 2 URIs do
var testPin = strings.Repeat("ab:", 31) + "ab"

func hy2(t *testing.T, link string) *option.Hysteria2OutboundOptions {
	t.Helper()
	out, err := ray2sing.Hysteria2Singbox(link)
	if err != nil {
		t.Fatal(err)
	}
	return out.Options.(*option.Hysteria2OutboundOptions)
}

func TestHysteria2KeepsThePin(t *testing.T) {
	o := hy2(t, "hysteria2://pass@example.com:443/?insecure=1&pinSHA256="+testPin+"&sni=example.com#h")
	if !o.TLS.Insecure || len(o.TLS.CertificateSHA256) != 1 || hex.EncodeToString(o.TLS.CertificateSHA256[0]) != strings.ReplaceAll(testPin, ":", "") {
		t.Fatalf("tls %+v", o.TLS)
	}
	o = hy2(t, "hysteria2://pass@example.com:443/?pcs="+strings.ReplaceAll(testPin, ":", "")+"#h")
	if len(o.TLS.CertificateSHA256) != 1 || o.TLS.Insecure {
		t.Fatalf("pcs: %+v", o.TLS)
	}
	if !hy2(t, "hysteria2://pass@example.com:443/?insecure=true#h").TLS.Insecure {
		t.Fatal("insecure=true not read")
	}
}

func TestHysteria2PortHopping(t *testing.T) {
	o := hy2(t, "hysteria2://pass@example.com:443/?mport=20000-30000,40000&hop-interval=30s#h")
	if !slices.Equal([]string(o.ServerPorts), []string{"20000:30000", "40000:40000"}) {
		t.Fatalf("ports %v", o.ServerPorts)
	}
	if time.Duration(o.HopInterval) != 30*time.Second {
		t.Fatalf("hop %v", o.HopInterval)
	}
	o = hy2(t, "hysteria2://pass@example.com:443,50000-51000/?hopInterval=10#h")
	if !slices.Equal([]string(o.ServerPorts), []string{"443:443", "50000:51000"}) || time.Duration(o.HopInterval) != 10*time.Second {
		t.Fatalf("ports in the address %v %v", o.ServerPorts, o.HopInterval)
	}
}

func vlessTLS(t *testing.T, link string) *option.OutboundTLSOptions {
	t.Helper()
	out, err := ray2sing.VlessSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	return out.Options.(*option.VLESSOutboundOptions).TLS
}

func TestALPNByTransport(t *testing.T) {
	const base = "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&sni=example.com&alpn=h2,http/1.1&"
	cases := map[string][]string{
		"type=ws&path=/a":          {"http/1.1"},
		"type=httpupgrade&path=/a": {"http/1.1"},
		"type=grpc&serviceName=s":  {"h2"},
		"type=tcp":                 {"h2", "http/1.1"},
	}
	for query, want := range cases {
		if got := vlessTLS(t, base+query+"#x").ALPN; !slices.Equal(got, want) {
			t.Errorf("%s: ALPN %v, want %v", query, got, want)
		}
	}
	if vlessTLS(t, "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&sni=example.com&nosni=0#x").DisableSNI {
		t.Error("nosni=0 disabled SNI")
	}
}
