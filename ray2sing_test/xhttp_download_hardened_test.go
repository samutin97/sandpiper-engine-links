package ray2sing_test

import (
	"net/url"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
)

func xhttpDownload(t *testing.T, extra string) *option.V2RayXHTTPDownloadOptions {
	t.Helper()
	link := "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&sni=example.com&fp=firefox&type=xhttp&path=/x&extra=" + url.QueryEscape(extra) + "#x"
	out, err := ray2sing.VlessSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	return out.Options.(*option.VLESSOutboundOptions).Transport.XHTTPOptions.Download
}

func TestXHTTPDownloadLegIsNeverPlainByAccident(t *testing.T) {
	// no security: the main leg's TLS
	if dl := xhttpDownload(t, `{"downloadSettings":{"address":"d.example.com","port":443}}`); dl.TLS == nil || !dl.TLS.Enabled || dl.TLS.ServerName != "example.com" {
		t.Fatalf("inherited: %+v", dl.TLS)
	}
	// tls without tlsSettings: TLS with the main SNI and fingerprint
	dl := xhttpDownload(t, `{"downloadSettings":{"address":"d.example.com","port":443,"security":"tls"}}`)
	if dl.TLS == nil || dl.TLS.ServerName != "example.com" || dl.TLS.UTLS == nil || dl.TLS.UTLS.Fingerprint != "firefox" {
		t.Fatalf("tls without settings: %+v", dl.TLS)
	}
	// explicit none stays plain
	if dl := xhttpDownload(t, `{"downloadSettings":{"address":"d.example.com","port":80,"security":"none"}}`); dl.TLS != nil {
		t.Fatalf("none: %+v", dl.TLS)
	}
	// REALITY without a fingerprint gets one (it needs uTLS)
	dl = xhttpDownload(t, `{"downloadSettings":{"address":"d.example.com","port":443,"security":"reality","realitySettings":{"publicKey":"k","serverName":"d.com"}}}`)
	if dl.TLS == nil || dl.TLS.UTLS == nil || dl.TLS.UTLS.Fingerprint == "" {
		t.Fatalf("reality: %+v", dl.TLS)
	}
	// the whole xhttpSettings of the leg
	dl = xhttpDownload(t, `{"downloadSettings":{"address":"d.example.com","port":443,"xPaddingBytes":"100-200","xhttpSettings":{"path":"/dl","noGRPCHeader":true}}}`)
	if dl.Path != "/dl" || !dl.NoGRPCHeader {
		t.Fatalf("xhttpSettings: %+v", dl.V2RayXHTTPBaseOptions)
	}
}

func TestXHTTPDownloadPortRange(t *testing.T) {
	link := "vless://00000000-0000-4000-8000-000000000001@example.com:443?security=tls&type=xhttp&extra=" + url.QueryEscape(`{"downloadSettings":{"address":"d","port":70000}}`) + "#x"
	if _, err := ray2sing.VlessSingbox(link); err == nil {
		t.Fatal("port 70000 accepted")
	}
}
