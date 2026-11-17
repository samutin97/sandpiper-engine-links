package ray2sing_test

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// amneziaKey packs a .conf as AmneziaVPN does: JSON, qCompress (big-endian length + zlib),
// base64url without padding.
func amneziaKey(t *testing.T, conf string, qcompress bool) string {
	t.Helper()
	last, _ := json.Marshal(map[string]any{"config": conf, "mtu": "1280"})
	key, _ := json.Marshal(map[string]any{
		"containers": []any{
			map[string]any{"container": "amnezia-openvpn", "openvpn": map[string]any{"last_config": `{"config":"client"}`}},
			map[string]any{"container": "amnezia-awg", "awg": map[string]any{"last_config": string(last), "port": "51830", "transport_proto": "udp"}},
		},
		"defaultContainer": "amnezia-awg",
		"description":      "Test server",
		"dns1":             "1.1.1.1",
	})
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(key)
	w.Close()
	payload := z.Bytes()
	if qcompress {
		payload = append(binary.BigEndian.AppendUint32(nil, uint32(len(key))), payload...)
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(payload)
}

func TestAmneziaVPNKey(t *testing.T) {
	for _, q := range []bool{true, false} {
		end, err := ray2sing.AmneziaVPNSingbox(amneziaKey(t, awg31Conf, q))
		if err != nil {
			t.Fatal(err)
		}
		if end.Type != C.TypeAwg || end.Tag != "Test server" {
			t.Fatalf("%s %q", end.Type, end.Tag)
		}
		o := end.Options.(*option.AwgEndpointOptions)
		if !o.Awg.RandomTrailers || o.Awg.S4 != 23 || o.Peers[0].PersistentKeepaliveInterval != "20-30" {
			t.Fatalf("awg %+v", o.Awg)
		}
	}
}

func TestAmneziaVPNKeyThroughTheParser(t *testing.T) {
	options, err := ray2sing.Ray2SingboxOptions(t.Context(), amneziaKey(t, awg31Conf, true), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 1 || options.Endpoints[0].Type != C.TypeAwg {
		t.Fatalf("%+v", options.Endpoints)
	}
}

func TestAmneziaVPNKeyLimits(t *testing.T) {
	// a zip bomb: 2 MiB of zeros declared and packed
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(bytes.Repeat([]byte{' '}, 2<<20))
	w.Close()
	bomb := "vpn://" + base64.RawURLEncoding.EncodeToString(z.Bytes())
	if _, err := ray2sing.AmneziaVPNSingbox(bomb); err == nil {
		t.Fatal("a 2 MiB key accepted")
	}
	if _, err := ray2sing.AmneziaVPNSingbox("vpn://!!!"); err == nil {
		t.Fatal("not base64 accepted")
	}
	noAwg := amneziaKey(t, awg31Conf, true)
	_ = noAwg
	key, _ := json.Marshal(map[string]any{"containers": []any{map[string]any{"container": "amnezia-xray", "xray": map[string]any{"last_config": "{}"}}}})
	var zz bytes.Buffer
	ww := zlib.NewWriter(&zz)
	ww.Write(key)
	ww.Close()
	if _, err := ray2sing.AmneziaVPNSingbox("vpn://" + base64.RawURLEncoding.EncodeToString(zz.Bytes())); err == nil || !strings.Contains(err.Error(), "no AmneziaWG") {
		t.Fatalf("xray-only key: %v", err)
	}
}
