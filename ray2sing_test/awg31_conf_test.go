package ray2sing_test

import (
	"strings"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// A synthetic AmneziaWG 3.1 .conf as AmneziaVPN exports it (made-up keys, documentation
// addresses): booleans as on/off, mixed-case keys, a comment at the end of a line, H ranges with
// spaces, a keepalive range, long I1/I2.
var awg31Conf = `[Interface]
PrivateKey = YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
Address = 10.8.0.2/32, fd00:8::2/128
DNS = 10.8.0.1, 1.1.1.1
MTU = 1280
Jc = 5 # junk packets
jmin = 12
JMAX = 60
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 100000 - 100100
H2 = 200000-200100
H3 = 300000-300100
H4 = 400000-400100
I1 = <b 0x` + strings.Repeat("c0ffee", 400) + `>
I2 = <b 0x` + strings.Repeat("0bad", 600) + `><r 16>
HeaderProtectionKey = Y2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2M=
ContentPaddingAddition = 0-16
RekeyAfterTime = 110-130
RandomTrailers = on
DisableCookies = ON

[Peer]
PublicKey = YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmI=
PresharedKey = ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.20:51830
PersistentKeepalive = 20-30
`

func awgOf(t *testing.T, conf string) *option.AwgEndpointOptions {
	t.Helper()
	end, err := ray2sing.AWGSingboxTxt(conf)
	if err != nil {
		t.Fatal(err)
	}
	if end.Type != C.TypeAwg {
		t.Fatalf("type %s", end.Type)
	}
	return end.Options.(*option.AwgEndpointOptions)
}

func TestAWG31ConfAllValues(t *testing.T) {
	o := awgOf(t, awg31Conf)
	a := o.Awg
	if !a.RandomTrailers || !a.DisableCookies {
		t.Fatalf("RandomTrailers/DisableCookies = on read as %v/%v", a.RandomTrailers, a.DisableCookies)
	}
	if a.Jc != 5 || a.Jmin != 12 || a.Jmax != 60 || a.S1 != 15 || a.S2 != 18 || a.S3 != 20 || a.S4 != 23 {
		t.Fatalf("numbers %+v", a)
	}
	if a.H1 != "100000-100100" || a.H4 != "400000-400100" {
		t.Fatalf("H ranges %q %q", a.H1, a.H4)
	}
	if len(a.I1) < 2400 || !strings.HasSuffix(a.I2, "<r 16>") {
		t.Fatalf("long I1/I2 cut: %d %q", len(a.I1), a.I2[len(a.I2)-8:])
	}
	if len(a.HeaderProtectionKey) != 64 {
		t.Fatalf("header protection key %q, want 64 hex digits", a.HeaderProtectionKey)
	}
	if a.ContentPaddingAddition != "0-16" || a.RekeyAfterTime != "110-130" {
		t.Fatalf("ranges %q %q", a.ContentPaddingAddition, a.RekeyAfterTime)
	}
	if len(o.Peers) != 1 || o.Peers[0].PersistentKeepaliveInterval != "20-30" || o.Peers[0].Port != 51830 || o.Peers[0].PresharedKey == "" {
		t.Fatalf("peer %+v", o.Peers)
	}
	if o.MTU != 1280 || len(o.Address) != 2 {
		t.Fatalf("interface mtu %d addresses %v", o.MTU, o.Address)
	}
}

func TestAWGConfBooleans(t *testing.T) {
	for value, want := range map[string]bool{"on": true, "yes": true, "true": true, "1": true, "TRUE": true, "off": false, "no": false, "false": false, "0": false} {
		conf := strings.Replace(awg31Conf, "RandomTrailers = on", "RandomTrailers = "+value, 1)
		if got := awgOf(t, conf).Awg.RandomTrailers; got != want {
			t.Fatalf("RandomTrailers = %s read as %v", value, got)
		}
	}
}

func TestAWGConfErrorsAreReported(t *testing.T) {
	for name, conf := range map[string]string{
		"bad bool":      strings.Replace(awg31Conf, "RandomTrailers = on", "RandomTrailers = maybe", 1),
		"bad number":    strings.Replace(awg31Conf, "S1 = 15", "S1 = fifteen", 1),
		"bad range":     strings.Replace(awg31Conf, "H2 = 200000-200100", "H2 = 2000x", 1),
		"bad keepalive": strings.Replace(awg31Conf, "PersistentKeepalive = 20-30", "PersistentKeepalive = soon", 1),
		"no peer":       awg31Conf[:strings.Index(awg31Conf, "[Peer]")],
	} {
		if _, err := ray2sing.AWGSingboxTxt(conf); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestAWGConfTwoPeers(t *testing.T) {
	conf := awg31Conf + `
[Peer]
PublicKey = ZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWVlZWU=
AllowedIPs = 10.0.0.0/8
Endpoint = 192.0.2.21:51820
`
	o := awgOf(t, conf)
	if len(o.Peers) != 2 || o.Peers[1].Address != "192.0.2.21" || o.Peers[0].Address != "192.0.2.20" {
		t.Fatalf("peers %+v", o.Peers)
	}
}

// The whole profile path (what Parse calls) reads the .conf the same way.
func TestAWG31ConfThroughRay2Singbox(t *testing.T) {
	options, err := ray2sing.Ray2SingboxOptions(t.Context(), awg31Conf, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Endpoints) != 1 || options.Endpoints[0].Type != C.TypeAwg {
		t.Fatalf("endpoints %+v", options.Endpoints)
	}
	if !options.Endpoints[0].Options.(*option.AwgEndpointOptions).Awg.RandomTrailers {
		t.Fatal("RandomTrailers lost")
	}
}
