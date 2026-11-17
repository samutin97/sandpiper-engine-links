package ray2sing

import (
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// hysteria2PortRanges reads a port list of mport= ("20000-30000,40000") as sing-box server_ports.
func hysteria2PortRanges(spec string) []string {
	spec = strings.ReplaceAll(strings.TrimSpace(spec), " ", "")
	if spec == "" || !portListRegex.MatchString(spec) {
		return nil
	}
	var ranges []string
	for _, part := range strings.Split(spec, ",") {
		from, to, found := strings.Cut(part, "-")
		if !found {
			to = from
		}
		ranges = append(ranges, from+":"+to)
	}
	return ranges
}

func Hysteria2Singbox(hysteria2Url string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteria2Url, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	var ObfsOpts *T.Hysteria2Obfs
	ObfsOpts = nil
	// "obfs=none" (and "plain") means no obfuscation; sing-box rejects them as an obfs type
	if obfs := strings.ToLower(decoded["obfs"]); obfs != "" && obfs != "none" && obfs != "plain" {
		ObfsOpts = &T.Hysteria2Obfs{
			Type:     obfs,
			Password: decoded["obfspassword"],
		}
	}

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
	}

	SNI := decoded["sni"]
	if SNI == "" {
		SNI = decoded["hostname"]
	}
	// turnRelay, err := u.GetRelayOptions()
	// if err != nil {
	// 	return nil, err
	// }
	pass := u.Username
	if u.Password != "" {
		pass += ":" + u.Password
	}
	// port hopping: in the address ("host:443,20000-30000"), else in mport / ports
	serverPorts := u.PortRanges
	if len(serverPorts) == 0 {
		serverPorts = hysteria2PortRanges(getOneOfN(decoded, "", "mport", "ports"))
	}
	opts := &T.Hysteria2OutboundOptions{
		ServerOptions: u.GetServerOption(),
		ServerPorts:   serverPorts,
		Obfs:          ObfsOpts,
		Password:      pass,
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled: true,
				// insecure=1 and insecure=true; the core refuses it without a pin unless the user
				// allows insecure servers (allow-insecure), see HC-02
				Insecure:   toBool(getOneOfN(decoded, "", "insecure", "allowinsecure"), false),
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				ECH:        ECHOpts,
				// pinSHA256 (Hysteria 2 URI) or pcs (Xray): the server certificate's SHA-256, checked
				// even with insecure; it was dropped, so a self-signed server needed insecure alone
				CertificateSHA256: parsePinnedCertSHA256(getOneOfN(decoded, "", "pinsha256", "pcs")),
			},
		},
		// TurnRelay: turnRelay,
	}
	if hop := getOneOfN(decoded, "", "hopinterval", "hop-interval"); hop != "" {
		if d, err := time.ParseDuration(hop); err == nil {
			opts.HopInterval = badoption.Duration(d)
		} else if seconds := toInt(hop); seconds > 0 {
			opts.HopInterval = badoption.Duration(time.Duration(seconds) * time.Second)
		}
	}
	if err := applyHysteria2FinalMask(hysteria2Url, opts); err != nil {
		return nil, err
	}

	return &T.Outbound{Type: "hysteria2", Tag: u.Name, Options: opts}, nil
}
