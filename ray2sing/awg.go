package ray2sing

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// linkKey restores a base64 key of a link query: url.Values decodes an unescaped "+" as a space.
func linkKey(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "+")
}

// awgHeaderProtectionKey returns the key as the 64 hex digits amneziawg-go reads; links and
// configs also write it in base64, like the other WireGuard keys.
func awgHeaderProtectionKey(s string) string {
	s = linkKey(s)
	if len(s) == 64 {
		if _, err := hex.DecodeString(s); err == nil {
			return s
		}
	}
	if key, err := base64.StdEncoding.DecodeString(s); err == nil && len(key) == 32 {
		return hex.EncodeToString(key)
	}
	return s
}

// setAwg3Option sets an AmneziaWG 3.x value from a normalized key (see normalizeStr), as a link
// writes it. It returns false for any other key; a value it cannot read is left unset.
func setAwg3Option(awg *T.AwgOptions, key, value string) bool {
	known, _ := setAwg3OptionErr(awg, key, value)
	return known
}

// setAwg3OptionErr is setAwg3Option with the error of a value it cannot read.
func setAwg3OptionErr(awg *T.AwgOptions, key, value string) (bool, error) {
	value = strings.TrimSpace(value)
	ranges := map[string]*T.AwgRange{
		"contentpaddingaddition": &awg.ContentPaddingAddition,
		"rekeyaftertime":         &awg.RekeyAfterTime,
		"rekeytimeout":           &awg.RekeyTimeout,
		"rejectaftertime":        &awg.RejectAfterTime,
		"keepalivetimeout":       &awg.KeepaliveTimeout,
		"maxhandshakeattempts":   &awg.MaxHandshakeAttempts,
	}
	if target, ok := ranges[key]; ok {
		v, err := awgRangeValue(value)
		if err != nil {
			return true, fmt.Errorf("invalid %s: %w", key, err)
		}
		*target = T.AwgRange(v)
		return true, nil
	}
	switch key {
	case "headerprotectionkey":
		awg.HeaderProtectionKey = awgHeaderProtectionKey(value)
	case "randomtrailers", "disablecookies":
		b, err := parseAwgBool(value)
		if err != nil {
			return true, fmt.Errorf("invalid %s: %w", key, err)
		}
		if key == "randomtrailers" {
			awg.RandomTrailers = b
		} else {
			awg.DisableCookies = b
		}
	default:
		return false, nil
	}
	return true, nil
}

// parseAwgBool reads a boolean of a .conf or a link as amneziawg-tools does: on/off, yes/no,
// true/false, 1/0, in any case. RandomTrailers = on became false with strconv.ParseBool, and
// the handshake with a 3.1 server then failed (HC-01).
func parseAwgBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "on", "yes", "true", "1":
		return true, nil
	case "off", "no", "false", "0", "":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean: %q", value)
}

// awgRangeValue is a number or "min-max" as the UAPI reads it: the spaces of "1 - 2" removed.
func awgRangeValue(value string) (string, error) {
	value = strings.ReplaceAll(strings.TrimSpace(value), " ", "")
	if value == "" {
		return "", nil
	}
	from, to, isRange := strings.Cut(value, "-")
	if _, err := strconv.ParseUint(from, 10, 32); err != nil {
		return "", fmt.Errorf("not a number or a range: %q", value)
	}
	if isRange {
		if _, err := strconv.ParseUint(to, 10, 32); err != nil {
			return "", fmt.Errorf("not a number or a range: %q", value)
		}
	}
	return value, nil
}

// confValue is a .conf value without its trailing comment ("Jc = 4 # junk").
func confValue(value string) string {
	if i := strings.Index(value, "#"); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

// AWGSingboxTxt reads a WireGuard or AmneziaWG .conf (awg-quick): keys in any case, comments at
// the end of a line, every [Peer], and every AmneziaWG 3.1 value. A value it cannot read is an
// error, not a silent 0 (HC-01, HC-45).
func AWGSingboxTxt(content string) (*T.Endpoint, error) {
	var (
		privateKey string
		mtu        uint32
		addresses  []netip.Prefix
		awg        T.AwgOptions
		peers      []T.WireGuardPeer
		keepalives []T.AwgRange
		reserved   []uint8
	)
	section := ""
	name := ""
	atoi := func(key, value string) (int, error) {
		n, err := strconv.Atoi(value)
		if err != nil {
			return 0, fmt.Errorf("invalid %s: %q", key, value)
		}
		return n, nil
	}
	headers := map[string]*string{"h1": &awg.H1, "h2": &awg.H2, "h3": &awg.H3, "h4": &awg.H4}
	ipackets := map[string]*string{"i1": &awg.I1, "i2": &awg.I2, "i3": &awg.I3, "i4": &awg.I4, "i5": &awg.I5}
	ints := map[string]*int{"jc": &awg.Jc, "jmin": &awg.Jmin, "jmax": &awg.Jmax, "s1": &awg.S1, "s2": &awg.S2, "s3": &awg.S3, "s4": &awg.S4}
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(strings.Trim(line, "[]")))
			if section == "peer" {
				peers = append(peers, T.WireGuardPeer{})
				keepalives = append(keepalives, "")
			}
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := normalizeStr(parts[0])
		val := strings.TrimSpace(parts[1])
		if key != "name" { // a tunnel name may hold a "#"
			val = confValue(val)
		}
		var err error
		switch section {
		case "interface":
			if target, ok := ints[key]; ok {
				*target, err = atoi(parts[0], val)
				break
			}
			if target, ok := headers[key]; ok {
				*target, err = awgRangeValue(val)
				break
			}
			if target, ok := ipackets[key]; ok {
				*target = val
				break
			}
			switch key {
			case "name": // the "# Name" comment, see confNamePattern
				name = val
			case "privatekey":
				privateKey = val
			case "mtu":
				var v int
				if v, err = atoi("MTU", val); err == nil {
					mtu = uint32(v)
				}
			case "address":
				for _, add := range strings.Split(val, ",") {
					if add = strings.TrimSpace(add); add == "" {
						continue
					}
					pfx, perr := netip.ParsePrefix(add)
					if perr != nil {
						addr, aerr := netip.ParseAddr(add)
						if aerr != nil {
							return nil, fmt.Errorf("invalid Address: %w", perr)
						}
						pfx = netip.PrefixFrom(addr, addr.BitLen())
					}
					addresses = append(addresses, pfx)
				}
			default:
				_, err = setAwg3OptionErr(&awg, key, val)
			}
		case "peer":
			if len(peers) == 0 {
				continue
			}
			peer := &peers[len(peers)-1]
			switch key {
			case "publickey":
				peer.PublicKey = val
			case "presharedkey":
				peer.PreSharedKey = val
			case "allowedips":
				for _, ip := range strings.Split(val, ",") {
					if ip = strings.TrimSpace(ip); ip == "" {
						continue
					}
					pfx, perr := netip.ParsePrefix(ip)
					if perr != nil {
						return nil, fmt.Errorf("invalid AllowedIPs: %w", perr)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, pfx)
				}
			case "endpoint":
				host, portStr, serr := net.SplitHostPort(val)
				if serr != nil {
					return nil, fmt.Errorf("invalid Endpoint: %w", serr)
				}
				port, perr := strconv.ParseUint(portStr, 10, 16)
				if perr != nil || port == 0 {
					return nil, fmt.Errorf("invalid Endpoint port: %q", portStr)
				}
				peer.Address = host
				peer.Port = uint16(port)
			case "persistentkeepalive":
				var ka string
				if ka, err = awgRangeValue(val); err == nil {
					keepalives[len(keepalives)-1] = T.AwgRange(ka)
					lower, _, _ := strings.Cut(ka, "-")
					v, _ := strconv.ParseUint(lower, 10, 16)
					peer.PersistentKeepaliveInterval = uint16(v)
				}
			case "reserved": // WARP generators write the client id so
				for _, part := range strings.Split(val, ",") {
					if num, perr := strconv.ParseUint(strings.TrimSpace(part), 10, 8); perr == nil {
						reserved = append(reserved, uint8(num))
					}
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}

	if privateKey == "" {
		return nil, errors.New("missing PrivateKey")
	}
	if len(peers) == 0 {
		return nil, errors.New("missing [Peer]")
	}
	for i := range peers {
		if peers[i].Address == "" || peers[i].Port == 0 {
			return nil, errors.New("missing peer Endpoint")
		}
		if len(peers[i].AllowedIPs) == 0 {
			peers[i].AllowedIPs = T.LegacyListable[netip.Prefix]{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		}
	}
	if len(reserved) > 0 {
		peers[0].Reserved = reserved
	}
	wg := T.WireGuardEndpointOptions{
		PrivateKey: privateKey,
		Address:    badoption.Listable[netip.Prefix](addresses),
		MTU:        mtu,
		Peers:      peers,
	}
	if !awg.IsAvailble() {
		if name == "" {
			name = "wireguard"
		}
		wg.Noise = defaultWireguardNoiseOptions()
		return amneziaWireGuardEndpoint(name, wg, awg), nil
	}
	if name == "" {
		name = "awg"
	}
	endpoint := amneziaWireGuardEndpoint(name, wg, awg)
	// the keepalive as written, a range included (3.1), for the awg endpoint
	if opts, ok := endpoint.Options.(*T.AwgEndpointOptions); ok {
		for i := range opts.Peers {
			if i < len(keepalives) && keepalives[i] != "" {
				opts.Peers[i].PersistentKeepaliveInterval = keepalives[i]
			}
		}
	}
	return endpoint, nil
}

func AWGSingbox(raw string) (*T.Endpoint, error) {
	content := raw
	splt := strings.SplitN(raw, "://", 2)
	if len(splt) == 2 {
		d, _ := decodeBase64IfNeeded(splt[1])
		raw = splt[0] + "://" + d
		content = d
	}
	u, err := ParseUrl(raw, 0)

	if err != nil || len(u.Params) == 0 {
		if end, err2 := AWGSingboxTxt(content); err2 == nil {
			return end, nil
		}
		return nil, err
	}
	// "obfs=amneziawg&obfsParam={...}": the AmneziaWG values as a JSON object, as sing-box based
	// clients (Karing, ...) export them
	if param, ok := u.Params["obfsparam"]; ok {
		var values map[string]any
		if err := json.Unmarshal([]byte(param), &values); err != nil {
			return nil, fmt.Errorf("invalid obfsParam: %w", err)
		}
		for key, value := range values {
			key = normalizeStr(key)
			if _, exists := u.Params[key]; !exists {
				u.Params[key] = fmt.Sprint(value)
			}
		}
	}

	getInt := func(key string) int {
		if v, ok := u.Params[key]; ok {
			i, _ := strconv.Atoi(v)
			return i
		}
		return 0
	}

	parsePrefixes := func(raw string) (badoption.Listable[netip.Prefix], error) {
		var out []netip.Prefix
		for _, s := range strings.Split(raw, ",") {
			if s != "" {
				p, err := netip.ParsePrefix(strings.TrimSpace(s))
				if err != nil {
					// a bare address is that one address: /32, or /128 for IPv6
					addr, err2 := netip.ParseAddr(strings.TrimSpace(s))
					if err2 != nil {
						return nil, fmt.Errorf("invalid %s: %w", raw, err)
					}
					p = netip.PrefixFrom(addr, addr.BitLen())
				}
				out = append(out, p)
			}
		}
		return badoption.Listable[netip.Prefix](out), nil
	}

	addresses, err := parsePrefixes(getOneOfN(u.Params, "", "ip", "address", "localaddress"))
	if err != nil {
		return nil, err
	}

	allowedIPs, err := parsePrefixes(getOneOfN(u.Params, "", "allowedips"))
	if err != nil {
		return nil, err
	}
	if len(allowedIPs) == 0 {
		allowedIPs = badoption.Listable[netip.Prefix]([]netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		})
	}

	peer := T.AwgPeerOptions{
		Address:                     u.Hostname,
		Port:                        u.Port,
		PublicKey:                   linkKey(getOneOfN(u.Params, "", "peerpublickey", "publickey", "pub", "peerpub", "peerpk")),
		PresharedKey:                linkKey(getOneOfN(u.Params, "", "presharedkey", "psk")),
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: T.AwgRange(strings.ReplaceAll(getOneOfN(u.Params, "", "keepalive", "persistentkeepaliveinterval", "persistentkeepalive"), " ", "")),
	}
	pk := linkKey(getOneOfN(u.Params, "", "privatekey", "pk"))
	if pk == "" {
		pk = u.Username
	}
	if pk == "" {
		return nil, errors.New("missing private_key")
	}
	if peer.PublicKey == "" {
		return nil, errors.New("missing peer_public_key")
	}
	opts := T.AwgEndpointOptions{

		PrivateKey: pk,
		Address:    addresses,

		Awg: T.AwgOptions{
			Jc:   getInt("jc"),
			Jmin: getInt("jmin"),
			Jmax: getInt("jmax"),

			S1: getInt("s1"),
			S2: getInt("s2"),
			S3: getInt("s3"),
			S4: getInt("s4"),
			H1: getOneOfN(u.Params, "", "h1"),
			H2: getOneOfN(u.Params, "", "h2"),
			H3: getOneOfN(u.Params, "", "h3"),
			H4: getOneOfN(u.Params, "", "h4"),

			I1: getOneOfN(u.Params, "", "i1"),
			I2: getOneOfN(u.Params, "", "i2"),
			I3: getOneOfN(u.Params, "", "i3"),
			I4: getOneOfN(u.Params, "", "i4"),
			I5: getOneOfN(u.Params, "", "i5"),
		},
		Peers: []T.AwgPeerOptions{peer},
	}
	for key, value := range u.Params {
		setAwg3Option(&opts.Awg, key, value)
	}
	if mtuStr, ok := u.Params["mtu"]; ok {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			opts.MTU = uint32(mtu)
		}
	}
	isAwg := opts.Awg.IsAvailble()
	wgopts := T.WireGuardEndpointOptions{
		PrivateKey: opts.PrivateKey,
		Address:    opts.Address,
		Peers: []T.WireGuardPeer{
			T.WireGuardPeer{
				Address:                     peer.Address,
				Port:                        peer.Port,
				PreSharedKey:                peer.PresharedKey,
				PublicKey:                   peer.PublicKey,
				AllowedIPs:                  T.LegacyListable[netip.Prefix](peer.AllowedIPs),
				PersistentKeepaliveInterval: awgKeepaliveLower(peer.PersistentKeepaliveInterval),
			},
		},
		MTU:   uint32(toInt(getOneOfN(u.Params, "1280", "mtu"))),
		Noise: getWireGuardNoise(u.Params, false),
	}
	if isAwg {
		wgopts.MTU = opts.MTU
	}
	if reservedStr, ok := u.Params["reserved"]; ok {
		reservedParts := strings.Split(reservedStr, ",")
		for _, part := range reservedParts {
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err // Handle the error appropriately
			}
			wgopts.Peers[0].Reserved = append(wgopts.Peers[0].Reserved, uint8(num))
		}
	}
	if workerStr, ok := u.Params["workers"]; ok {
		if workers, err := strconv.Atoi(workerStr); err == nil {
			wgopts.Workers = workers
		}
	}
	tag := u.Name
	if tag == "" {
		tag = "WG"
		if isAwg {
			tag = "AWG"
		}
	}
	endpoint := amneziaWireGuardEndpoint(tag, wgopts, opts.Awg)
	if awgOpts, ok := endpoint.Options.(*T.AwgEndpointOptions); ok && len(awgOpts.Peers) == 1 {
		awgOpts.Peers[0].PersistentKeepaliveInterval = peer.PersistentKeepaliveInterval // a range too
	}
	return endpoint, nil
}

// awgKeepaliveLower is the lower end of a keepalive range, for a plain WireGuard peer.
func awgKeepaliveLower(r T.AwgRange) uint16 {
	lower, _, _ := strings.Cut(string(r), "-")
	v, _ := strconv.ParseUint(strings.TrimSpace(lower), 10, 16)
	return uint16(v)
}
