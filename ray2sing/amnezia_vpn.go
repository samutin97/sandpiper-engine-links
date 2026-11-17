package ray2sing

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// maxAmneziaVPNSize bounds what a vpn:// key may unpack to: a profile is a few KiB (one with
// long I1/I2 about 12 KiB), and a zip bomb must not take the core's memory.
const maxAmneziaVPNSize = 1 << 20

// AmneziaVPNSingbox reads an AmneziaVPN key, vpn://: base64url of a qCompress block (4 bytes of
// big-endian length, then zlib) of a JSON whose containers[].awg.last_config is a JSON string
// with the AmneziaWG .conf in its "config". The .conf is read by AWGSingboxTxt; the name is the
// key's description. Containers other than AmneziaWG/WireGuard (OpenVPN, Xray of AmneziaVPN) are
// not read (HC-11).
func AmneziaVPNSingbox(link string) (*T.Endpoint, error) {
	data, err := amneziaVPNJSON(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(link), "vpn://")))
	if err != nil {
		return nil, fmt.Errorf("vpn:// key: %w", err)
	}
	var key struct {
		Containers       []map[string]json.RawMessage `json:"containers"`
		DefaultContainer string                       `json:"defaultContainer"`
		Description      string                       `json:"description"`
	}
	if err := json.Unmarshal(data, &key); err != nil {
		return nil, fmt.Errorf("vpn:// key: %w", err)
	}
	// the default container first, then the others in order
	ordered := make([]map[string]json.RawMessage, 0, len(key.Containers))
	for _, c := range key.Containers {
		if containerName(c) == key.DefaultContainer {
			ordered = append([]map[string]json.RawMessage{c}, ordered...)
		} else {
			ordered = append(ordered, c)
		}
	}
	for _, container := range ordered {
		for _, protocol := range []string{"awg", "wireguard"} {
			raw, ok := container[protocol]
			if !ok {
				continue
			}
			var settings struct {
				LastConfig string `json:"last_config"`
			}
			if json.Unmarshal(raw, &settings) != nil || settings.LastConfig == "" {
				continue
			}
			var last struct {
				Config string `json:"config"`
			}
			if err := json.Unmarshal([]byte(settings.LastConfig), &last); err != nil || last.Config == "" {
				continue
			}
			endpoint, err := AWGSingboxTxt(last.Config)
			if err != nil {
				return nil, fmt.Errorf("vpn:// key, %s: %w", containerName(container), err)
			}
			if name := strings.TrimSpace(key.Description); name != "" {
				endpoint.Tag = name
			}
			return endpoint, nil
		}
	}
	return nil, errors.New("vpn:// key: no AmneziaWG or WireGuard configuration in it")
}

func containerName(container map[string]json.RawMessage) string {
	var name string
	json.Unmarshal(container["container"], &name)
	return name
}

// amneziaVPNJSON unpacks the JSON of a vpn:// key: base64url with or without padding, then a
// qCompress block, a bare zlib stream, or plain JSON.
func amneziaVPNJSON(payload string) ([]byte, error) {
	var raw []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if raw, err = enc.DecodeString(payload); err == nil {
			break
		}
	}
	if err != nil {
		return nil, errors.New("not base64")
	}
	if json.Valid(raw) {
		return raw, nil
	}
	stream := raw
	if len(raw) > 4 && raw[4] == 0x78 { // qCompress: the length, then the zlib header
		if size := binary.BigEndian.Uint32(raw[:4]); size > maxAmneziaVPNSize {
			return nil, fmt.Errorf("declares %d bytes, more than %d", size, maxAmneziaVPNSize)
		}
		stream = raw[4:]
	}
	reader, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, fmt.Errorf("not compressed JSON: %w", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, maxAmneziaVPNSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAmneziaVPNSize {
		return nil, fmt.Errorf("unpacks to more than %d bytes", maxAmneziaVPNSize)
	}
	return data, nil
}
