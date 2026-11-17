package ray2sing

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
)

type beepassData struct {
	Server     string `json:"server"`
	ServerPort string `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`
	Prefix     string `json:"prefix"`
	Name       string `json:"name"`
}

func fetchSSConf(parsedURL *url.URL) ([]byte, error) {

	// Construct the HTTP URL
	httpURL := "https://" + parsedURL.Host + parsedURL.Path

	// hardened: a timeout and a size limit, a hung or endless answer held the parser (HC-16)
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Get(httpURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 4<<20 {
		return nil, errors.New("ssconf: answer larger than 4 MiB")
	}
	return body, nil
}
func parseAndFetchBeePass(body []byte) (*beepassData, error) {

	// Decode JSON
	var config beepassData
	err := json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func BeepassSingbox(beepassUrl string) (*T.Outbound, error) {
	parsedURL, err := url.Parse(beepassUrl)
	if err != nil {
		return nil, err
	}
	body, err := fetchSSConf(parsedURL)
	if err != nil {
		return nil, err
	}
	decoded, err := parseAndFetchBeePass(body)
	if err != nil {
		return ShadowsocksSingbox(strings.TrimSpace(string(body)))
		// return nil, err
	}
	if decoded.Name == "" {
		decoded.Name = parsedURL.Fragment
	}
	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  decoded.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded.Server,
				ServerPort: toUInt16(decoded.ServerPort, 443),
			},
			Method:   decoded.Method,
			Password: decoded.Password,
		},
	}

	return &result, nil
}
