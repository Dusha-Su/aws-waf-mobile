package solver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	http "github.com/bogdanfinn/fhttp"
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/bogdanfinn/tls-client/profiles"
	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
)

const (
	DefaultEndpoint = "3f0fb9bcf568.edge.sdk.awswaf.com/3f0fb9bcf568/a5c4893dba6e"
	DefaultDomain   = "api.coinmarketcap.com"
	DefaultAppID    = "com.coinmarketcap.android"
	DalvikUA        = "Dalvik/2.1.0 (Linux; U; Android 13; sdk_gphone64_arm64 Build/TE1A.240213.009)"
)

var signalNames = []string{
	"AndroidID", "GsfID", "ApplicationID", "MediaDRMID", "MediaDRMVendor",
	"MediaDRMVersion", "MediaDRMAlgorithms", "IsNewDevice", "WAFDeviceUUID", "DeviceID",
	"DeviceModel", "DeviceBrand", "ManufacturerName", "AndroidVersion", "SDKVersion",
	"KernelVersion", "OSFingerprint", "BatteryCapacity", "CameraCount", "CameraInfo",
	"Processor", "CPUHardware", "CPUCoreCount", "GLEVersion", "CodecsSupported",
	"TotalRAM", "TotalInternalStorage", "TotalExternalStorage", "Sensors", "NetworkInterfaces",
	"DefaultLanguage", "Timezone", "Locales", "CountryCode",
	"LastKnownLocationLatitude", "LastKnownLocationLongitude",
	"StorageEncryptionStatus", "IsPinSecurityEnabled", "SecurityProviders",
	"ADBEnabled", "DevelopmentSettingEnabled", "HttpProxy",
	"TransitionAnimationScale", "WindowAnimationScale", "DataRoamingEnabled",
	"AccessibilityEnabled", "TouchExplorationEnabled", "AlarmAlertPath",
	"DateFormat", "FontScale", "EndButtonBehaviour", "ScreenOffTimeout",
	"TextAutoReplaceEnabled", "TextAutoPunctuateEnabled", "Time12Or24",
	"SupportedInputMethods",
}

type Options struct {
	Proxy    string
	Direct   bool
	Endpoint string
	Domain   string
	AppID    string
	Timeout  int // seconds; default 12
}

type signal struct {
	Name  string      `json:"name"`
	Value signalValue `json:"value"`
}

type signalValue struct {
	Present string `json:"Present"`
}

func Mint(opt Options) (string, error) {
	opt = defaults(opt)
	c, err := newClient(opt)
	if err != nil {
		return "", err
	}
	return mint(c, opt)
}

func defaults(opt Options) Options {
	if opt.Endpoint == "" {
		opt.Endpoint = DefaultEndpoint
	}
	if opt.Domain == "" {
		opt.Domain = DefaultDomain
	}
	if opt.AppID == "" {
		opt.AppID = DefaultAppID
	}
	if opt.Timeout < 1 {
		opt.Timeout = 12
	}
	return opt
}

func newClient(opt Options) (tls_client.HttpClient, error) {
	opts := []tls_client.HttpClientOption{
		tls_client.WithTimeoutSeconds(opt.Timeout),
		tls_client.WithClientProfile(profiles.Okhttp4Android13),
		tls_client.WithNotFollowRedirects(),
		tls_client.WithInsecureSkipVerify(),
	}
	proxy := strings.TrimSpace(opt.Proxy)
	if proxy != "" {
		opts = append(opts, tls_client.WithProxyUrl(proxy))
	} else if !opt.Direct {
		return nil, fmt.Errorf("proxy required (or pass Direct: true)")
	}
	return tls_client.NewHttpClient(tls_client.NewNoopLogger(), opts...)
}

func mint(c tls_client.HttpClient, opt Options) (string, error) {
	inputsURL := "https://" + opt.Endpoint + "/inputs?client=android"
	req, err := http.NewRequest(http.MethodGet, inputsURL, nil)
	if err != nil {
		return "", err
	}
	req.Header = http.Header{
		"user-agent":      {DalvikUA},
		"connection":      {"Keep-Alive"},
		"accept-encoding": {"gzip"},
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("inputs: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("inputs HTTP %d: %s", resp.StatusCode, clip(body, 160))
	}

	var inputs struct {
		Challenge struct {
			Input string `json:"input"`
			Hmac  string `json:"hmac"`
		} `json:"challenge"`
		Difficulty uint32 `json:"difficulty"`
	}
	if err := json.Unmarshal(body, &inputs); err != nil {
		return "", fmt.Errorf("inputs json: %w", err)
	}
	if inputs.Challenge.Input == "" || inputs.Challenge.Hmac == "" {
		return "", fmt.Errorf("inputs incomplete")
	}
	diff := inputs.Difficulty
	if diff == 0 {
		diff = 4
	}

	signals, checksum := buildSignals(opt.AppID)
	solution, err := solvePoW(inputs.Challenge.Input, checksum, diff)
	if err != nil {
		return "", err
	}

	payload := map[string]any{
		"challenge": map[string]string{
			"input": inputs.Challenge.Input,
			"hmac":  inputs.Challenge.Hmac,
		},
		"solution": solution,
		"checksum": checksum,
		"client":   "android",
		"domain":   opt.Domain,
		"signals":  signals,
		"metrics": []map[string]any{
			{"name": "TokenRefreshStartTimestamp", "value": float64(time.Now().UnixMilli()), "unit": "Milliseconds"},
			{"name": "SignalExecutionTime", "value": 72.0, "unit": "Milliseconds"},
			{"name": "ChallengeExecutionTime", "value": 188.0, "unit": "Milliseconds"},
			{"name": "GetChallengeExecutionTime", "value": 343.0, "unit": "Milliseconds"},
		},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	verifyURL := "https://" + opt.Endpoint + "/verify"
	vreq, err := http.NewRequest(http.MethodPost, verifyURL, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	vreq.Header = http.Header{
		"content-type":    {"application/json"},
		"user-agent":      {DalvikUA},
		"connection":      {"Keep-Alive"},
		"accept-encoding": {"gzip"},
	}
	vresp, err := c.Do(vreq)
	if err != nil {
		return "", fmt.Errorf("verify: %w", err)
	}
	vbody, _ := io.ReadAll(vresp.Body)
	vresp.Body.Close()
	if vresp.StatusCode != 200 {
		return "", fmt.Errorf("verify HTTP %d: %s", vresp.StatusCode, clip(vbody, 200))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(vbody, &out); err != nil {
		return "", fmt.Errorf("verify json: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("empty token: %s", clip(vbody, 200))
	}
	return out.Token, nil
}

func buildSignals(appID string) ([]signal, string) {
	wafUUID := uuid.NewString()
	deviceID := uuid.NewString() + "-1"
	isNew := "false"
	if time.Now().UnixNano()%100 < 55 {
		isNew = "true"
	}
	out := make([]signal, 0, len(signalNames))
	presents := make([]string, 0, len(signalNames))
	for _, name := range signalNames {
		v := ""
		switch name {
		case "ApplicationID":
			v = appID
		case "IsNewDevice":
			v = isNew
		case "WAFDeviceUUID":
			v = wafUUID
		case "DeviceID":
			v = deviceID
		}
		out = append(out, signal{Name: name, Value: signalValue{Present: v}})
		presents = append(presents, v)
	}
	sum := sha256.Sum256([]byte(strings.Join(presents, ",")))
	return out, hex.EncodeToString(sum[:])
}

func solvePoW(challengeInput, checksum string, difficulty uint32) (string, error) {
	saltLen := 12
	if len(checksum) < saltLen {
		saltLen = len(checksum)
	}
	salt := []byte(checksum[:saltLen])
	for i := uint64(0); i < 5_000_000; i++ {
		nonce := fmt.Sprintf("%X", i)
		password := challengeInput + checksum + nonce
		key := pbkdf2.Key([]byte(password), salt, 1000, 32, sha256.New)
		if leadingZeroBits(key, difficulty) {
			return nonce, nil
		}
	}
	return "", fmt.Errorf("pow failed")
}

func leadingZeroBits(key []byte, difficulty uint32) bool {
	full := int(difficulty / 8)
	rem := int(difficulty % 8)
	if full > 0 {
		if full > len(key) {
			return false
		}
		for i := 0; i < full; i++ {
			if key[i] != 0 {
				return false
			}
		}
	}
	if rem == 0 {
		return true
	}
	if full >= len(key) {
		return false
	}
	return key[full]>>(8-rem) == 0
}

func clip(b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		return s[:n]
	}
	return s
}
