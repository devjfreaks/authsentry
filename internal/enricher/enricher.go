package enricher

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/devjfreaks/authsentry/internal/cache"
	"github.com/devjfreaks/authsentry/internal/ratelimit"
)


type IPData struct {
	IP        string      `json:"ip"`
	Hostname  string      `json:"hostname"`
	Location  Location    `json:"location"`
	Network   Network     `json:"network"`
	ASN       ASNInfo     `json:"asn"`
	Company   CompanyInfo `json:"company"`
	Security  Security    `json:"security"`
	Abuse     Abuse       `json:"abuse"`
	TimeZone  TimeZone    `json:"time_zone"`
	FromCache bool        `json:"from_cache,omitempty"`
}

type Location struct {
	ContinentCode       string `json:"continent_code"`
	ContinentName       string `json:"continent_name"`
	CountryCode2        string `json:"country_code2"`
	CountryCode3        string `json:"country_code3"`
	CountryName         string `json:"country_name"`
	CountryNameOfficial string `json:"country_name_official"`
	CountryCapital      string `json:"country_capital"`
	StateProv           string `json:"state_prov"`
	StateCode           string `json:"state_code"`
	District            string `json:"district"`
	City                string `json:"city"`
	Locality            string `json:"locality"`
	AccuracyRadius      string `json:"accuracy_radius"`
	Confidence          string `json:"confidence"`
	DMACode             string `json:"dma_code"`
	Zipcode             string `json:"zipcode"`
	Latitude            string `json:"latitude"`
	Longitude           string `json:"longitude"`
	IsEU                bool   `json:"is_eu"`
	CountryFlag         string `json:"country_flag"`
	GeonameID           string `json:"geoname_id"`
	CountryEmoji        string `json:"country_emoji"`
}

type Network struct {
	ConnectionType string `json:"connection_type"`
	Route          string `json:"route"`
	IsAnycast      bool   `json:"is_anycast"`
}

type ASNInfo struct {
	ASNumber      string `json:"as_number"`
	Organization  string `json:"organization"`
	Country       string `json:"country"`
	Type          string `json:"type"` 
	Domain        string `json:"domain"`
	DateAllocated string `json:"date_allocated"`
	RIR           string `json:"rir"`
}

type CompanyInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Domain string `json:"domain"`
}

type Security struct {
	ThreatScore          int      `json:"threat_score"`
	IsTor                bool     `json:"is_tor"`
	IsProxy              bool     `json:"is_proxy"`
	ProxyProviderNames   []string `json:"proxy_provider_names"`
	ProxyConfidenceScore int      `json:"proxy_confidence_score"`
	ProxyLastSeen        string   `json:"proxy_last_seen"`
	IsResidentialProxy   bool     `json:"is_residential_proxy"`
	IsVPN                bool     `json:"is_vpn"`
	VPNProviderNames     []string `json:"vpn_provider_names"`
	VPNConfidenceScore   int      `json:"vpn_confidence_score"`
	VPNLastSeen          string   `json:"vpn_last_seen"`
	IsRelay              bool     `json:"is_relay"`
	RelayProviderName    string   `json:"relay_provider_name"`
	IsAnonymous          bool     `json:"is_anonymous"`
	IsKnownAttacker      bool     `json:"is_known_attacker"`
	IsBot                bool     `json:"is_bot"`
	IsSpam               bool     `json:"is_spam"`
	IsCloudProvider      bool     `json:"is_cloud_provider"`
	CloudProviderName    string   `json:"cloud_provider_name"`
}

type Abuse struct {
	Route        string   `json:"route"`
	Country      string   `json:"country"`
	Name         string   `json:"name"`
	Organization string   `json:"organization"`
	Kind         string   `json:"kind"`
	Address      string   `json:"address"`
	Emails       []string `json:"emails"`
	PhoneNumbers []string `json:"phone_numbers"`
}

type TimeZone struct {
	Name                  string `json:"name"`
	Offset                int    `json:"offset"`
	OffsetWithDST         int    `json:"offset_with_dst"`
	CurrentTime           string `json:"current_time"`
	CurrentTZAbbreviation string `json:"current_tz_abbreviation"`
}


type ErrFatalAPI struct {
	Msg string
}

func (e *ErrFatalAPI) Error() string { return e.Msg }

func IsFatalAPIError(err error) bool {
	var fe *ErrFatalAPI
	return errors.As(err, &fe)
}


type Enricher struct {
	apiKey  string
	cache   *cache.Cache
	limiter *ratelimit.Limiter
	client  *http.Client
}

func New(apiKey string, c *cache.Cache, rps float64, workers int) *Enricher {
	return &Enricher{
		apiKey:  apiKey,
		cache:   c,
		limiter: ratelimit.NewLimiter(rps, int(rps)+1),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (e *Enricher) Enrich(ctx context.Context, ip string) (*IPData, error) {
	if cached, err := e.cache.Get(ip); err == nil && cached != nil {
		return mapToIPData(cached, true), nil
	}

	if e.apiKey == "" {
		return &IPData{IP: ip}, nil
	}

	if err := e.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit wait: %w", err)
	}

	data, err := e.fetchAPI(ctx, ip)
	if err != nil {
		return nil, err
	}

	_ = e.cache.Set(ip, data)

	return mapToIPData(data, false), nil
}

func (e *Enricher) fetchAPI(ctx context.Context, ip string) (map[string]interface{}, error) {
	url := fmt.Sprintf(
		"https://api.ipgeolocation.io/v3/ipgeo?apiKey=%s&ip=%s&include=security,abuse,dma_code,geo_accuracy,hostname",
		e.apiKey, ip,
	)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "authsentry/1.0")

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, err
	}


	var check struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &check)

	switch resp.StatusCode {
	case 200:
		if check.Message != "" {
			return nil, fmt.Errorf("api error: %s", check.Message)
		}
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			return nil, fmt.Errorf("json decode: %w", err)
		}
		return result, nil

	case 401, 403:
		msg := fmt.Sprintf("invalid API key (HTTP %d)", resp.StatusCode)
		if check.Message != "" {
			msg = fmt.Sprintf("invalid API key (HTTP %d): %s", resp.StatusCode, check.Message)
		}
		return nil, &ErrFatalAPI{Msg: msg}

	case 429:
		msg := "rate limited by API (HTTP 429)"
		if check.Message != "" {
			msg = fmt.Sprintf("rate limited by API (HTTP 429): %s", check.Message)
		}
		return nil, fmt.Errorf("%s", msg)

	default:
		if check.Message != "" {
			return nil, fmt.Errorf("api returned HTTP %d: %s", resp.StatusCode, check.Message)
		}
		return nil, fmt.Errorf("api returned HTTP %d: %s", resp.StatusCode, string(body))
	}
}

func mapToIPData(m map[string]interface{}, fromCache bool) *IPData {
	b, _ := json.Marshal(m)
	var d IPData
	json.Unmarshal(b, &d)
	d.FromCache = fromCache
	return &d
}
