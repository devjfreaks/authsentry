package enricher

import (
	"testing"
)

func TestScoreHostingVPNCombo(t *testing.T) {
	ip := &IPData{
		IP:  "1.2.3.4",
		ASN: ASNInfo{Type: "HOSTING", Organization: "DigitalOcean"},
		Security: Security{
			IsVPN:              true,
			VPNConfidenceScore: 90,
			ThreatScore:        85,
		},
		Location: Location{CountryCode2: "US"},
	}

	score := Score(ip, false, "admin")
	if score.Level != RiskCritical {
		t.Errorf("expected CRITICAL, got %s (score=%d)", score.Level, score.Score)
	}
	if score.Score < 75 {
		t.Errorf("expected score >= 75, got %d", score.Score)
	}
	if len(score.Reasons) == 0 {
		t.Error("expected non-empty reasons")
	}
	if score.RecommendedAction == "" {
		t.Error("expected a recommended action")
	}
}

func TestScoreCleanISP(t *testing.T) {
	ip := &IPData{
		IP:  "91.128.103.196",
		ASN: ASNInfo{Type: "ISP", Organization: "Tele2 Sverige AB"},
		Security: Security{
			ThreatScore: 0,
		},
		Location: Location{CountryCode2: "SE", CountryName: "Sweden", City: "Stockholm"},
	}

	score := Score(ip, true, "alice")
	if score.Level == RiskCritical || score.Level == RiskHigh {
		t.Errorf("clean ISP IP should not be CRITICAL/HIGH, got %s (score=%d)", score.Level, score.Score)
	}
}

func TestScoreTorNode(t *testing.T) {
	ip := &IPData{
		IP: "5.5.5.5",
		Security: Security{
			IsTor:       true,
			ThreatScore: 90,
		},
	}
	score := Score(ip, false, "root")
	if score.Level != RiskCritical {
		t.Errorf("Tor node should be CRITICAL, got %s (score=%d)", score.Level, score.Score)
	}
	if !contains(score.Indicators, "TOR") {
		t.Error("expected TOR indicator")
	}
}

func TestScoreKnownAttacker(t *testing.T) {
	ip := &IPData{
		IP: "6.6.6.6",
		Security: Security{
			IsKnownAttacker: true,
		},
	}
	score := Score(ip, false, "admin")
	if score.Level != RiskHigh && score.Level != RiskCritical {
		t.Errorf("known attacker should be HIGH or CRITICAL, got %s (score=%d)", score.Level, score.Score)
	}
	if !contains(score.Indicators, "KNOWN_ATTACKER") {
		t.Error("expected KNOWN_ATTACKER indicator")
	}
}

func TestScoreKnownAttackerWithHosting(t *testing.T) {
	ip := &IPData{
		IP:  "6.6.6.6",
		ASN: ASNInfo{Type: "HOSTING", Organization: "OVH"},
		Security: Security{
			IsKnownAttacker: true,
			IsVPN:           true,
		},
	}
	score := Score(ip, false, "admin")
	if score.Level != RiskCritical {
		t.Errorf("known attacker + hosting combo should be CRITICAL, got %s (score=%d)", score.Level, score.Score)
	}
}

func TestScoreVPNProviderNames(t *testing.T) {
	ip := &IPData{
		IP: "7.7.7.7",
		Security: Security{
			IsVPN:            true,
			VPNProviderNames: []string{"NordVPN"},
			VPNConfidenceScore: 95,
		},
	}
	score := Score(ip, false, "user")
	if score.Level == RiskInfo {
		t.Error("VPN should not be INFO level")
	}
	found := false
	for _, r := range score.Reasons {
		if len(r) > 10 {
			found = true
		}
	}
	if !found {
		t.Error("expected detailed reasons")
	}
}

func TestScoreProxyWithConfidence(t *testing.T) {
	ip := &IPData{
		IP: "8.8.4.4",
		Security: Security{
			IsProxy:              true,
			ProxyProviderNames:   []string{"Zscaler"},
			ProxyConfidenceScore: 80,
		},
	}
	score := Score(ip, true, "bob")
	if !contains(score.Indicators, "PROXY") {
		t.Error("expected PROXY indicator")
	}
}

func TestScoreNilIPData(t *testing.T) {
	score := Score(nil, false, "admin")
	if score.Level != RiskInfo {
		t.Errorf("nil IPData should return INFO, got %s", score.Level)
	}
}

func TestScoreCap(t *testing.T) {
	ip := &IPData{
		ASN:     ASNInfo{Type: "HOSTING"},
		Company: CompanyInfo{Type: "HOSTING"},
		Security: Security{
			IsVPN:           true,
			IsProxy:         true,
			IsTor:           true,
			IsKnownAttacker: true,
			IsBot:           true,
			IsSpam:          true,
			ThreatScore:     100,
		},
	}
	score := Score(ip, false, "admin")
	if score.Score > 100 {
		t.Errorf("score must be capped at 100, got %d", score.Score)
	}
}

func TestScoreComboIndicator(t *testing.T) {
	ip := &IPData{
		ASN:      ASNInfo{Type: "HOSTING", Organization: "AWS"},
		Security: Security{IsVPN: true},
	}
	score := Score(ip, false, "test")
	if !contains(score.Indicators, "COMBO_HOSTING_ANON") {
		t.Error("expected COMBO_HOSTING_ANON indicator for hosting+vpn")
	}
}

func TestScoreCloudProvider(t *testing.T) {
	ip := &IPData{
		IP:  "35.180.1.1",
		ASN: ASNInfo{Type: "BUSINESS", Organization: "Amazon"},
		Security: Security{
			IsCloudProvider:   true,
			CloudProviderName: "AWS",
		},
	}
	score := Score(ip, false, "admin")
	if !contains(score.Indicators, "HOSTING_IP") {
		t.Error("cloud provider should trigger HOSTING_IP indicator")
	}
}
