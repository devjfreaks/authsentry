package enricher

import (
	"fmt"
	"strings"
)

type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
	RiskInfo     RiskLevel = "INFO"
)

type RiskScore struct {
	Level             RiskLevel `json:"level"`
	Score             int       `json:"score"` 
	Reasons           []string  `json:"reasons"`
	RecommendedAction string    `json:"recommended_action"`
	Indicators        []string  `json:"indicators"`
}

func Score(ip *IPData, success bool, username string) RiskScore {
	if ip == nil {
		return RiskScore{Level: RiskInfo, Score: 0, Reasons: []string{"No enrichment data"}}
	}

	score := 0
	var reasons []string
	var indicators []string

	asnType := strings.ToUpper(ip.ASN.Type)
	compType := strings.ToUpper(ip.Company.Type)
	org := ip.ASN.Organization
	if org == "" {
		org = ip.Company.Name
	}

	isHostingASN := asnType == "HOSTING" || compType == "HOSTING" || ip.Security.IsCloudProvider
	if isHostingASN {
		score += 30
		reasons = append(reasons, fmt.Sprintf("Hosting/datacenter ASN (%s)", org))
		indicators = append(indicators, "HOSTING_IP")
	}


	if ip.Security.IsTor {
		score += 50
		reasons = append(reasons, "Tor exit node")
		indicators = append(indicators, "TOR")
	}

	if ip.Security.IsVPN {
		score += 25
		detail := "VPN detected"
		if len(ip.Security.VPNProviderNames) > 0 {
			detail = fmt.Sprintf("VPN detected (%s)", ip.Security.VPNProviderNames[0])
		}
		if ip.Security.VPNConfidenceScore > 0 {
			detail += fmt.Sprintf(" — confidence %d%%", ip.Security.VPNConfidenceScore)
		}
		reasons = append(reasons, detail)
		indicators = append(indicators, "VPN")
	}


	if ip.Security.IsProxy {
		score += 20
		detail := "Proxy detected"
		if len(ip.Security.ProxyProviderNames) > 0 {
			detail = fmt.Sprintf("Proxy detected (%s)", ip.Security.ProxyProviderNames[0])
		}
		if ip.Security.ProxyConfidenceScore > 0 {
			detail += fmt.Sprintf(" — confidence %d%%", ip.Security.ProxyConfidenceScore)
		}
		reasons = append(reasons, detail)
		indicators = append(indicators, "PROXY")
	}


	if ip.Security.IsResidentialProxy && !ip.Security.IsProxy {
		score += 10
		reasons = append(reasons, "Residential proxy detected")
		indicators = append(indicators, "RESIDENTIAL_PROXY")
	}


	if ip.Security.IsRelay {
		score += 20
		detail := "Relay detected"
		if ip.Security.RelayProviderName != "" {
			detail = fmt.Sprintf("Relay detected (%s)", ip.Security.RelayProviderName)
		}
		reasons = append(reasons, detail)
		indicators = append(indicators, "RELAY")
	}
	if ip.Security.IsAnonymous && !ip.Security.IsVPN && !ip.Security.IsProxy && !ip.Security.IsRelay {
		score += 15
		reasons = append(reasons, "Anonymous IP (unclassified anonymizer)")
		indicators = append(indicators, "ANONYMOUS")
	}


	if ip.Security.IsKnownAttacker {
		score += 45
		reasons = append(reasons, "IP is a known attacker")
		indicators = append(indicators, "KNOWN_ATTACKER")
	}


	if ip.Security.IsBot {
		score += 25
		reasons = append(reasons, "IP is a known bot")
		indicators = append(indicators, "BOT")
	}
	if ip.Security.IsSpam {
		score += 20
		reasons = append(reasons, "IP is a known spam source")
		indicators = append(indicators, "SPAM")
	}


	if ip.Security.ThreatScore >= 80 {
		score += 20
		reasons = append(reasons, fmt.Sprintf("High threat score: %d/100", ip.Security.ThreatScore))
		indicators = append(indicators, "HIGH_THREAT_SCORE")
	} else if ip.Security.ThreatScore >= 50 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("Elevated threat score: %d/100", ip.Security.ThreatScore))
		indicators = append(indicators, "MED_THREAT_SCORE")
	}


	if isHostingASN && (ip.Security.IsVPN || ip.Security.IsProxy || ip.Security.IsTor) {
		score += 15
		reasons = append(reasons, "Hosting ASN + anonymization combo (credential stuffing pattern)")
		indicators = append(indicators, "COMBO_HOSTING_ANON")
	}

	if !success && score > 20 {
		score += 10
		reasons = append(reasons, "Failed login from suspicious IP")
	}
	if score > 100 {
		score = 100
	}

	level := scoreToLevel(score)
	action := recommendedAction(level, indicators)

	return RiskScore{
		Level:             level,
		Score:             score,
		Reasons:           reasons,
		RecommendedAction: action,
		Indicators:        indicators,
	}
}

func scoreToLevel(score int) RiskLevel {
	switch {
	case score >= 75:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskInfo
	}
}

func recommendedAction(level RiskLevel, indicators []string) string {
	hasTor := contains(indicators, "TOR")
	hasAttacker := contains(indicators, "KNOWN_ATTACKER")
	hasCombo := contains(indicators, "COMBO_HOSTING_ANON")

	switch level {
	case RiskCritical:
		if hasTor || hasAttacker {
			return "Block IP immediately. Add to blocklist. Review associated accounts for compromise."
		}
		if hasCombo {
			return "Block IP. Likely credential stuffing. Enforce MFA. Audit affected accounts."
		}
		return "Block IP immediately. Investigate all associated sessions."
	case RiskHigh:
		return "Challenge with CAPTCHA or MFA. Monitor account for 24h. Consider temporary block."
	case RiskMedium:
		return "Log and monitor. Enforce MFA for this session. Alert account owner."
	case RiskLow:
		return "Log for trend analysis. No immediate action required."
	default:
		return "No action required."
	}
}

func contains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
