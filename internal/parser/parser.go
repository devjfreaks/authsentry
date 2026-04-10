package parser

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

type LogEvent struct {
	Timestamp time.Time
	IP        string
	Username  string
	Success   bool
	Endpoint  string
	RawLine   string
	Format    string
}

type Parser struct {
	format string
}

func New(format string) *Parser {
	return &Parser{format: format}
}

func (p *Parser) Stream(r io.Reader) (<-chan LogEvent, <-chan error) {
	events := make(chan LogEvent, 256)
	errs := make(chan error, 64)

	go func() {
		defer close(events)
		defer close(errs)

		scanner := bufio.NewScanner(r)
		buf := make([]byte, 4*1024*1024)
		scanner.Buffer(buf, len(buf))

		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}

			ev, ok := p.parseLine(line)
			if ok {
				events <- ev
			}
		}

		if err := scanner.Err(); err != nil {
			errs <- err
		}
	}()

	return events, errs
}

func (p *Parser) parseLine(line string) (LogEvent, bool) {
	switch p.format {
	case "django":
		return parseDjango(line)
	case "laravel":
		return parseLaravel(line)
	case "rails":
		return parseRails(line)
	case "apache":
		return parseApache(line)
	case "nginx":
		return parseNginx(line)
	default:
		return parseRaw(line)
	}
}


var commonLogRe = regexp.MustCompile(
	`^([\d.a-fA-F:]+)\s+-\s+([^\s]+)\s+\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2}[^\]]*)\]\s+"([A-Z]+\s+([^\s"]+)[^"]*)" (\d{3})`,
)

func parseApache(line string) (LogEvent, bool) {
	return parseHTTPCommon(line, "apache")
}

func parseNginx(line string) (LogEvent, bool) {
	return parseHTTPCommon(line, "nginx")
}

func parseHTTPCommon(line, format string) (LogEvent, bool) {
	m := commonLogRe.FindStringSubmatch(line)
	if m == nil {
		return LogEvent{}, false
	}

	ip := m[1]
	if net.ParseIP(ip) == nil {
		return LogEvent{}, false
	}

	path := strings.ToLower(m[5])

	if !isLoginLine(path) && !isLoginLine(line) {
		return LogEvent{}, false
	}

	ts, _ := time.Parse("02/Jan/2006:15:04:05 -0700", m[3])
	status := m[6]

	success := status == "200" || status == "302"

	username := m[2]
	if username == "-" {
		username = ""
	}

	return LogEvent{
		Timestamp: ts,
		IP:        ip,
		Username:  username,
		Endpoint:  m[5],
		Success:   success,
		RawLine:   line,
		Format:    format,
	}, true
}



var djangoRe = regexp.MustCompile(
	`(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[,.]?\d*\s+(\w+)\s+[\w.]+\s+.*?(?:user\s+'?(\w+)'?).*?from\s+([\d.a-fA-F:]+)`,
)

func parseDjango(line string) (LogEvent, bool) {
	m := djangoRe.FindStringSubmatch(line)
	if m == nil {
		return LogEvent{}, false
	}
	if !isLoginLine(line) {
		return LogEvent{}, false
	}

	ip := m[4]
	if net.ParseIP(ip) == nil {
		return LogEvent{}, false
	}

	ts, _ := time.Parse("2006-01-02 15:04:05", m[1])

	success := !strings.Contains(strings.ToLower(line), "fail") &&
		!strings.Contains(strings.ToLower(line), "invalid") &&
		!strings.Contains(strings.ToLower(line), "error")

	return LogEvent{
		Timestamp: ts,
		IP:        ip,
		Username:  m[3],
		Success:   success,
		RawLine:   line,
		Format:    "django",
	}, true
}



var laravelRe = regexp.MustCompile(
	`\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*?[Ll]ogin.*?"ip":"([\d.a-fA-F:]+)".*?"(?:user|email)":"([^"]+)"`,
)

var laravelSuccessRe = regexp.MustCompile(`"success"\s*:\s*(true|false)`)

func parseLaravel(line string) (LogEvent, bool) {
	if !isLoginLine(line) {
		return LogEvent{}, false
	}

	m := laravelRe.FindStringSubmatch(line)
	if m == nil {
		return LogEvent{}, false
	}

	if net.ParseIP(m[2]) == nil {
		return LogEvent{}, false
	}

	ts, _ := time.Parse("2006-01-02 15:04:05", m[1])

	success := true
	if sm := laravelSuccessRe.FindStringSubmatch(line); sm != nil {
		success = sm[1] == "true"
	}

	return LogEvent{
		Timestamp: ts,
		IP:        m[2],
		Username:  m[3],
		Success:   success,
		RawLine:   line,
		Format:    "laravel",
	}, true
}



var railsStartRe = regexp.MustCompile(
	`Started POST "([^"]*(?:sign_in|login|session)[^"]*)" for ([\d.a-fA-F:]+) at (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})`,
)

func parseRails(line string) (LogEvent, bool) {
	m := railsStartRe.FindStringSubmatch(line)
	if m == nil {
		return LogEvent{}, false
	}

	if net.ParseIP(m[2]) == nil {
		return LogEvent{}, false
	}

	ts, _ := time.Parse("2006-01-02 15:04:05", m[3])

	return LogEvent{
		Timestamp: ts,
		IP:        m[2],
		Endpoint:  m[1],
		Success:   true,
		RawLine:   line,
		Format:    "rails",
	}, true
}


var ipRe = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{7,39})\b`)
var tsRe = regexp.MustCompile(`(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})`)

func parseRaw(line string) (LogEvent, bool) {
	if !isLoginLine(line) {
		return LogEvent{}, false
	}

	ips := ipRe.FindAllString(line, -1)
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if parsed.IsLoopback() || parsed.IsPrivate() {
			continue
		}

		ts := time.Now()

		if m := tsRe.FindStringSubmatch(line); m != nil {
			if t, err := time.Parse("2006-01-02 15:04:05", m[1]); err == nil {
				ts = t
			}
			if t, err := time.Parse("2006-01-02T15:04:05", m[1]); err == nil {
				ts = t
			}
		}

		success := !strings.Contains(strings.ToLower(line), "fail") &&
			!strings.Contains(strings.ToLower(line), "invalid") &&
			!strings.Contains(strings.ToLower(line), "401") &&
			!strings.Contains(strings.ToLower(line), "403")

		return LogEvent{
			Timestamp: ts,
			IP:        ip,
			Success:   success,
			RawLine:   line,
			Format:    "raw",
		}, true
	}

	return LogEvent{}, false
}



var loginKeywords = []string{
	"login", "signin", "sign_in", "sign-in", "logon",
	"authentication", "auth", "session", "password",
	"credential", "token", "oauth",
	"failed login", "invalid password",
}

func isLoginLine(line string) bool {
	lower := strings.ToLower(line)
	for _, kw := range loginKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}