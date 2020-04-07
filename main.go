package whois

import (
	"time"
)

var (
	whoisTimeout = 5 * time.Second
)

func SetTimeout(duration time.Duration) {
	whoisTimeout = duration
	rdapClient.Timeout = duration
}

func IsAvailable(domain string) (bool, error) {
	rdapResult, err := IsAvailableFromRdap(domain)
	if err == nil {
		return rdapResult, err
	}

	return IsAvailableFromWhois(domain)
}
