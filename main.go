package whois

func IsAvailable(domain string) (bool, error) {
	rdapResult, err := IsAvailableFromRdap(domain)
	if err == nil {
		return rdapResult, err
	}

	return IsAvailableFromWhois(domain)
}
