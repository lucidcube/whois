package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/zonedb/zonedb"
)

func splitRecord(result string) map[string]string {
	res := make(map[string]string)
	r := regexp.MustCompile(`(?mi:^\s?([\w\s\/]*)\:(.*)$)`)
	vars := r.FindAllStringSubmatch(result, -1)
	for _, parts := range vars {
		val := strings.TrimSpace(strings.Replace(parts[2], "\n", "", -1))
		key := strings.TrimSpace(strings.Trim(strings.Replace(parts[1], "\n", "", -1), ":"))
		if len(key) > 2 && strings.Count(key, " ") < 5 && len(val) > 0 {
			res[key] = val
		}
	}
	return res
}

func ConvertRecord(result string) map[string]string {
	res := splitRecord(result)
	r := regexp.MustCompile(`(?ms)^ +([^:]+):(\n|\r\n)(.+?)(\n|\r\n)(\n|\r\n)`)
	vars := r.FindAllStringSubmatch(result, -1)
	for _, vals := range vars {
		resKey := ""
		resVal := ""
		for key, val := range vals {
			if key == 1 {
				resKey = val
			} else if key == 3 {
				tmpVal := regexp.MustCompile(`(?m)^\s*`).ReplaceAllString(val, "")

				partsVal := splitRecord(tmpVal)
				if len(partsVal) > 0 {
					for subK, subV := range partsVal {
						res[subK] = subV
					}
					resVal = ""
				} else {
					resVal = tmpVal
				}
			}
		}

		resKey = strings.TrimSpace(strings.Trim(strings.Replace(resKey, "\n", "", -1), ":"))
		resVal = strings.TrimSpace(resVal)
		if len(resKey) > 2 && strings.Count(resKey, " ") < 5 && len(resVal) > 0 {
			res[resKey] = resVal
		}

	}
	return res
}

func IsAvailable(domain string) (bool, error) {
	result, err := GetRecord(domain)
	if err != nil {
		return true, err
	}
	return IsAvailableFromWhois(domain, result), nil
}

func IsAvailableFromWhois(domain string, whoisResult string) bool {
	uppercaseResult := strings.ToUpper(whoisResult)
	return strings.Contains(uppercaseResult, "NO MATCH FOR") || strings.Contains(uppercaseResult, "DOMAIN NOT FOUND")
}

func GetRecord(domain string) (string, error) {
	return GetRecordWithTimeout(domain, 5*time.Second)
}

func GetRecordWithTimeout(domain string, timeout time.Duration) (string, error) {

	server, err := getServer(domain)
	if err != nil {
		return "", err
	}

	primaryWhois, err := getWhoisResult(server, domain, timeout)

	if strings.Contains(primaryWhois, "To single out one record") {

		primaryWhois, err = getWhoisResult(server, "="+domain, timeout)
	}

	r := regexp.MustCompile(`Whois Server: (.*)`)
	searchIndex := strings.Index(primaryWhois, "Domain Name: ")
	if searchIndex < 0 {
		searchIndex = 0
	}
	res := r.FindAllStringSubmatch(primaryWhois[searchIndex:], -1)

	fullWhois := primaryWhois

	for _, servers := range res {
		if len(servers[1]) > 1 {
			secondaryWhois, err := getWhoisResult(servers[1], domain, timeout)
			if err == nil {
				fullWhois += secondaryWhois
			}
		}
	}

	return fullWhois, nil

}

func getWhoisResult(server string, domain string, timeout time.Duration) (string, error) {
	connection, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), timeout)
	if err != nil {
		return "", err
	}

	defer connection.Close()
	connection.Write([]byte(domain + "\r\n"))

	buffer, err := ioutil.ReadAll(connection)

	if err != nil {
		return "", err
	}

	return string(buffer[:]), nil
}

func getServer(domain string) (string, error) {
	if strings.Index(domain, ".") < 0 {
		return "whois.iana.org", nil
	}
	z := zonedb.PublicZone(domain)
	if z == nil {
		return "", fmt.Errorf("no public zone found for %s", domain)
	}
	host := z.WhoisServer()
	wu := z.WhoisURL()
	if host != "" {
		return host, nil
	}
	u, err := url.Parse(wu)
	if err == nil && u.Host != "" {
		return u.Host, nil
	}
	return "", fmt.Errorf("no whois server found for %s", domain)
}
