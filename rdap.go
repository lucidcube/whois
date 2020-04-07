package whois

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

type rdapBootstrap struct {
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Publication time.Time    `json:"publication"`
	Services    [][][]string `json:"services"`
}

var (
	rdapDns = map[string][]string{}
)

func RefreshMap() {
	response, err := http.Get("http://data.iana.org/rdap/dns.json")
	if err == nil {
		body, err := ioutil.ReadAll(response.Body)
		if err == nil {
			bootstrap := rdapBootstrap{}
			err := json.Unmarshal(body, &bootstrap)
			if err == nil {
				rdapDns = map[string][]string{}
				for _, svc := range bootstrap.Services {
					for _, tld := range svc[0] {
						for _, endpoint := range svc[1] {
							rdapDns[tld] = append(rdapDns[tld], endpoint)
						}
					}
				}
			}
		}
	}
}

func IsAvailableFromRdap(domain string) (bool, error) {
	split := strings.SplitN(domain, ".", 2)
	if services, ok := rdapDns[split[1]]; ok && len(services) > 0 {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(services), func(i, j int) { services[i], services[j] = services[j], services[i] })
		for len(services) > 0 {
			service := services[0]
			services = services[1:]

			response, err := http.Get(service + "domain/" + domain)
			if err == nil {
				if response.StatusCode == 404 {
					return true, nil
				}
				if response.StatusCode == 200 {
					return false, nil
				}
			}
		}
		return false, errors.New("no valid response from rdap endpoint")
	}
	return false, errors.New("not an rdap enabled tld")
}
