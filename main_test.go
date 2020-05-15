package whois_test

import (
	"github.com/lucidcube/whois"
	"strings"
	"testing"
)

var tests = []struct {
	domain          string
	expectError     string
	expectAvailable bool
}{
	{"test.invalid", "no public zone found for test.invalid", false},
	{"test.com", "", false},
	{"lucidcube-whois-test.com", "", true},
	{"lucidcube-whois-test.net", "", true},
	{"lucidcube-whois-test.org", "", true},
	{"lucidcube-whois-test.ar.com", "", true},
	{"lucidcube-whois-test.am", "", true},
	{"lucidcube-whois-test.org.au", "", true},
	{"lucidcube-whois-test.com.au", "", true},
	{"lucidcube-whois-test.net.au", "", true},
	{"lucidcube-whois-test.at", "", true},
	{"lucidcube-whois-test.be", "", true},
	{"lucidcube-whois-test.bz", "", true},
	{"lucidcube-whois-test.br.com", "", true},
	{"lucidcube-whois-test.io", "", true},
	{"lucidcube-whois-test.vg", "", true},
	{"lucidcube-whois-test.cm", "", true},
	{"lucidcube-whois-test.ab.ca", "", true},
	{"lucidcube-whois-test.bc.ca", "", true},
	{"lucidcube-whois-test.mb.ca", "", true},
	{"lucidcube-whois-test.nb.ca", "", true},
	{"lucidcube-whois-test.nf.ca", "", true},
	{"lucidcube-whois-test.nl.ca", "", true},
	{"lucidcube-whois-test.ns.ca", "", true},
	{"lucidcube-whois-test.nt.ca", "", true},
	{"lucidcube-whois-test.nu.ca", "", true},
	{"lucidcube-whois-test.on.ca", "", true},
	{"lucidcube-whois-test.pe.ca", "", true},
	{"lucidcube-whois-test.qc.ca", "", true},
	{"lucidcube-whois-test.sk.ca", "", true},
	{"lucidcube-whois-test.yk.ca", "", true},
	{"lucidcube-whois-test.ca", "", true},
	{"lucidcube-whois-test.qc.com", "", true},
	{"lucidcube-whois-test.cn", "", true},
	{"lucidcube-whois-test.com.cn", "", true},
	{"lucidcube-whois-test.net.cn", "", true},
	{"lucidcube-whois-test.org.cn", "", true},
	{"lucidcube-whois-test.cn.com", "", true},
	{"lucidcube-whois-test.cc", "", true},
	{"lucidcube-whois-test.com.co", "", true},
	{"lucidcube-whois-test.net.co", "", true},
	{"lucidcube-whois-test.nom.co", "", true},
	{"lucidcube-whois-test.co", "", true},
	{"lucidcube-whois-test.radio.fm", "", true},
	{"lucidcube-whois-test.fm", "", true},
	{"lucidcube-whois-test.fr", "", true},
	{"lucidcube-whois-test.de", "", true},
	{"lucidcube-whois-test.com.de", "", true},
	{"lucidcube-whois-test.de.com", "", true},
	{"lucidcube-whois-test.gr.com", "", true},
	{"lucidcube-whois-test.hu.com", "", true},
	{"lucidcube-whois-test.in", "", true},
	{"lucidcube-whois-test.co.in", "", true},
	{"lucidcube-whois-test.firm.in", "", true},
	{"lucidcube-whois-test.gen.in", "", true},
	{"lucidcube-whois-test.ind.in", "", true},
	{"lucidcube-whois-test.net.in", "", true},
	{"lucidcube-whois-test.org.in", "", true},
	{"lucidcube-whois-test.it", "", true},
	{"lucidcube-whois-test.jpn.com", "", true},
	{"lucidcube-whois-test.jp", "", true},
	{"lucidcube-whois-test.la", "", true},
	{"lucidcube-whois-test.li", "", true},
	{"lucidcube-whois-test.com.mx", "", true},
	{"lucidcube-whois-test.me", "", true},
	{"lucidcube-whois-test.ms", "", true},
	{"lucidcube-whois-test.nl", "", true},
	{"lucidcube-whois-test.net.nz", "", true},
	{"lucidcube-whois-test.org.nz", "", true},
	{"lucidcube-whois-test.co.nz", "", true},
	{"lucidcube-whois-test.nu", "", true},
	{"lucidcube-whois-test.no.com", "", true},
	{"lucidcube-whois-test.pw", "", true},
	{"lucidcube-whois-test.com.pe", "", true},
	{"lucidcube-whois-test.net.pe", "", true},
	{"lucidcube-whois-test.nom.pe", "", true},
	{"lucidcube-whois-test.org.pe", "", true},
	{"lucidcube-whois-test.pe", "", true},
	{"lucidcube-whois-test.ru.com", "", true},
	{"lucidcube-whois-test.ws", "", true},
	{"lucidcube-whois-test.sa.com", "", true},
	{"lucidcube-whois-test.sh", "", true},
	{"lucidcube-whois-test.ac", "", true},
	{"lucidcube-whois-test.com.sg", "", true},
	{"lucidcube-whois-test.sg", "", true},
	{"lucidcube-whois-test.za.com", "", true},
	{"lucidcube-whois-test.gs", "", true},
	{"lucidcube-whois-test.com.es", "", true},
	{"lucidcube-whois-test.nom.es", "", true},
	{"lucidcube-whois-test.org.es", "", true},
	{"lucidcube-whois-test.es", "", true},
	{"lucidcube-whois-test.se.com", "", true},
	{"lucidcube-whois-test.se.net", "", true},
	{"lucidcube-whois-test.ch", "", true},
	{"lucidcube-whois-test.com.tw", "", true},
	{"lucidcube-whois-test.idv.tw", "", true},
	{"lucidcube-whois-test.org.tw", "", true},
	{"lucidcube-whois-test.tw", "", true},
	{"lucidcube-whois-test.tm", "", true},
	{"lucidcube-whois-test.tc", "", true},
	{"lucidcube-whois-test.tv", "", true},
	{"lucidcube-whois-test.co.uk", "", true},
	{"lucidcube-whois-test.me.uk", "", true},
	{"lucidcube-whois-test.org.uk", "", true},
	{"lucidcube-whois-test.uk", "", true},
	{"lucidcube-whois-test.ltd.uk", "", true},
	{"lucidcube-whois-test.plc.uk", "", true},
	{"lucidcube-whois-test.uk.com", "", true},
	{"lucidcube-whois-test.uk.net", "", true},
	{"lucidcube-whois-test.uy.com", "", true},
	{"lucidcube-whois-test.us", "", true},
	{"lucidcube-whois-test.us.org", "", true},
	{"lucidcube-whois-test.us.com", "", true},
	{"lucidcube-whois-test.kids.us", "", true},
}

func Test(t *testing.T) {
	whois.RefreshMap()
	t.Parallel()
	for _, tt := range tests {
		tst := tt
		t.Run(tst.domain, func(t *testing.T) {
			t.Parallel()
			t.Log(tst.domain)
			result, err := whois.IsAvailable(tst.domain)
			if tst.expectError != "" {
				if err == nil {
					t.Errorf("expected an error")
				} else if err.Error() != tst.expectError {
					t.Errorf("error did not match expected `%s`; got `%s`", tst.expectError, err)
				}
			} else {
				if err != nil {
					if strings.Contains(err.Error(), "i/o timeout") {
						t.Skip(err)
					} else if err.Error() == "not authorized to use this service" {
						t.Skip(err)
					} else if strings.Contains(err.Error(), "operation timed out") {
						t.Skip(err)
					} else if strings.Contains(err.Error(), "connection reset by peer") {
						t.Skip(err)
					} else {
						t.Errorf("unexpected error `%s`", err)
					}
				} else {
					if result != tst.expectAvailable {
						t.Errorf("wrong result expected %v; got %v", tst.expectAvailable, result)
					}
				}
			}
			t.Log(tst.domain + " end")
		})
	}
}
