package whois_test

import (
	"github.com/lucidcube/whois"
	"strings"
	"testing"
)

func TestWhois(t *testing.T) {
	t.Parallel()
	for _, tt := range tests {
		tst := tt
		t.Run(tst.domain, func(t *testing.T) {
			t.Parallel()
			t.Log(tst.domain)
			result, err := whois.IsAvailableFromWhois(tst.domain)
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
