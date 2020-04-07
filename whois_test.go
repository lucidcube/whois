package whois_test

import (
	"github.com/lucidcube/whois"
	"testing"
)

func TestWhois(t *testing.T) {
	result, err := whois.IsAvailableFromWhois("test.invalid")
	if err == nil {
		t.Errorf("invalid domain returned no error")
	} else if err.Error() != "no public zone found for test.invalid" {
		t.Errorf("invalid domain returned wrong error `%s`; should be `not an rdap enabled tld`", err)
	}
	if result == true {
		t.Errorf("invalid domain returned true; should be false")
	}

	result, err = whois.IsAvailableFromWhois("test.com")
	if err != nil {
		t.Errorf("taken domain returned an error %s", err)
	}
	if result == true {
		t.Errorf("taken domain returned true; should be false")
	}

	result, err = whois.IsAvailableFromWhois("available-lucidcube.com")
	if err != nil {
		t.Errorf("available domain returned an error %s", err)
	}
	if result == false {
		t.Errorf("available domain returned false; should be true")
	}
}
