package whois_test

import "github.com/lucidcube/whois"
import "testing"

func TestRdap(t *testing.T) {
	whois.RefreshMap()

	result, err := whois.IsAvailableFromRdap("test.invalid")
	if err == nil {
		t.Errorf("invalid domain returned no error")
	} else if err.Error() != "not an rdap enabled tld" {
		t.Errorf("invalid domain returned wrong error; should be `not an rdap enabled tld`")
	}
	if result == true {
		t.Errorf("invalid domain returned true; should be false")
	}

	result, err = whois.IsAvailableFromRdap("test.com")
	if err != nil {
		t.Errorf("taken domain returned an error %s", err.Error())
	}
	if result == true {
		t.Errorf("taken domain returned true; should be false")
	}

	result, err = whois.IsAvailableFromRdap("available-lucidcube.com")
	if err != nil {
		t.Errorf("available domain returned an error %s", err.Error())
	}
	if result == false {
		t.Errorf("available domain returned false; should be true")
	}
}
