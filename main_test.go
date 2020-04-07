package whois_test

import (
	"github.com/lucidcube/whois"
	"testing"
)

func Test(t *testing.T) {
	whois.RefreshMap()

	result, err := whois.IsAvailable("test.invalid")
	if err == nil {
		t.Errorf("invalid domain returned no error")
	} else if err.Error() != "no public zone found for test.invalid" {
		t.Errorf("invalid domain returned wrong error `%s`; should be `no public zone found`", err)
	}
	if result == true {
		t.Errorf("invalid domain returned true; should be false")
	}

	result, err = whois.IsAvailable("test.com")
	if err != nil {
		t.Errorf("taken domain returned an error %s", err.Error())
	}
	if result == true {
		t.Errorf("taken domain returned true; should be false")
	}

	result, err = whois.IsAvailable("available-lucidcube.com")
	if err != nil {
		t.Errorf("available domain returned an error %s", err.Error())
	}
	if result == false {
		t.Errorf("available domain returned false; should be true")
	}
}
