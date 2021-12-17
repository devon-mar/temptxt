package temptxt

import (
	"fmt"
	"testing"

	"github.com/coredns/caddy"
)

func TestSetup(t *testing.T) {
	c := caddy.NewTestController("dns", "temptxt")
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors but got: %v", err)
	}

	c = caddy.NewTestController("dns", `temptxt {
	clean_interval 15m
}`)
	if err := setup(c); err != nil {
		t.Fatalf("Expected no errors but got: %v", err)
	}
}

func TestConfigErrors(t *testing.T) {
	tests := []string{
		// 0. Extra after suffix
		"temptxt prefix suffix abcd",
		// 1. Invalid option
		`temptxt {
	invalid option
}`,
		// 2. Empty listen
		`temptxt {
	listen
}`,
		// 3. No domain
		`temptxt {
	txt
}`,
		// 4. No users
		`temptxt {
	txt test.example.com
}`,
		// 5. No domain
		`temptxt {
	txt_alias
}`,
		// 6. No alias
		`temptxt {
	txt_alias test.example.com
}`,
		// 7. No users
		`temptxt {
	txt_alias test.example.com alias
}`,
		// 8. Unsupported lookaround in regexp
		`temptxt {
	txt test (?!) abc
}`,
		// 9. Alias which is also a domain
		`temptxt {
	txt test.example.com abc def
	txt_alias test2.example.com test.example.com abc def
}`,
		// 10. Domain which is also an alias
		`temptxt {
	txt_alias test2.example.com test.example.com abc def
	txt test.example.com abc def
}`,
		// 11. Unexpected val to abcd
		`temptxt {
	fallthrough_empty abcd
}`,
		// 12. No value for auth_header
		`temptxt {
	auth_header
}`,
		// 13. Invalid duration for max_Age
		`temptxt {
	max_age invalid
}`,
		// 14. Invalid duration for clean_interval
		`temptxt {
	clean_interval invalid
}`,
		// 15. No duration for max_age
		`temptxt {
	max_age
}`,
		// 16. No duration for clean_interval
		`temptxt {
	clean_interval
}`,
		// 17. No port in listen
		`temptxt {
	listen 127.0.0.1
}`,
		// 18. clean_interval < 60
		`temptxt {
	clean_interval 30s
}`,
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("[%d] Expected error but got nil", i)
		}
	}
}

func getConfig(cfg string, t *testing.T) *TempTxt {
	c := caddy.NewTestController("dns", cfg)
	tt, err := parseConfig(c)
	if err != nil {
		t.Helper()
		t.Fatalf("Got an unexpected error: %v", err)
	}
	return tt
}

// A minimal config without zone or block is valid
// but is useless.
func TestMinimal(t *testing.T) {
	c := getConfig("temptxt", t)
	if c.authHeader != defaultAuthHeader {
		t.Errorf("Expected %q, but got %q", defaultAuthHeader, c.authHeader)
	}
	if c.maxAge != defaultMaxAge {
		t.Errorf("Expected %q, but got %q", defaultMaxAge, c.maxAge)
	}
	if c.cleanInterval != defaultCleanInterval {
		t.Errorf("Expected %q, but got %q", defaultCleanInterval, c.cleanInterval)
	}
	if c.listenAddr != defaultListenAddr {
		t.Errorf("Expected %q, but got %q", defaultListenAddr, c.listenAddr)
	}
}

func TestPrefix(t *testing.T) {
	// We also test that ToLower() is called on strings
	body := `temptxt _dns-challenge. {
	txt test1.eXAMple.com user1
	txt_alias test2.example.com alias.exaMPLe.com. user1
}`
	c := getConfig(body, t)

	expectedRecords := []string{
		"_dns-challenge.test1.example.com.",
		"_dns-challenge.test2.example.com.",
	}
	expectedAliases := []string{
		"test1.example.com.",
		"alias.example.com.",
	}

	if len(expectedRecords) != len(c.records) {
		t.Errorf("Expected records to have length %d, but got %d", len(expectedAliases), len(c.records))
	}

	if len(expectedAliases) != len(c.aliases) {
		t.Errorf("Expected aliases to have length %d, but got %d", len(expectedAliases), len(expectedRecords))
	}

	for _, r := range expectedRecords {
		if _, ok := c.records[r]; !ok {
			t.Errorf("Expected %q to be in records", r)
		}
	}

	for _, a := range expectedAliases {
		if _, ok := c.aliases[a]; !ok {
			t.Errorf("Expected %q to be in aliases", a)
		}
	}
}

func TestPrefixNoTrailingDot(t *testing.T) {
	body := `temptxt _dns-challenge {
	txt test1.example.com user1
	txt_alias test2.example.com alias.example.com. user1
}`
	c := getConfig(body, t)

	expectedRecords := []string{
		"_dns-challenge.test1.example.com.",
		"_dns-challenge.test2.example.com.",
	}
	expectedAliases := []string{
		"test1.example.com.",
		"alias.example.com.",
	}

	if len(expectedRecords) != len(c.records) {
		t.Errorf("Expected records to have length %d, but got %d", len(expectedAliases), len(c.records))
	}

	if len(expectedAliases) != len(c.aliases) {
		t.Errorf("Expected aliases to have length %d, but got %d", len(expectedAliases), len(expectedRecords))
	}

	for _, r := range expectedRecords {
		if _, ok := c.records[r]; !ok {
			t.Errorf("Expected %q to be in records", r)
		}
	}

	for _, a := range expectedAliases {
		if _, ok := c.aliases[a]; !ok {
			t.Errorf("Expected %q to be in aliases", a)
		}
	}
}

func TestSuffix(t *testing.T) {
	body := `temptxt "" example.com {
	txt test1 user1
	txt_alias test2 alias.example.com. user1
}`
	c := getConfig(body, t)

	expectedRecords := []string{
		"test1.example.com.",
		"test2.example.com.",
	}
	expectedAliases := []string{
		"test1.example.com.",
		"alias.example.com.",
	}

	if len(expectedRecords) != len(c.records) {
		t.Errorf("Expected records to have length %d, but got %d", len(expectedAliases), len(c.records))
	}

	if len(expectedAliases) != len(c.aliases) {
		t.Errorf("Expected aliases to have length %d, but got %d", len(expectedAliases), len(expectedRecords))
	}

	for _, r := range expectedRecords {
		if _, ok := c.records[r]; !ok {
			t.Errorf("Expected %q to be in records", r)
		}
	}

	for _, a := range expectedAliases {
		if _, ok := c.aliases[a]; !ok {
			t.Errorf("Expected %q to be in aliases", a)
		}
	}
}

func TestPrefixAndSuffix(t *testing.T) {
	body := `temptxt _dns-challenge. example.com {
	txt test1 user1
	txt_alias test2 alias.example.com. user1
}`
	c := getConfig(body, t)

	expectedRecords := []string{
		"_dns-challenge.test1.example.com.",
		"_dns-challenge.test2.example.com.",
	}
	expectedAliases := []string{
		"test1.example.com.",
		"alias.example.com.",
	}

	if len(expectedRecords) != len(c.records) {
		t.Errorf("Expected records to have length %d, but got %d", len(expectedAliases), len(c.records))
	}

	if len(expectedAliases) != len(c.aliases) {
		t.Errorf("Expected aliases to have length %d, but got %d", len(expectedAliases), len(expectedRecords))
	}

	for _, r := range expectedRecords {
		if _, ok := c.records[r]; !ok {
			t.Errorf("Expected %q to be in records", r)
		}
	}

	for _, a := range expectedAliases {
		if _, ok := c.aliases[a]; !ok {
			t.Errorf("Expected %q to be in aliases", a)
		}
	}
}

func TestNoPrefix(t *testing.T) {
	body := `temptxt {
	txt test1.example.com user1
	txt_alias test2.example.com alias.example.com. user1
}`
	c := getConfig(body, t)

	expectedRecords := []string{
		"test1.example.com.",
		"test2.example.com.",
	}
	expectedAliases := []string{
		"test1.example.com.",
		"alias.example.com.",
	}

	if len(expectedRecords) != len(c.records) {
		t.Errorf("Expected records to have length %d, but got %d", len(expectedAliases), len(c.records))
	}

	if len(expectedAliases) != len(c.aliases) {
		t.Errorf("Expected aliases to have length %d, but got %d", len(expectedAliases), len(expectedRecords))
	}

	for _, r := range expectedRecords {
		if _, ok := c.records[r]; !ok {
			t.Errorf("Expected %q to be in records", r)
		}
	}

	for _, a := range expectedAliases {
		if _, ok := c.aliases[a]; !ok {
			t.Errorf("Expected %q to be in aliases", a)
		}
	}
}

func TestAuthHeader(t *testing.T) {
	body := `temptxt {
	auth_header X-Test
}`
	c := getConfig(body, t)
	if want := "X-Test"; c.authHeader != want {
		t.Errorf("Got %s, expected %s", c.authHeader, want)
	}
}

func TestMaxAge(t *testing.T) {
	body := `temptxt {
	max_age 15m
}`
	c := getConfig(body, t)
	if want := "15m0s"; c.maxAge.String() != want {
		t.Errorf("Got %s, expected %s", c.maxAge, want)
	}
}

func TestListen(t *testing.T) {
	body := `temptxt {
	listen :8080
}`
	c := getConfig(body, t)
	if want := ":8080"; c.listenAddr != want {
		t.Errorf("Got %s, expected %s", c.listenAddr, want)
	}
}

func TestCleanInterval(t *testing.T) {
	body := `temptxt {
	clean_interval 15m
}`
	c := getConfig(body, t)
	if want := "15m0s"; c.cleanInterval.String() != want {
		t.Errorf("Got %s, expected %s", c.cleanInterval, want)
	}
}

func TestSubdomainsOne(t *testing.T) {
	body := `temptxt {
	txt test.example.com user0 user1 user2
}`
	c := getConfig(body, t)
	if len(c.records) != 1 {
		t.Errorf("Expected 1 record, got %d", len(c.records))
	}
	r0, ok := c.records["test.example.com."]
	if !ok {
		t.Fatal("Expected test.example.com. to be in records")
	}
	if len(r0.allowed) != 3 {
		t.Errorf("Expected 3 allowed users, got %d", len(r0.allowed))
	}
	for i, regexp := range r0.allowed {
		if want := fmt.Sprintf("^user%d$", i); regexp.String() != want {
			t.Errorf("Expected regexp %q, got %q", want, regexp)
		}
	}
}

// Also test that we normalize to FQDNs
func TestSubdomainsTwo(t *testing.T) {
	body := `temptxt {
	txt test.example.com user0 user1 user2
	txt test2.example.com. user0 user1 user2
}`
	c := getConfig(body, t)
	if len(c.records) != 2 {
		t.Errorf("Expected 2 records, got %d", len(c.records))
	}

	if _, ok := c.records["test.example.com."]; !ok {
		t.Errorf("Expected test.example.com. to be in records")
	}
	if _, ok := c.records["test2.example.com."]; !ok {
		t.Errorf("Expected test2.example.com. to be in records")
	}

	for k, v := range c.records {
		if len(v.allowed) != 3 {
			t.Errorf("[%s] Expected 3 allowed users, got %d", k, len(v.allowed))
		}
		for i, regexp := range v.allowed {
			if want := fmt.Sprintf("^user%d$", i); regexp.String() != want {
				t.Errorf("[%s] Expected regexp %q, got %q", k, want, regexp)
			}
		}
	}

}
