package temptxt

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

var (
	tt        TempTxt
	updateUrl string
	client    = http.Client{}
)

func testHandler() test.HandlerFunc {
	return func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		state := request.Request{W: w, Req: r}
		m := new(dns.Msg)
		rcode := dns.RcodeServerFailure
		switch state.Name() {
		case "_acme-challenge.empty.example.com.":
			m.SetReply(r)
			rr := test.TXT(`_acme-challenge.empty.example.com.	300	IN	TXT	"fallthrough"`)
			m.Answer = []dns.RR{rr}
			m.Authoritative = true
			rcode = dns.RcodeSuccess
		}
		m.SetRcode(r, rcode)
		w.WriteMsg(m)
		return rcode, nil
	}
}

func TestMain(m *testing.M) {
	tt = TempTxt{authHeader: defaultAuthHeader, Next: testHandler()}

	tt.aliases = map[string]*Record{
		"test1.example.com.": {allowed: []*regexp.Regexp{regexp.MustCompile("^test1[0-9]$")}},
		// Used in TestServeDNS. Do not modify content.
		"test2.example.com.": {content: []string{"test2"}},
		// Used in TestUpdateAndQuery.
		"test3.example.com.": {content: []string{}, allowed: []*regexp.Regexp{regexp.MustCompile("^test13$")}},
		// Used in TestUpdateAndQueryAlias
		"test4-alias.example.com.": {content: nil, allowed: []*regexp.Regexp{regexp.MustCompile("test14")}},
		// Used in TestUPdateAndQueryForm
		"test5.example.com.": {content: []string{}, allowed: []*regexp.Regexp{regexp.MustCompile("^test15$")}},
		// Used in TestUpdateAndQueryAliasMultiple
		"test6-alias.example.com.": {content: []string{}, allowed: []*regexp.Regexp{regexp.MustCompile("^test16$")}},
		// Used in TestUpdateAndQueryMultiple
		"test7.example.com.": {content: []string{}, allowed: []*regexp.Regexp{regexp.MustCompile("^test17$")}},
		"empty.example.com.": {},
	}

	tt.records = make(map[string]*Record)
	for k, v := range tt.aliases {
		if k == "test4-alias.example.com." {
			tt.records["_acme-challenge.test4.example.com."] = v
		} else if k == "test6-alias.example.com." {
			tt.records["_acme-challenge.test6.example.com."] = v
		} else {
			tt.records["_acme-challenge."+k] = v
		}
	}

	if err := tt.OnStartup(); err != nil {
		log.Errorf("Error starting acme proxy server: %v\n", err)
		os.Exit(1)
	}
	defer tt.OnFinalShutdown()

	updateUrl = fmt.Sprintf("http://%s%s", tt.listener.Addr().String(), "/update")

	code := m.Run()
	os.Exit(code)
}

func assertStatus(want int, r *http.Response, t *testing.T) {
	if r.StatusCode != want {
		t.Helper()
		t.Errorf("Expected status code %s (%d) but got %s (%d)",
			http.StatusText(want), want, http.StatusText(r.StatusCode), r.StatusCode)
	}
}

func TestServeDNS(t *testing.T) {
	tests := []struct {
		qname      string
		qtype      uint16
		wantAnswer []string
		wantRcode  int
		wantError  error
	}{
		{
			qname: "_acme-challenge.test2.example.com.",
			qtype: dns.TypeTXT,
			wantAnswer: []string{`_acme-challenge.test2.example.com.	0	IN	TXT	"test2"`},
		},
		// Should be case insensitive
		{
			qname: "_aCME-chaLLEnge.teST2.exaMPle.com.",
			qtype: dns.TypeTXT,
			wantAnswer: []string{`_aCME-chaLLEnge.teST2.exaMPle.com.	0	IN	TXT	"test2"`},
		},
		// Should fallthrough because our config has a prefix
		{
			qname:     "test2.example.com.",
			qtype:     dns.TypeTXT,
			wantRcode: dns.RcodeServerFailure,
		},
		// Should fallthrough because content is empty
		{
			qname: "_acme-challenge.empty.example.com.",
			qtype: dns.TypeTXT,
			wantAnswer: []string{`_acme-challenge.empty.example.com.	300	IN	TXT	"fallthrough"`},
		},
	}

	for i, tc := range tests {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(tc.qname), tc.qtype)

		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		code, err := tt.ServeDNS(context.Background(), rec, req)
		if err != nil {
			t.Errorf("[%d] Unexpected error %v", i, err)
			continue
		}

		if code != tc.wantRcode {
			t.Errorf("[%d] Expected rcode %s, but got %s", i, dns.RcodeToString[tc.wantRcode], dns.RcodeToString[code])
			continue
		}

		if code != dns.RcodeSuccess {
			continue
		}

		if !rec.Msg.Authoritative {
			t.Errorf("[%d] Expected authoritative to be true", i)
		}

		if len(tc.wantAnswer) != len(rec.Msg.Answer) {
			t.Errorf("[%d] Expected %d answer(s), got %d", i, len(tc.wantAnswer), len(rec.Msg.Answer))
		} else {
			for i, have := range rec.Msg.Answer {
				if have.String() != tc.wantAnswer[i] {
					t.Errorf("[%d] Expected answer %q, got %q", i, tc.wantAnswer[i], have)
				}
			}
		}

	}
}

func TestInvalidMethod(t *testing.T) {
	response, err := http.Get(updateUrl)
	if err != nil {
		t.Fatalf("Received error message making GET: %v", err)
	}
	assertStatus(http.StatusMethodNotAllowed, response, t)
}

func TestUpdateInvalidJSON(t *testing.T) {
	req, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte("123")))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("X-Forwarded-User", "test10")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusBadRequest, resp, t)
}

func TestFormNoName(t *testing.T) {
	data := url.Values{}
	data.Set("content", "abcd")
	req, err := http.NewRequest("PUT", updateUrl, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("X-Forwarded-User", "test10")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusBadRequest, resp, t)
}

// Should set content to ""
// ALso test that the FQDN is normalized
func TestFormNoContent(t *testing.T) {
	data := url.Values{}
	data.Set("fqdn", "test1.example.com.")
	req, err := http.NewRequest("PUT", updateUrl, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("X-Forwarded-User", "test10")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusNoContent, resp, t)
}

func TestInvalidForm(t *testing.T) {
	req, err := http.NewRequest("PUT", updateUrl, strings.NewReader("domain=%&content=test"))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("X-Forwarded-User", "test10")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusBadRequest, resp, t)
}

func TestNoAuthHeader(t *testing.T) {
	req, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusUnauthorized, resp, t)
}

func TestNotFound(t *testing.T) {
	req, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"invalid", "content": "c"}`)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-User", "test12")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusNotFound, resp, t)
}

func TestUnsupportedMediaType(t *testing.T) {
	req, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test1.example.com.", "content": "c"}`)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/other")
	req.Header.Set("X-Forwarded-User", "test12")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusUnsupportedMediaType, resp, t)
}

func TestForbidden(t *testing.T) {
	req, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test1.example.com.", "content": "c"}`)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-User", "unauthorized")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusForbidden, resp, t)
}

func TestContentTooLong(t *testing.T) {
	content := strings.Repeat("a", 256)
	req, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test1.example.com.", "content": "`+content+`"}`)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-User", "test14")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}

	assertStatus(http.StatusBadRequest, resp, t)
}

func TestUpdateAndQuery(t *testing.T) {
	content := strings.Repeat("a", 255)
	updateReq, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test3.example.com.", "content": "`+content+`"}`)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("X-Forwarded-User", "test13")
	resp, err := client.Do(updateReq)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	assertStatus(http.StatusNoContent, resp, t)

	// Test query
	req := new(dns.Msg)
	req.SetQuestion("_acme-challenge.test3.example.com.", dns.TypeTXT)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := tt.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if code != dns.RcodeSuccess {
		t.Fatalf("Expected rcode %s, but got %s", dns.RcodeToString[dns.RcodeSuccess], dns.RcodeToString[code])
	}

	if rec.Msg.Authoritative != true {
		t.Errorf("Expected authoritative to be true")
	}

	if len(rec.Msg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(rec.Msg.Answer))
	} else {
		if want := fmt.Sprintf("_acme-challenge.test3.example.com.	0	IN	TXT	%q", content); rec.Msg.Answer[0].String() != want {
			t.Errorf("Expected answer %q, got %q", want, rec.Msg.Answer[0].String())
		}
	}
}

func TestUpdateAndQueryMultiple(t *testing.T) {
	content := []string{strings.Repeat("a", 255), "content2"}
	for _, c := range content {
		updateReq, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test7.example.com.", "content": "`+c+`"}`)))
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}
		updateReq.Header.Set("Content-Type", "application/json")
		updateReq.Header.Set("X-Forwarded-User", "test17")
		resp, err := client.Do(updateReq)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		assertStatus(http.StatusNoContent, resp, t)
	}

	// Test query
	req := new(dns.Msg)
	req.SetQuestion("_acme-challenge.test7.example.com.", dns.TypeTXT)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := tt.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if code != dns.RcodeSuccess {
		t.Fatalf("Expected rcode %s, but got %s", dns.RcodeToString[dns.RcodeSuccess], dns.RcodeToString[code])
	}

	if rec.Msg.Authoritative != true {
		t.Errorf("Expected authoritative to be true")
	}

	if len(rec.Msg.Answer) != 2 {
		t.Errorf("Expected 2 answers, got %d", len(rec.Msg.Answer))
	} else {
		for i, c := range content {
			if want := fmt.Sprintf("_acme-challenge.test7.example.com.	0	IN	TXT	%q", c); rec.Msg.Answer[i].String() != want {
				t.Errorf("[%d] Expected answer %q, got %q", i, want, rec.Msg.Answer[i].String())
			}
		}
	}
}

func TestUpdateAndQueryAlias(t *testing.T) {
	updateReq, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test4-alias.example.com.", "content": "alias_update"}`)))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("X-Forwarded-User", "test14")
	resp, err := client.Do(updateReq)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	assertStatus(http.StatusNoContent, resp, t)

	// Test query
	req := new(dns.Msg)
	req.SetQuestion("_acme-challenge.test4.example.com.", dns.TypeTXT)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := tt.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if code != dns.RcodeSuccess {
		t.Fatalf("Expected rcode %s, but got %s", dns.RcodeToString[dns.RcodeSuccess], dns.RcodeToString[code])
	}

	if rec.Msg.Authoritative != true {
		t.Errorf("Expected authoritative to be true")
	}

	if len(rec.Msg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(rec.Msg.Answer))
	} else {
		if want := fmt.Sprintf("_acme-challenge.test4.example.com.	0	IN	TXT	%q", "alias_update"); rec.Msg.Answer[0].String() != want {
			t.Errorf("Expected answer %q, got %q", want, rec.Msg.Answer[0].String())
		}
	}
}

func TestUpdateAndQueryAliasMultiple(t *testing.T) {
	content := []string{"alias_update1", "alias_update2"}
	for _, c := range content {
		updateReq, err := http.NewRequest("PUT", updateUrl, bytes.NewBuffer([]byte(`{"fqdn":"test6-alias.example.com.", "content": "`+c+`"}`)))
		if err != nil {
			t.Fatalf("Error creating request: %v", err)
		}
		updateReq.Header.Set("Content-Type", "application/json")
		updateReq.Header.Set("X-Forwarded-User", "test16")
		resp, err := client.Do(updateReq)
		if err != nil {
			t.Fatalf("Error sending request: %v", err)
		}
		assertStatus(http.StatusNoContent, resp, t)
	}

	// Test query
	req := new(dns.Msg)
	req.SetQuestion("_acme-challenge.test6.example.com.", dns.TypeTXT)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := tt.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if code != dns.RcodeSuccess {
		t.Fatalf("Expected rcode %s, but got %s", dns.RcodeToString[dns.RcodeSuccess], dns.RcodeToString[code])
	}

	if rec.Msg.Authoritative != true {
		t.Errorf("Expected authoritative to be true")
	}

	if len(rec.Msg.Answer) != 2 {
		t.Errorf("Expected 2 answers, got %d", len(rec.Msg.Answer))
	} else {
		for i, c := range content {
			if want := fmt.Sprintf("_acme-challenge.test6.example.com.	0	IN	TXT	%q", c); rec.Msg.Answer[i].String() != want {
				t.Errorf("[%d] Expected answer %q, got %q", i, want, rec.Msg.Answer[i].String())
			}
		}
	}
}

func TestUpdateAndQueryForm(t *testing.T) {
	content := "__token__"
	data := url.Values{}
	data.Set("fqdn", "test5.example.com.")
	data.Set("content", content)
	updateReq, err := http.NewRequest("PUT", updateUrl, strings.NewReader(data.Encode()))
	if err != nil {
		t.Fatalf("Error creating request: %v", err)
	}
	updateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	updateReq.Header.Set("X-Forwarded-User", "test15")
	resp, err := client.Do(updateReq)
	if err != nil {
		t.Fatalf("Error sending request: %v", err)
	}
	assertStatus(http.StatusNoContent, resp, t)

	// Test query
	req := new(dns.Msg)
	req.SetQuestion("_acme-challenge.test5.example.com.", dns.TypeTXT)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	code, err := tt.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	if code != dns.RcodeSuccess {
		t.Fatalf("Expected rcode %s, but got %s", dns.RcodeToString[dns.RcodeSuccess], dns.RcodeToString[code])
	}

	if rec.Msg.Authoritative != true {
		t.Errorf("Expected authoritative to be true")
	}

	if len(rec.Msg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(rec.Msg.Answer))
	} else {
		if want := fmt.Sprintf("_acme-challenge.test5.example.com.	0	IN	TXT	%q", content); rec.Msg.Answer[0].String() != want {
			t.Errorf("Expected answer %q, got %q", want, rec.Msg.Answer[0].String())
		}
	}
}

func TestCleanModified(t *testing.T) {
	tt := TempTxt{Next: testHandler(), maxAge: 4 * time.Minute, cleanInterval: 10 * time.Millisecond}

	updated := time.Now().Add(time.Duration(-5 * time.Minute))
	tt.records = map[string]*Record{
		"test-clean1.example.com.": {content: []string{"some data"}, updated: updated},
		"test-clean2.example.com.": {content: []string{"other data"}, updated: updated},
	}
	tt.setModified()

	ctx, cancel := context.WithCancel(context.Background())
	tt.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()

	for k, v := range tt.records {
		if l := len(v.content); l != 0 {
			t.Errorf("[%s] Expected length 0, but got %d", k, l)
		}
	}

	if tt.clearModified() {
		t.Errorf("Expected modified to be cleared")
	}
}

// Nothing should be cleared because the modified flag hasn't been set.
func TestCleanNotModified(t *testing.T) {
	tt := TempTxt{Next: testHandler(), maxAge: 4 * time.Minute, cleanInterval: 10 * time.Millisecond}

	updated := time.Now().Add(time.Duration(-5 * time.Minute))
	tt.records = map[string]*Record{
		"test-clean1.example.com.": {content: []string{"data"}, updated: updated},
		"test-clean2.example.com.": {content: []string{"data", "data2"}, updated: updated},
	}

	ctx, cancel := context.WithCancel(context.Background())
	tt.Run(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()

	wantLen := 1
	for k, v := range tt.records {
		if l := len(v.content); l != wantLen {
			t.Errorf(`[%s] wanted %d item(s) in content but got %d: %v`, k, wantLen, l, v.content)
		}
		wantLen++
	}
}
