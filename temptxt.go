package temptxt

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type TempTxt struct {
	Next    plugin.Handler
	records map[string]*Record
	// aliases stores any aliases made with txt_alias.
	// The Record should also be in records.
	aliases    map[string]*Record
	authHeader string

	cleanInterval time.Duration
	maxAge        time.Duration
	modified      uint32

	listenAddr string
	listener   net.Listener
}

type Record struct {
	content []string
	// Store the alias for deletion
	updated time.Time
	allowed []*regexp.Regexp
	mtx     sync.RWMutex
}

func (r *Record) IsAuthorized(user string) bool {
	r.mtx.RLock()
	defer r.mtx.RUnlock()
	for _, r := range r.allowed {
		if r.MatchString(user) {
			return true
		}
	}
	return false
}

type UpdateBody struct {
	FQDN    string `json:"fqdn"`
	Content string `json:"content"`
}

func (tt *TempTxt) Name() string {
	return "temptxt"
}

func (tt *TempTxt) setModified() {
	atomic.StoreUint32(&tt.modified, 1)
}

func (tt *TempTxt) clearModified() bool {
	return atomic.CompareAndSwapUint32(&tt.modified, 1, 0)
}

func (tt *TempTxt) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if state.QType() != dns.TypeTXT {
		return plugin.NextOrFailure(tt.Name(), tt.Next, ctx, w, r)
	}

	name := state.QName()

	// ToLower for DNS capitalization randomiztion
	record, ok := tt.records[strings.ToLower(name)]

	if !ok {
		return plugin.NextOrFailure(tt.Name(), tt.Next, ctx, w, r)
	}

	answers := []dns.RR{}
	record.mtx.RLock()
	if len(record.content) == 0 {
		return plugin.NextOrFailure(tt.Name(), tt.Next, ctx, w, r)
	}
	for _, c := range record.content {
		txt := new(dns.TXT)
		txt.Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeTXT, Class: dns.ClassINET}
		txt.Txt = []string{c}
		answers = append(answers, txt)
	}
	record.mtx.RUnlock()

	m := new(dns.Msg)
	m.SetReply(r)

	m.Authoritative = true
	m.Answer = answers

	w.WriteMsg(m)

	return dns.RcodeSuccess, nil
}

func (tt *TempTxt) OnStartup() error {
	var err error
	tt.listener, err = reuseport.Listen("tcp", tt.listenAddr)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/update", tt.updateHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, http.StatusText(http.StatusOK))
	})

	go func() { http.Serve(tt.listener, mux) }()

	return nil
}

func (tt *TempTxt) OnFinalShutdown() error {
	if tt.listener != nil {
		return tt.listener.Close()
	}
	return nil
}

func (tt *TempTxt) updateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	user := r.Header.Get(tt.authHeader)
	if user == "" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	ub := UpdateBody{}
	switch r.Header.Get("Content-Type") {
	case "application/json":
		if err := json.NewDecoder(r.Body).Decode(&ub); err != nil {
			log.Errorf("error decoding json: %v", err)
			http.Error(w, "error parsing body", http.StatusBadRequest)
			return
		}
	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			log.Errorf("Error decoding form: %v", err)
			http.Error(w, "error parsing form", http.StatusBadRequest)
			return
		}
		ub.FQDN = r.PostFormValue("fqdn")
		ub.Content = r.PostFormValue("content")
	default:
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}

	if ub.FQDN == "" {
		http.Error(w, "fqdn cannot be empty", http.StatusBadRequest)
		return
	}

	if len(ub.Content) > 255 {
		http.Error(w, "content is too long", http.StatusBadRequest)
		return
	}

	// Normalize
	ub.FQDN = dns.Fqdn(ub.FQDN)

	record, ok := tt.aliases[ub.FQDN]

	if !ok {
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	if !record.IsAuthorized(user) {
		log.Errorf("Unauthorized update for %q from user %q", ub.FQDN, user)
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	record.mtx.Lock()
	if ub.Content == "" {
		record.content = nil
	} else {
		record.content = append(record.content, ub.Content)
	}
	record.updated = time.Now()
	record.mtx.Unlock()

	tt.setModified()

	log.Infof("Received update for %q from user %q", ub.FQDN, user)

	w.WriteHeader(http.StatusNoContent)
}

// Clean old records from the zone
func (tt *TempTxt) Run(ctx context.Context) error {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(tt.cleanInterval):
				if tt.clearModified() {
					for _, v := range tt.records {
						v.mtx.Lock()
						if time.Since(v.updated) > tt.maxAge && len(v.content) > 0 {
							v.content = nil
						}
						v.mtx.Unlock()
					}
				}
			}
		}
	}()
	return nil
}
