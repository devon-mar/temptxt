package temptxt

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/miekg/dns"
)

const (
	defaultAuthHeader    = "X-Forwarded-User"
	defaultMaxAge        = 15 * time.Minute
	defaultCleanInterval = 0
	defaultListenAddr    = ":8080"
)

var log = clog.NewWithPlugin("temptxt")

func init() {
	plugin.Register("temptxt", setup)
}

func setup(c *caddy.Controller) error {
	tt, err := parseConfig(c)
	if err != nil {
		return err
	}

	if tt.cleanInterval > 0 {
		ctx, cancel := context.WithCancel(context.Background())
		tt.Run(ctx)
		c.OnShutdown(func() error { cancel(); return nil })
	}

	c.OnStartup(tt.OnStartup)
	c.OnRestart(tt.OnFinalShutdown)
	c.OnFinalShutdown(tt.OnFinalShutdown)
	c.OnRestartFailed(tt.OnStartup)

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		tt.Next = next
		return tt
	})

	return nil
}

func parseConfig(c *caddy.Controller) (*TempTxt, error) {
	tt := &TempTxt{
		authHeader:    defaultAuthHeader,
		maxAge:        defaultMaxAge,
		cleanInterval: defaultCleanInterval,
		listenAddr:    defaultListenAddr,
	}

	tt.records = make(map[string]*Record)
	tt.aliases = make(map[string]*Record)

	var prefix string
	var suffix string

	c.Next() // Skip "temptxt"

	args := c.RemainingArgs()
	if len(args) > 2 {
		return nil, c.ArgErr()
	}
	if len(args) >= 1 {
		prefix = args[0]
		if prefix != "" && !strings.HasSuffix(prefix, ".") {
			prefix += "."
		}
	}
	if len(args) == 2 {
		suffix = strings.TrimLeft(dns.Fqdn(args[1]), ".")
	}

	for c.NextBlock() {
		switch c.Val() {
		case "auth_header":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			tt.authHeader = c.Val()
		case "txt_alias":
			err := addRecord(tt, c, prefix, suffix, true)
			if err != nil {
				return nil, err
			}
		case "txt":
			err := addRecord(tt, c, prefix, suffix, false)
			if err != nil {
				return nil, err
			}
		case "max_age":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.Errf("Error parsing duration %q", c.Val())
			}
			tt.maxAge = duration
		case "clean_interval":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			duration, err := time.ParseDuration(c.Val())
			if err != nil {
				return nil, c.Errf("Error parsing duration %q", c.Val())
			}
			if duration < 60*time.Second {
				return nil, c.Errf("clean_interval must be greater than 60.")
			}
			tt.cleanInterval = duration
		case "listen":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			if _, _, err := net.SplitHostPort(c.Val()); err != nil {
				return nil, c.Errf("Invalid listen address: %v", err)
			}
			tt.listenAddr = c.Val()
		default:
			return nil, c.ArgErr()
		}
	}

	return tt, nil
}

func addRecord(tt *TempTxt, c *caddy.Controller, prefix string, suffix string, hasAlias bool) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	r := &Record{}

	alias := (dns.Fqdn(strings.ToLower(c.Val())))
	fqdn := prefix + alias + suffix
	if !hasAlias {
		alias += suffix
	}
	if _, ok := tt.aliases[fqdn]; ok {
		return c.Errf("Cannot have domain %q that is also in aliases")
	}
	tt.records[fqdn] = r

	if hasAlias {
		if !c.NextArg() {
			return c.ArgErr()
		}
		alias = dns.Fqdn(strings.ToLower(c.Val()))
		if _, ok := tt.records[alias]; ok {
			return c.Errf("Cannot have alias %q that is also in domains")
		}
	}
	tt.aliases[alias] = r

	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}
	for _, u := range args {
		regexp, err := regexp.Compile("^" + u + "$")
		if err != nil {
			return c.Errf("Unable to compile regexp: %v", err)
		}

		r.allowed = append(r.allowed, regexp)
	}
	return nil
}
