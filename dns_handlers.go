package dkim

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

func dnsFetchHandler(domain string) ([]byte, error) {
	var response *dns.Msg
	var txt *dns.TXT
	var ok bool
	var client *dns.Client = new(dns.Client)
	var msg *dns.Msg = new(dns.Msg)
	var err error

	msg.SetQuestion(domain, dns.TypeTXT)
	if response, _, err = client.Exchange(msg, dnsHost); err != nil {
		return nil, err
	}
	for _, rr := range response.Answer {
		if txt, ok = rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
			return []byte(strings.Join(txt.Txt, "")), nil
		}
	}
	return nil, errors.New("not found")
}

var dnsHost string = "8.8.8.8:53"

func SetDNS(ns string) {
	dnsHost = ns
}

func init() {
	CustomHandlers.DnsFetchHandler = dnsFetchHandler
}
