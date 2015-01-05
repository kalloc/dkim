package dkim

import (
    "errors"
    "github.com/miekg/dns"
    "strings"
)

var localCache map[string][]byte

func LocalCacheGetHandler(key string) (string, error) {
    var value []byte = localCache[key]
    if value == nil {
        return "", errors.New("Not found")
    }
    return string(value), nil
}
func LocalCacheSetHandler(key string, value []byte) {
    localCache[key] = value
}

func dnsFetchHandler(domain string) (string, error) {
    var response *dns.Msg
    var txt *dns.TXT
    var ok bool
    var client *dns.Client = new(dns.Client)
    var msg *dns.Msg = new(dns.Msg)
    var err error

    msg.SetQuestion(domain, dns.TypeTXT)
    if response, _, err = client.Exchange(msg, "8.8.8.8:53"); err != nil {
        return "", err
    }
    for _, rr := range response.Answer {
        if txt, ok = rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
            return strings.Join(txt.Txt, ""), nil
        }
    }
    return "", errors.New("not found")
}

var CustomHandlers struct {
    CacheGetHandler func(string) (string, error)
    CacheSetHandler func(string, []byte)
    DnsFetchHandler func(string) (string, error)
}

func init() {
    localCache = make(map[string][]byte, 0)
    if CustomHandlers.CacheGetHandler == nil {
        CustomHandlers.CacheGetHandler = LocalCacheGetHandler
        CustomHandlers.CacheSetHandler = LocalCacheSetHandler
    }
    CustomHandlers.DnsFetchHandler = dnsFetchHandler
}
