package dkim

import (
    "errors"
    "github.com/bradfitz/gomemcache/memcache"
    "github.com/miekg/dns"
    "strings"
)

func cacheGetHandler(key string) (string, error) {
    var err error
    var mc *memcache.Client
    var item *memcache.Item
    mc = memcache.New("127.0.0.1:11211")

    if item, err = mc.Get(key); err == nil {
        return string(item.Value), nil
    }
    return "", err
}
func cacheSetHandler(key string, value []byte) {
    mc := memcache.New("127.0.0.1:11211")
    mc.Set(&memcache.Item{Key: key, Value: value})
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
    CustomHandlers.CacheGetHandler = cacheGetHandler
    CustomHandlers.CacheSetHandler = cacheSetHandler
    CustomHandlers.DnsFetchHandler = dnsFetchHandler
}
