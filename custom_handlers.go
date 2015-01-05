package dkim

import (
    "errors"
    lru "github.com/golang/groupcache/lru"
    "github.com/miekg/dns"
    "strings"
)

var localCache *lru.Cache = lru.New(1000)

func LocalCacheGetHandler(key string) ([]byte, error) {
    var value interface{}
    var ok bool

    if value, ok = localCache.Get(key); !ok {
        return nil, errors.New("Not found")
    }
    return value.([]byte), nil
}
func LocalCacheSetHandler(key string, value []byte) {
    if len(value) == 0 {
        return
    }
    localCache.Add(key, value)
}

func dnsFetchHandler(domain string) ([]byte, error) {
    var response *dns.Msg
    var txt *dns.TXT
    var ok bool
    var client *dns.Client = new(dns.Client)
    var msg *dns.Msg = new(dns.Msg)
    var err error

    msg.SetQuestion(domain, dns.TypeTXT)
    if response, _, err = client.Exchange(msg, "8.8.8.8:53"); err != nil {
        return nil, err
    }
    for _, rr := range response.Answer {
        if txt, ok = rr.(*dns.TXT); ok && len(txt.Txt) > 0 {
            return []byte(strings.Join(txt.Txt, "")), nil
        }
    }
    return nil, errors.New("not found")
}

var CustomHandlers struct {
    CacheGetHandler func(string) ([]byte, error)
    CacheSetHandler func(string, []byte)
    DnsFetchHandler func(string) ([]byte, error)
}

func init() {
    if CustomHandlers.CacheGetHandler == nil {
        CustomHandlers.CacheGetHandler = LocalCacheGetHandler
        CustomHandlers.CacheSetHandler = LocalCacheSetHandler
    }
    CustomHandlers.DnsFetchHandler = dnsFetchHandler
}
