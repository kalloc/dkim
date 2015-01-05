// +build memcache

package dkim

import (
    "fmt"
    "github.com/bradfitz/gomemcache/memcache"
)

func MemCacheGetHandler(key string) (string, error) {
    var err error
    var mc *memcache.Client
    var item *memcache.Item
    mc = memcache.New("127.0.0.1:11211")

    if item, err = mc.Get(key); err == nil {
        return string(item.Value), nil
    }
    return "", err
}
func MemCacheSetHandler(key string, value []byte) {
    mc := memcache.New("127.0.0.1:11211")
    mc.Set(&memcache.Item{Key: key, Value: value})
}

func init() {
    CustomHandlers.CacheGetHandler = MemCacheGetHandler
    CustomHandlers.CacheSetHandler = MemCacheSetHandler
}
