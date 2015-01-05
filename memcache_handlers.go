// +build memcache

package dkim

import (
    "fmt"
    "github.com/bradfitz/gomemcache/memcache"
)

func MemCacheGetHandler(key string) ([]byte, error) {
    var err error
    var mc *memcache.Client
    var item *memcache.Item
    mc = memcache.New("127.0.0.1:11211")

    if item, err = mc.Get(key); err == nil {
        return item.Value, nil
    }
    return nil, err
}
func MemCacheSetHandler(key string, value []byte) {
    if len(value) == 0 {
        return
    }
    mc := memcache.New("127.0.0.1:11211")
    mc.Set(&memcache.Item{Key: key, Value: value})
}

func init() {
    CustomHandlers.CacheGetHandler = MemCacheGetHandler
    CustomHandlers.CacheSetHandler = MemCacheSetHandler
}
