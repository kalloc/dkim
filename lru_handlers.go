package dkim

import (
	"errors"
	lru "github.com/golang/groupcache/lru"
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

func init() {
	if CustomHandlers.CacheGetHandler == nil {
		CustomHandlers.CacheGetHandler = LocalCacheGetHandler
		CustomHandlers.CacheSetHandler = LocalCacheSetHandler
	}
}
