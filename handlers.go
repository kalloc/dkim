package dkim

var CustomHandlers struct {
    CacheGetHandler func(string) ([]byte, error)
    CacheSetHandler func(string, []byte)
    DnsFetchHandler func(string) ([]byte, error)
}
