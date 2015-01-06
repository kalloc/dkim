package dkim

import (
	"hash"
	"net/mail"
)

type DKIM struct {
	Header            *DKIMHeader
	HeaderName        string
	HeaderNameForHash string
	RawMailHeader     mail.Header
	Hasher            *hash.Hash
	Mail              *mail.Message
	IsBodyRelaxed     bool
	IsHeaderRelaxed   bool
	Status            struct {
		HasPublicKey bool
		ValidBody    bool
		Valid        bool
	}
	PublicKey  *DKIMPublicKey
	headerHash []byte
	bodyHash   []byte
}

type DKIMHeader struct {
	Version       string            `dkim:"v", json:"version"`
	Algorithm     string            `dkim:"a", json:"algorithm"`
	Canonization  string            `dkim:"c", json:"canonization"`
	Domain        string            `dkim:"d", json:"domain"`
	Selector      string            `dkim:"s", json:"selector"`
	Headers       []string          `dkim:"h", json:"headers"`
	Unixtime      int               `dkim:"t", json:"unixtime"`
	BodyHash      []byte            `dkim:"bh", json:"body_hash"`
	Signature     []byte            `dkim:"b", json:"signature"`
	Identifier    string            `dkim:"i", json:"identifier"`
	Length        int               `dkim:"l", json:"length"`
	QueryType     string            `dkim:"q", json:"query_type"`
	Expiration    int               `dkim:"x", json:"expiration"`
	CopiedHeaders map[string]string `dkim:"z", json:"copied_headers"`
}
