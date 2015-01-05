package godkim

import (
    "bytes"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "errors"
    "fmt"
    "github.com/golang/glog"
    "strings"
)

type DKIMPublicKey struct {
    Key       string `dkim_pk:"k", json:"key"`
    Version   string `dkim_pk:"v", json:"version"`
    Tag       string `dkim_pk:"t", json:"version"`
    PublicKey []byte `dkim_pk:"p", json:"public_key"`
}

func NewDKIMPublicKey(txt string) (*DKIMPublicKey, error) {
    var key, value, item string
    var kvs []string
    var err error
    var dkim_pk DKIMPublicKey
    for _, item = range strings.Split(strings.Replace(txt, " ", "", -1), ";") {
        kvs = strings.SplitN(item, "=", 2)
        if len(kvs) != 2 {
            continue
        }
        key = kvs[0]
        value = kvs[1]
        switch key {
        case "v":
            if value != "DKIM1" {
                return nil, errors.New("invalid version")
            }
            dkim_pk.Version = value
            break
        case "k":
            dkim_pk.Key = value
            break
        case "t":
            dkim_pk.Tag = value
            break
        case "p":
            if dkim_pk.PublicKey, err = base64.StdEncoding.DecodeString(value); err != nil {
                return nil, errors.New("invalid public")
            }
            break
        default:
            return nil, errors.New(fmt.Sprintf("unknown key %s", key))
        }
    }
    if dkim_pk.PublicKey == nil {
        return nil, errors.New("empty")
    }
    return &dkim_pk, nil
}
func (dkim *DKIM) GetPublicKey() (*DKIMPublicKey, error) {
    var domain string = dkim.Header.Selector + "._domainkey." + dkim.Header.Domain + "."
    var err error
    var text_public_key string

    if dkim.PublicKey != nil {
        return dkim.PublicKey, nil
    }
    text_public_key, err = CustomHandlers.CacheGetHandler(domain)

    if err != nil {
        glog.Infof("CACHE MISS: %s\n", domain)
        if text_public_key, err = CustomHandlers.DnsFetchHandler(domain); err != nil {
            CustomHandlers.CacheSetHandler(domain, []byte(text_public_key))
        }
    } else {
        glog.Infof("CACHE HIT: %s -> %s\n", domain, text_public_key)
    }
    if err == nil {
        return NewDKIMPublicKey(text_public_key)
    }
    return nil, errors.New("no public key found")
}

func (dkim *DKIM) Verify() bool {
    var err error
    var pk interface{}

    if dkim.Header.Domain != "" {
        dkim.Status.ValidBody = bytes.Equal(dkim.GetBodyHash(), dkim.Header.BodyHash)
        glog.Infof("dkim.BodyHash %#v\n", dkim.BodyHash)
        glog.Infof("dkim.Header.BodyHash %#v\n", dkim.Header.BodyHash)
        if dkim.PublicKey, err = dkim.GetPublicKey(); err == nil {
            dkim.Status.HasPublicKey = true

            if pk, err = x509.ParsePKIXPublicKey(dkim.PublicKey.PublicKey); err == nil {
                if err = rsa.VerifyPKCS1v15(pk.(*rsa.PublicKey), dkim.GetHasher(), dkim.GetHeaderHash(), dkim.Header.Signature); err == nil {
                    dkim.Status.Valid = true
                }
            }
        }
    }
    glog.Infof("Body: %v, Valid: %v, PK: %v\n", dkim.Status.ValidBody, dkim.Status.Valid, dkim.Status.HasPublicKey)
    return dkim.Status.ValidBody && dkim.Status.Valid && dkim.Status.HasPublicKey
}
