package dkim

import (
    "bufio"
    "errors"
    "net/mail"
)

func ParseEml(r *bufio.Reader) (*DKIM, error) {
    var Dkim *DKIM
    var msg *mail.Message
    var raw_headers mail.Header
    var err error

    raw_headers, r = GetRawHeaders(r)

    if msg, err = mail.ReadMessage(r); err != nil {
        return nil, err
    }

    if msg.Header.Get("DKIM-Signature") == "" {
        return nil, errors.New("DKIM-Signature not found")
    }

    if Dkim, err = NewDKIM(msg); err != nil {
        return nil, err
    }
    Dkim.RawMailHeader = raw_headers
    return Dkim, nil
}
