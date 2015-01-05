package dkim

import (
    "bufio"
    "fmt"
    "net/mail"
)

func ParseEml(r *bufio.Reader) *DKIM {
    var Dkim *DKIM
    var msg *mail.Message
    var raw_headers mail.Header
    var err error

    raw_headers, r = GetRawHeaders(r)

    if msg, err = mail.ReadMessage(r); err != nil {
        fmt.Printf("%#v\n", err)
        return nil
    }

    if msg.Header.Get("DKIM-Signature") == "" {
        return nil
    }

    if Dkim, err = NewDKIM(msg); err != nil {
        panic(err)
    }
    Dkim.RawMailHeader = raw_headers
    return Dkim
}
