package godkim

import (
    "bufio"
    "fmt"
    "net/mail"
)

func ParseEml(r *bufio.Reader) *DKIM {
    var dkim *DKIM
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

    if dkim, err = NewDKIM(msg); err != nil {
        panic(err)
    }
    dkim.RawMailHeader = raw_headers
    return dkim
}
