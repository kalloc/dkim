package dkim

import (
    "bufio"
    "os"
    "testing"
)

func Test_Ok(t *testing.T) {
    var fp *os.File

    fp, _ = os.Open("test_data/valid_1.eml")
    defer fp.Close()
    if ParseEml(bufio.NewReader(fp)).Verify() != true {
        t.Fail()
    }
}

func Test_MayBeNotOk(t *testing.T) {
    var fp *os.File

    fp, _ = os.Open("test_data/invalid_1.eml")
    defer fp.Close()
    if ParseEml(bufio.NewReader(fp)).Verify() == true {
        t.Fail()
    }
}
