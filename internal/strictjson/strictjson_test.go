package strictjson

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictObjects(t *testing.T) {
	valid := []string{`{"name":"probe","nested":{}}`, `{"name":"\ud83d\ude00","nested":{"ok":true}}`, `{"name":"\\ud800","nested":[]}`}
	for _, input := range valid {
		var dst struct {
			Name   string          `json:"name"`
			Nested json.RawMessage `json:"nested"`
		}
		if err := Decode([]byte(input), &dst, 4096, "name", "nested"); err != nil {
			t.Fatalf("valid object rejected: %s: %v", input, err)
		}
	}
	invalid := []string{
		`{"name":"a","name":"b","nested":{}}`,
		`{"name":"a","na\u006de":"b","nested":{}}`,
		`{"Name":"a","nested":{}}`,
		`{"name":"a","nested":{"x":1,"x":2}}`,
		`{"name":"a","nested":{},"extra":1}`, `{"name":"a"}`,
		`{"name":null,"nested":{}}`, `{"name":"a","nested":{"x":null}}`,
		`{"name":"\ud800","nested":{}}`, `{"name":"\udc00","nested":{}}`,
		`{"name":"\ud800\u0000","nested":{}}`,
		`{"name":"a","nested":{}} {}`, `{"name":"a","nested":{}} garbage`,
		`{"name":12,"nested":{}}`, `{"name":"a","nested":`, `null`, `[]`,
		"{\"name\":\"\xff\",\"nested\":{}}",
		`{"name":"a","nested":` + strings.Repeat("[", 8) + "0" + strings.Repeat("]", 8) + "}",
	}
	for _, input := range invalid {
		t.Run(input, func(t *testing.T) {
			var dst struct {
				Name   string          `json:"name"`
				Nested json.RawMessage `json:"nested"`
			}
			if err := Decode([]byte(input), &dst, 4096, "name", "nested"); err == nil {
				t.Fatal("accepted invalid JSON")
			}
		})
	}
}
func TestBounds(t *testing.T) {
	var dst struct{}
	if Decode([]byte(`{}`), &dst, 1) == nil {
		t.Fatal("accepted oversized input")
	}
	if _, err := Read(bytes.NewBufferString("12345"), 4); err == nil {
		t.Fatal("accepted oversized stream")
	}
	if b, err := Read(bytes.NewBufferString("1234"), 4); err != nil || string(b) != "1234" {
		t.Fatal("exact limit rejected")
	}
}
func FuzzDecode(f *testing.F) {
	for _, seed := range []string{`{"value":1}`, `{"value":{"x":1,"x":2}}`, `{"Value":null}`, `{"value":"\ud800"}`, `{}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var dst struct {
			Value json.RawMessage `json:"value"`
		}
		if err := Decode(b, &dst, 4096, "value"); err == nil {
			if !json.Valid(b) || !json.Valid(dst.Value) || len(b) > 4096 {
				t.Fatal("accepted invalid JSON")
			}
		}
	})
}
