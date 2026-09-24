package service

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func wire(t testing.TB, order binary.ByteOrder, sender string, value any) []byte {
	t.Helper()
	msg := dbus.Message{Type: dbus.TypeMethodReply, Headers: map[dbus.HeaderField]dbus.Variant{dbus.FieldReplySerial: dbus.MakeVariant(uint32(1)), dbus.FieldSender: dbus.MakeVariant(sender), dbus.FieldSignature: dbus.MakeVariant(dbus.SignatureOf(value))}, Body: []any{value}}
	var b bytes.Buffer
	if err := msg.EncodeTo(&b, order); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestFrameGuardBoundsEveryNestedLength(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, value := range []any{"test", dbus.ObjectPath("/org/freedesktop/systemd1/unit/example"), uint32(0), dbus.MakeVariant("active")} {
			frame := wire(t, order, ":1.4", value)
			if err := validateFrame(frame, ":1.4"); err != nil {
				t.Fatal("valid response rejected", err)
			}
			if err := validateFrame(frame, ":1.5"); err == nil {
				t.Fatal("untrusted sender accepted")
			}
			for i := 0; i < len(frame); i++ {
				if err := validateFrame(frame[:i], ":1.4"); err == nil {
					t.Fatalf("truncated frame accepted at %d", i)
				}
			}
		}
	}
	for _, value := range []any{[]string{"unexpected"}, dbus.MakeVariant([]uint32{1}), dbus.MakeVariant(uint32(1))} {
		if err := validateFrame(wire(t, binary.LittleEndian, ":1.4", value), ":1.4"); err == nil {
			t.Fatal("unsupported body accepted")
		}
	}
	frame := wire(t, binary.LittleEndian, "org.freedesktop.DBus", "safe")
	bodyAt := (16 + int(binary.LittleEndian.Uint32(frame[12:16])) + 7) &^ 7
	binary.LittleEndian.PutUint32(frame[bodyAt:bodyAt+4], 0xffffffff)
	if err := validateFrame(frame, ""); err == nil {
		t.Fatal("hostile nested string length reached decoder")
	}
}
func TestGuardRejectsDeclaredSizeBeforeReadingBody(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	left.SetDeadline(time.Now().Add(time.Second))
	g := newGuard(left)
	g.binary.Store(true)
	var h [16]byte
	h[0] = 'l'
	h[1] = 2
	h[3] = 1
	binary.LittleEndian.PutUint32(h[4:8], 1<<30)
	done := make(chan error, 1)
	go func() { _, err := right.Write(h[:]); done <- err }()
	if _, err := io.ReadAll(g); err == nil {
		t.Fatal("oversized response accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func FuzzDBusResponseGuard(f *testing.F) {
	f.Add(wire(f, binary.LittleEndian, "org.freedesktop.DBus", "hello"))
	f.Add(wire(f, binary.BigEndian, ":1.4", dbus.MakeVariant("active")))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 8192 {
			return
		}
		if validateFrame(data, ":1.4") == nil {
			_, _ = dbus.DecodeMessage(bytes.NewReader(data))
		}
	})
}
