package service

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"unicode/utf8"
)

var errFrame = errors.New("unapproved or oversized D-Bus response")

// The general D-Bus decoder accepts larger and more varied messages than these
// queries need. Validate bounded frames and all nested lengths before passing
// bytes to it. No arrays, file descriptors, incoming calls, or arbitrary variants
// are accepted. Only the bus daemon and the verified root systemd owner may send.
type guardedConn struct {
	net.Conn
	binary          atomic.Bool
	owner           atomic.Value
	authLeft, total int
	frame           []byte
}

func newGuard(c net.Conn) *guardedConn {
	g := &guardedConn{Conn: c, authLeft: 4096}
	g.owner.Store("")
	return g
}
func (g *guardedConn) Write(p []byte) (int, error) {
	if bytes.Equal(p, []byte("BEGIN\r\n")) {
		g.binary.Store(true)
	}
	return g.Conn.Write(p)
}
func (g *guardedConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !g.binary.Load() {
		if g.authLeft == 0 {
			return 0, errFrame
		}
		if len(p) > g.authLeft {
			p = p[:g.authLeft]
		}
		n, err := g.Conn.Read(p)
		g.authLeft -= n
		return n, err
	}
	if len(g.frame) == 0 {
		var header [16]byte
		if _, err := io.ReadFull(g.Conn, header[:]); err != nil {
			return 0, err
		}
		order, err := byteOrder(header[0])
		if err != nil {
			return 0, err
		}
		body, hdr := uint64(order.Uint32(header[4:8])), uint64(order.Uint32(header[12:16]))
		total := 16 + ((hdr + 7) &^ uint64(7))
		total += body
		if hdr > 4096 || body > 4096 || total > 8192 || uint64(g.total)+total > 65536 {
			return 0, errFrame
		}
		frame := make([]byte, int(total))
		copy(frame, header[:])
		if _, err := io.ReadFull(g.Conn, frame[16:]); err != nil {
			return 0, err
		}
		if err := validateFrame(frame, g.owner.Load().(string)); err != nil {
			return 0, err
		}
		g.total += len(frame)
		g.frame = frame
	}
	n := copy(p, g.frame)
	g.frame = g.frame[n:]
	return n, nil
}
func byteOrder(b byte) (binary.ByteOrder, error) {
	if b == 'l' {
		return binary.LittleEndian, nil
	}
	if b == 'B' {
		return binary.BigEndian, nil
	}
	return nil, errFrame
}

type cursor struct {
	b     []byte
	pos   int
	order binary.ByteOrder
}

func (c *cursor) align(n int) bool {
	end := (c.pos + n - 1) &^ (n - 1)
	if end > len(c.b) {
		return false
	}
	for _, v := range c.b[c.pos:end] {
		if v != 0 {
			return false
		}
	}
	c.pos = end
	return true
}
func (c *cursor) number() (uint32, bool) {
	if !c.align(4) || len(c.b)-c.pos < 4 {
		return 0, false
	}
	v := c.order.Uint32(c.b[c.pos : c.pos+4])
	c.pos += 4
	return v, true
}
func (c *cursor) signature() (string, bool) {
	if len(c.b)-c.pos < 2 {
		return "", false
	}
	n := int(c.b[c.pos])
	c.pos++
	if n > 1 || len(c.b)-c.pos < n+1 || c.b[c.pos+n] != 0 {
		return "", false
	}
	s := string(c.b[c.pos : c.pos+n])
	c.pos += n + 1
	return s, true
}
func (c *cursor) text() (string, bool) {
	n, ok := c.number()
	if !ok || n > 256 || uint64(len(c.b)-c.pos) < uint64(n)+1 {
		return "", false
	}
	b := c.b[c.pos : c.pos+int(n)]
	if c.b[c.pos+int(n)] != 0 || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", false
	}
	c.pos += int(n) + 1
	return string(b), true
}
func validateFrame(frame []byte, owner string) error {
	if len(frame) < 16 || frame[3] != 1 || frame[1] < 2 || frame[1] > 4 {
		return errFrame
	}
	order, err := byteOrder(frame[0])
	if err != nil {
		return err
	}
	hlen, blen := int64(order.Uint32(frame[12:16])), int64(order.Uint32(frame[4:8]))
	bodyAt := (16 + hlen + 7) &^ int64(7)
	if hlen > 4096 || blen > 4096 || bodyAt+blen != int64(len(frame)) {
		return errFrame
	}
	c := cursor{b: frame[:16+hlen], pos: 16, order: order}
	fields := map[byte]bool{}
	signature, sender := "", ""
	for c.pos < len(c.b) {
		if !c.align(8) {
			return errFrame
		}
		if c.pos == len(c.b) {
			break
		}
		field := c.b[c.pos]
		c.pos++
		if field < 1 || field > 9 || fields[field] {
			return errFrame
		}
		fields[field] = true
		sig, ok := c.signature()
		if !ok {
			return errFrame
		}
		want := map[byte]string{1: "o", 2: "s", 3: "s", 4: "s", 5: "u", 6: "s", 7: "s", 8: "g", 9: "u"}[field]
		if sig != want {
			return errFrame
		}
		switch sig {
		case "s", "o":
			v, ok := c.text()
			if !ok {
				return errFrame
			}
			if field == 7 {
				sender = v
			}
		case "u":
			v, ok := c.number()
			if !ok || field == 9 && v != 0 {
				return errFrame
			}
		case "g":
			v, ok := c.signature()
			if !ok {
				return errFrame
			}
			signature = v
		}
	}
	if sender != "org.freedesktop.DBus" && (owner == "" || sender != owner) {
		return errFrame
	}
	for _, b := range frame[16+hlen : bodyAt] {
		if b != 0 {
			return errFrame
		}
	}
	c = cursor{b: frame[bodyAt:], order: order}
	switch signature {
	case "s", "o":
		if _, ok := c.text(); !ok {
			return errFrame
		}
	case "u":
		if _, ok := c.number(); !ok {
			return errFrame
		}
	case "v":
		sig, ok := c.signature()
		if !ok || sig != "s" {
			return errFrame
		}
		if _, ok := c.text(); !ok {
			return errFrame
		}
	case "":
	default:
		return errFrame
	}
	if c.pos != len(c.b) {
		return errFrame
	}
	return nil
}
