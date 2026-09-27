//go:build linux

package localfile

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialACLHasOnlyOneNonRootReader(t *testing.T) {
	b := make([]byte, 44)
	binary.LittleEndian.PutUint32(b, 2)
	for i, entry := range [][3]uint32{{1, 4, 0xffffffff}, {2, 4, 1001}, {4, 0, 0xffffffff}, {16, 4, 0xffffffff}, {32, 0, 0xffffffff}} {
		binary.LittleEndian.PutUint16(b[4+8*i:], uint16(entry[0]))
		binary.LittleEndian.PutUint16(b[6+8*i:], uint16(entry[1]))
		binary.LittleEndian.PutUint32(b[8+8*i:], entry[2])
	}
	if !onlyReaderACL(b, 1001) {
		t.Fatal("systemd named-user read ACL rejected")
	}
	for _, offset := range []int{0, 4, 6, 12, 14, 16, 20, 22, 28, 30, 36, 38} {
		altered := append([]byte{}, b...)
		altered[offset] ^= 1
		if onlyReaderACL(altered, 1001) {
			t.Fatal("accepted changed ACL entry", offset)
		}
	}
	if onlyReaderACL(b, 1002) || onlyReaderACL(b, 0) || onlyReaderACL(append(b, make([]byte, 8)...), 1001) || onlyReaderACL(b[:43], 1001) {
		t.Fatal("accepted other reader or malformed ACL")
	}
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("secret"), 0440); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", filepath.Dir(path))
	if _, err := Read(path, 10, true); err == nil {
		t.Fatal("environment hint bypassed ordinary group-readable key rejection")
	}
}
