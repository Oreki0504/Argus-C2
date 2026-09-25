//go:build windows

package adminclient

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// User-scoped DPAPI; never CRYPTPROTECT_LOCAL_MACHINE or interactive prompts.
func protect(b []byte, decrypt bool) ([]byte, error) {
	if len(b) == 0 || len(b) > 8192 {
		return nil, errors.New("invalid protected session size")
	}
	input := windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
	entropy := []byte("argus-c2/admin-session-file/v1")
	extra := windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}
	var output windows.DataBlob
	var err error
	if decrypt {
		err = windows.CryptUnprotectData(&input, nil, &extra, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	} else {
		err = windows.CryptProtectData(&input, nil, &extra, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	if output.Size == 0 || output.Size > 8192 || output.Data == nil {
		return nil, errors.New("invalid protected session")
	}
	view := unsafe.Slice(output.Data, int(output.Size))
	result := append([]byte{}, view...)
	clear(view)
	return result, nil
}
func seal(b []byte) ([]byte, error)   { return protect(b, false) }
func unseal(b []byte) ([]byte, error) { return protect(b, true) }
