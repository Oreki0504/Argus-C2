//go:build linux

package service

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/resources"
	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func query(parent context.Context, s resources.Service) protocol.ServiceReport {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	// The system bus may drop to its own service UID. Trust the fixed socket's
	// root-controlled directories, then separately verify systemd's bus UID.
	for _, path := range []string{"/run", "/run/dbus"} {
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			return protocol.ServiceReport{Code: "bus_unavailable"}
		}
	}
	var socket unix.Stat_t
	if unix.Lstat("/run/dbus/system_bus_socket", &socket) != nil || socket.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	// A fixed system socket ignores DBUS_* environment variables and never
	// accesses a session bus, an arbitrary address, or a remote endpoint.
	c, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", "/run/dbus/system_bus_socket")
	if err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	if err := c.SetDeadline(deadline); err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	u, ok := c.(*net.UnixConn)
	if !ok {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	var peer *unix.Ucred
	var peerErr error
	var current unix.Stat_t
	if unix.Lstat("/run/dbus/system_bus_socket", &current) != nil || current.Dev != socket.Dev || current.Ino != socket.Ino {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	if err := raw.Control(func(fd uintptr) { peer, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil || peerErr != nil || peer == nil || (peer.Uid != socket.Uid && socket.Uid != 0) {
		return protocol.ServiceReport{Code: "permission_denied"}
	}
	g := newGuard(c)
	conn, err := dbus.NewConn(g, dbus.WithContext(ctx))
	if err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	defer conn.Close()
	if err := conn.Auth([]dbus.Auth{dbus.AuthExternal(strconv.Itoa(os.Geteuid()))}); err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	if err := conn.Hello(); err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", dbus.FlagNoAutoStart, "org.freedesktop.systemd1").Store(&owner); err != nil {
		return protocol.ServiceReport{Code: "bus_unavailable"}
	}
	if !strings.HasPrefix(owner, ":") || len(owner) > 128 {
		return protocol.ServiceReport{Code: "invalid_response"}
	}
	var uid uint32
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetConnectionUnixUser", dbus.FlagNoAutoStart, owner).Store(&uid); err != nil || uid != 0 {
		return protocol.ServiceReport{Code: "permission_denied"}
	}
	g.owner.Store(owner)
	return queryUnit(ctx, conn, owner, s)
}
func queryUnit(ctx context.Context, conn *dbus.Conn, owner string, s resources.Service) protocol.ServiceReport {
	var path dbus.ObjectPath
	err := conn.Object(owner, "/org/freedesktop/systemd1").CallWithContext(ctx, "org.freedesktop.systemd1.Manager.GetUnit", dbus.FlagNoAutoStart, s.Unit).Store(&path)
	if err != nil {
		var busError dbus.Error
		if errors.As(err, &busError) && busError.Name == "org.freedesktop.systemd1.NoSuchUnit" {
			return protocol.ServiceReport{Code: "unit_not_loaded"}
		}
		return protocol.ServiceReport{Code: "invalid_response"}
	}
	if !path.IsValid() || !strings.HasPrefix(string(path), "/org/freedesktop/systemd1/unit/") || len(path) > 256 {
		return protocol.ServiceReport{Code: "invalid_response"}
	}
	values := make([]string, 4)
	for i, name := range []string{"Id", "LoadState", "ActiveState", "SubState"} {
		var v dbus.Variant
		if err := conn.Object(owner, path).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", dbus.FlagNoAutoStart, "org.freedesktop.systemd1.Unit", name).Store(&v); err != nil {
			return protocol.ServiceReport{Code: "invalid_response"}
		}
		value, ok := v.Value().(string)
		if !ok {
			return protocol.ServiceReport{Code: "invalid_response"}
		}
		values[i] = value
	}
	if values[0] != s.Unit {
		return protocol.ServiceReport{Code: "alias_mismatch"}
	}
	r := protocol.ServiceReport{ServiceID: s.ID, ObservedAt: time.Now().Unix(), Available: true, Unit: values[0], LoadState: values[1], ActiveState: values[2], SubState: values[3]}
	if r.Validate(time.Now().Unix()) != nil {
		return protocol.ServiceReport{Code: "invalid_response"}
	}
	return r
}
