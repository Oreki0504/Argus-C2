package protocol

import (
	"errors"
	"net"

	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type Process struct {
	PID   int    `json:"pid"`
	Name  string `json:"name"`
	State string `json:"state"`
	UID   uint32 `json:"uid"`
}
type Processes struct {
	Available bool      `json:"available"`
	Truncated bool      `json:"truncated"`
	Items     []Process `json:"items"`
}
type Listener struct {
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     uint16 `json:"port"`
}
type Listeners struct {
	Coverage  string     `json:"coverage"`
	Available bool       `json:"available"`
	Truncated bool       `json:"truncated"`
	Items     []Listener `json:"items"`
}

func ValidateProcesses(b []byte) error {
	var v Processes
	if e := strictjson.Decode(b, &v, MaxResultBytes, "available", "truncated", "items"); e != nil {
		return e
	}
	if v.Items == nil || len(v.Items) > 256 || !v.Available && len(v.Items) > 0 {
		return errors.New("invalid process list")
	}
	for _, p := range v.Items {
		if p.PID <= 0 || !CleanText(p.Name, 64) || len(p.State) != 1 {
			return errors.New("invalid process")
		}
	}
	return nil
}
func ValidateListeners(b []byte) error {
	var v Listeners
	if e := strictjson.Decode(b, &v, MaxResultBytes, "available", "truncated", "coverage", "items"); e != nil {
		return e
	}
	if v.Items == nil || len(v.Items) > 256 || !v.Available && len(v.Items) > 0 {
		return errors.New("invalid listeners")
	}
	if !oneOf(v.Coverage, "complete", "partial", "unavailable") || (v.Coverage == "unavailable") != (!v.Available) || v.Coverage == "complete" && v.Truncated {
		return errors.New("invalid listener coverage")
	}
	for _, p := range v.Items {
		if (p.Protocol != "tcp" && p.Protocol != "tcp6" && p.Protocol != "udp" && p.Protocol != "udp6") || net.ParseIP(p.Address) == nil {
			return errors.New("invalid listener")
		}
	}
	return nil
}
