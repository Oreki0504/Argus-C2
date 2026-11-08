//go:build linux

package collector

import "testing"

func TestDefaultInterfacesChooseLowestMetricAndDeduplicate(t *testing.T) {
	v4 := "Iface Destination Gateway Flags RefCnt Use Metric Mask\neth1 00000000 0100000A 0003 0 0 200 00000000\neth0 00000000 0100000A 0003 0 0 100 00000000\nveth0 0100000A 00000000 0001 0 0 0 00FFFFFF\n"
	v6 := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000001 00000064 00000000 00000000 00000003 eth0\n"
	names := defaultInterfaces(v4, v6)
	if len(names) != 1 || names[0] != "eth0" {
		t.Fatal(names)
	}
	if got := defaultInterfaces("garbage", ""); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestLinuxCounterSemantics(t *testing.T) {
	total, idle, err := cpuTicks("cpu 10 20 30 40 50 60 70 80 900 1000\n")
	if err != nil || total != 360 || idle != 90 {
		t.Fatal("guest double-counted or idle incorrect", total, idle, err)
	}
	for _, s := range []string{"cpu 1 2", "cpu -1 0 0 0 0 0 0 0", "cpu 18446744073709551615 1 0 0 0 0 0 0"} {
		if _, _, err := cpuTicks(s); err == nil {
			t.Fatal("invalid CPU counters accepted")
		}
	}
	m := memory("MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	if !m.Available || m.TotalBytes != 1048576 || m.AvailableBytes != 524288 {
		t.Fatal("incorrect memory units", m)
	}
	for _, s := range []string{"MemTotal: 1 kB\n", "MemTotal: 1 kB\nMemAvailable: 2 kB", "MemTotal: 1 kB\nMemTotal: 1 kB\nMemAvailable: 0 kB", "MemTotal: 18446744073709551615 kB\nMemAvailable: 0 kB"} {
		if memory(s).Available {
			t.Fatal("invalid memory counters accepted")
		}
	}
	n := network(" lo: 12 0 0 0 0 0 0 0 34 0 0 0 0 0 0 0\n", "lo")
	if !n.Available || n.RXBytes != 12 || n.TXBytes != 34 {
		t.Fatal("incorrect network counters", n)
	}
	if network(" lo: 12 0 0 0 0 0 0 0 34 0 0 0 0 0 0 0\n", "eth0").Available {
		t.Fatal("unrequested interface reported")
	}
}
