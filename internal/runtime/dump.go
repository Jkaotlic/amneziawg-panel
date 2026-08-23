package runtime

import (
	"fmt"
	"strconv"
	"strings"
)

type DumpPeer struct {
	PublicKey       string
	PresharedKey    string
	Endpoint        string
	AllowedIPs      []string
	LatestHandshake int64
	RxBytes         int64
	TxBytes         int64
	Keepalive       string
}

// ParseDump разбирает вывод `awg show <iface> dump`.
// Первая строка описывает устройство, остальные — пиры.
func ParseDump(s string) ([]DumpPeer, error) {
	trimmed := strings.TrimRight(s, "\n")
	if strings.TrimSpace(trimmed) == "" {
		return nil, fmt.Errorf("пустой вывод awg show dump")
	}
	lines := strings.Split(trimmed, "\n")
	peers := make([]DumpPeer, 0, len(lines)-1)
	for i, line := range lines[1:] {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			return nil, fmt.Errorf("строка пира %d: полей %d, ожидалось не меньше 8", i+2, len(f))
		}
		p := DumpPeer{
			PublicKey:    f[0],
			PresharedKey: f[1],
			Endpoint:     f[2],
			Keepalive:    f[7],
		}
		if f[3] != "(none)" && f[3] != "" {
			p.AllowedIPs = strings.Split(f[3], ",")
		}
		for idx, dst := range []*int64{&p.LatestHandshake, &p.RxBytes, &p.TxBytes} {
			v, err := strconv.ParseInt(f[4+idx], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("строка пира %d, поле %d: %w", i+2, 5+idx, err)
			}
			*dst = v
		}
		peers = append(peers, p)
	}
	return peers, nil
}
