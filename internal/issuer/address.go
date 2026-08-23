// Package issuer выпускает клиентские конфиги и применяет изменения к
// серверному конфигу с соблюдением инварианта раздела 6 спеки.
package issuer

import (
	"fmt"
	"net/netip"
	"strings"
)

// HostIP возвращает адрес без маски.
func HostIP(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

// AllocateAddress выбирает наименьший свободный адрес в подсети сервера.
//
// Занятыми считаются адрес самого сервера и всё, что перечислено в used
// (AllowedIPs живых пиров и адреса отключённых пиров из peers.json).
// Элементы used могут быть склеены запятыми (AllowedIPs пира); функция
// разбивает каждый элемент и помечает каждый адрес занятым.
// Сетевой и широковещательный адреса не выдаются. Исчерпание пула —
// явная ошибка, а не молчаливое переиспользование чужого адреса (7.4 спеки).
func AllocateAddress(serverAddr string, used []string) (string, error) {
	pfx, err := netip.ParsePrefix(strings.TrimSpace(serverAddr))
	if err != nil {
		return "", fmt.Errorf("Address сервера %q не разбирается: %w", serverAddr, err)
	}
	if !pfx.Addr().Is4() {
		return "", fmt.Errorf("Address сервера %q: поддерживается только IPv4", serverAddr)
	}
	taken := map[netip.Addr]bool{pfx.Addr(): true}
	for _, u := range used {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		// Разбиваем по запятой, так как used может содержать склеенные AllowedIPs
		for _, part := range strings.Split(u, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			a, err := netip.ParseAddr(HostIP(part))
			if err != nil {
				// Чужие сети (CIDR) и иностранные адреса не помечаются как занятые.
				// Если адрес собственной подсети не разбирается — это может быть
				// опечатка в конфиге; игнорируем осознанно.
				continue
			}
			taken[a] = true
		}
	}
	network := pfx.Masked()
	bits := pfx.Bits()
	if bits > 30 {
		return "", fmt.Errorf("подсеть /%d слишком мала: свободных адресов нет", bits)
	}
	if bits <= 8 {
		return "", fmt.Errorf("подсеть /%d слишком велика: минимум /9 для туннеля", bits)
	}
	// Первый хост = сеть + 1, последний = широковещательный - 1.
	total := uint32(1) << uint(32-bits)
	base := network.Addr()
	for i := uint32(1); i < total-1; i++ {
		cand := addOffset(base, i)
		if !taken[cand] {
			return cand.String() + "/32", nil
		}
	}
	// ErrInvalidInput, а не внутренняя ошибка: исчерпание пула — состояние,
	// которое оператор может исправить сам (удалить неиспользуемого пира,
	// расширить подсеть), и он обязан прочитать причину, а не «внутреннюю
	// ошибку». Остальные ошибки этой функции (неразбираемый или заведомо
	// негодный Address сервера) — именно поломка конфигурации сервера и
	// остаются внутренними.
	return "", fmt.Errorf("%w: в подсети %s не осталось свободных адресов", ErrInvalidInput, pfx)
}

func addOffset(a netip.Addr, n uint32) netip.Addr {
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	v += n
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
