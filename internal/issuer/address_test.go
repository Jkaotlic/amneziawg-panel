package issuer_test

import (
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

func TestAllocateFirstFree(t *testing.T) {
	got, err := issuer.AllocateAddress("10.0.0.1/24", []string{"10.0.0.2/32", "10.0.0.3/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.4/32" {
		t.Errorf("получено %q, ожидалось 10.0.0.4/32", got)
	}
}

func TestAllocateFillsHoles(t *testing.T) {
	got, err := issuer.AllocateAddress("10.0.0.1/24", []string{"10.0.0.2/32", "10.0.0.4/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.3/32" {
		t.Errorf("получено %q, ожидалось 10.0.0.3/32 — дыра в нумерации не заполнена", got)
	}
}

func TestAllocateSkipsServerAddressItself(t *testing.T) {
	got, err := issuer.AllocateAddress("10.0.0.1/24", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.2/32" {
		t.Errorf("получено %q — адрес сервера должен быть занят", got)
	}
}

func TestAllocateSkipsNetworkAndBroadcast(t *testing.T) {
	// /30 = 10.0.0.0 сеть, .1 сервер, .2 свободен, .3 широковещательный
	got, err := issuer.AllocateAddress("10.0.0.1/30", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.2/32" {
		t.Errorf("получено %q, ожидалось 10.0.0.2/32", got)
	}
	if _, err := issuer.AllocateAddress("10.0.0.1/30", []string{"10.0.0.2"}); err == nil {
		t.Fatal("ожидалось исчерпание пула: .0 и .3 использовать нельзя")
	}
}

func TestAllocatePoolExhaustedIsExplicitError(t *testing.T) {
	_, err := issuer.AllocateAddress("10.0.0.1/31", nil)
	if err == nil {
		t.Fatal("ожидалась явная ошибка, а не молчаливое переиспользование чужого адреса")
	}
	if !strings.Contains(err.Error(), "свободн") {
		t.Errorf("ошибка невнятная: %v", err)
	}
}

func TestAllocateAcceptsUsedWithoutMask(t *testing.T) {
	got, err := issuer.AllocateAddress("10.0.0.1/24", []string{"10.0.0.2", "10.0.0.3/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.4/32" {
		t.Errorf("получено %q", got)
	}
}

func TestAllocateIgnoresForeignSubnets(t *testing.T) {
	// AllowedIPs пира может содержать чужие сети — они не занимают адреса пула.
	got, err := issuer.AllocateAddress("10.0.0.1/24", []string{"192.168.9.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.2/32" {
		t.Errorf("получено %q", got)
	}
}

func TestAllocateRejectsBadServerAddress(t *testing.T) {
	for _, bad := range []string{"", "10.0.0.1", "не-адрес/24", "10.0.0.1/99"} {
		if _, err := issuer.AllocateAddress(bad, nil); err == nil {
			t.Errorf("Address %q: ожидалась ошибка", bad)
		}
	}
}

func TestHostIP(t *testing.T) {
	if got := issuer.HostIP("10.0.0.2/32"); got != "10.0.0.2" {
		t.Errorf("HostIP = %q", got)
	}
	if got := issuer.HostIP("10.0.0.2"); got != "10.0.0.2" {
		t.Errorf("HostIP без маски = %q", got)
	}
}

func TestAllocateRejectsSubnetTooLarge(t *testing.T) {
	// /9 и шире не имеют смысла для туннеля VPN
	for _, bad := range []string{"10.0.0.1/8", "192.168.0.1/7", "0.0.0.1/0"} {
		_, err := issuer.AllocateAddress(bad, nil)
		if err == nil {
			t.Errorf("Address %q: ожидалась ошибка про размер подсети", bad)
		} else if !strings.Contains(err.Error(), "велика") {
			t.Errorf("Address %q: неправильная ошибка %v (должна упоминать размер)", bad, err)
		}
	}
	// /9 допустимо
	if _, err := issuer.AllocateAddress("10.0.0.1/9", nil); err != nil {
		t.Errorf("Address /9 должна быть допустимой, ошибка: %v", err)
	}
}

func TestAllocateHandlesCommaSeparatedAllowedIPs(t *testing.T) {
	// AllowedIPs может быть склеено запятыми: "10.0.0.5/32, 10.0.0.6/32"
	// Обе адреса должны быть помечены занятыми
	got, err := issuer.AllocateAddress("10.0.0.1/24", []string{"10.0.0.5/32, 10.0.0.6/32"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.2/32" {
		t.Errorf("получено %q, ожидалось 10.0.0.2/32", got)
	}

	// Попытка выдать .5 и .6: оба заняты запятой, должны пропуститься
	got2, err := issuer.AllocateAddress("10.0.0.1/24", []string{"10.0.0.5, 10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	if got2 != "10.0.0.3/32" {
		t.Errorf("получено %q, ожидалось 10.0.0.3/32 (оба адреса из запятой должны быть заняты)", got2)
	}
}

func TestAllocateExhausts24(t *testing.T) {
	// Регрессионный тест на реалистичный размер пула: /24 имеет 253 доступных адреса.
	// Проверяем: первый = .2, последний = .254, всего выдано 253, цикл не вешается.

	server := "10.0.0.1/24"
	got := make([]string, 0, 253)
	used := []string{} // начинаем с пустого пула

	// Выдаём адреса по одному, добавляя каждый в used для следующей итерации
	iterCount := 0
	maxIter := 300 // защита от бесконечного цикла (should not hit)
	for iterCount < maxIter {
		addr, err := issuer.AllocateAddress(server, used)
		if err != nil {
			// Исчерпание пула — ожидаемо
			break
		}
		got = append(got, addr)
		used = append(used, addr)
		iterCount++
	}

	if iterCount >= maxIter {
		t.Fatalf("цикл вешается на /24: не исчерпал пул за %d итераций", maxIter)
	}

	if len(got) != 253 {
		t.Errorf("выдано %d адресов, ожидалось 253 для /24", len(got))
	}
	if got[0] != "10.0.0.2/32" {
		t.Errorf("первый адрес = %q, ожидалось 10.0.0.2/32", got[0])
	}
	if got[len(got)-1] != "10.0.0.254/32" {
		t.Errorf("последний адрес = %q, ожидалось 10.0.0.254/32", got[len(got)-1])
	}
	// Ни .0 (сеть), ни .1 (сервер), ни .255 (broadcast) не должны быть в выданных
	for _, addr := range got {
		ip := issuer.HostIP(addr)
		switch ip {
		case "10.0.0.0", "10.0.0.1", "10.0.0.255":
			t.Errorf("выдан запрещённый адрес %q", ip)
		}
	}
}
