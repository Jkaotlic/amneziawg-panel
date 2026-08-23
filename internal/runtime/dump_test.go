package runtime_test

import (
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// Реальный формат: первая строка — устройство, дальше по строке на пира,
// поля разделены табуляцией.
const sampleDump = "c2VydmVyLXByaXY=\tc2VydmVyLXB1Yg==\t51820\toff\n" +
	"bWUtcHVi\tbWUtcHNr\t203.0.113.207:59487\t10.0.0.2/32\t1754049600\t11400000\t2300000\toff\n" +
	"cGFwYS1wdWI=\tcGFwYS1wc2s=\t(none)\t10.0.0.3/32\t0\t0\t0\t25\n"

func TestParseDumpSkipsDeviceLine(t *testing.T) {
	peers, err := runtime.ParseDump(sampleDump)
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("пиров %d, ожидалось 2", len(peers))
	}
}

func TestParseDumpFields(t *testing.T) {
	peers, _ := runtime.ParseDump(sampleDump)
	p := peers[0]
	if p.PublicKey != "bWUtcHVi" {
		t.Errorf("PublicKey = %q", p.PublicKey)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.0.0.2/32" {
		t.Errorf("AllowedIPs = %v", p.AllowedIPs)
	}
	if p.LatestHandshake != 1754049600 {
		t.Errorf("LatestHandshake = %d", p.LatestHandshake)
	}
	if p.RxBytes != 11400000 || p.TxBytes != 2300000 {
		t.Errorf("счётчики = %d/%d", p.RxBytes, p.TxBytes)
	}
	if peers[1].LatestHandshake != 0 {
		t.Errorf("второй пир: LatestHandshake = %d, ожидался 0", peers[1].LatestHandshake)
	}
}

func TestParseDumpMultipleAllowedIPs(t *testing.T) {
	line := "cHVi\t(none)\t(none)\t10.0.0.5/32,192.168.9.0/24\t0\t0\t0\toff\n"
	peers, err := runtime.ParseDump("dev\tdev\t1\toff\n" + line)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers[0].AllowedIPs) != 2 {
		t.Errorf("AllowedIPs = %v, ожидалось 2 элемента", peers[0].AllowedIPs)
	}
}

// Формат dump может обрасти полями в новых версиях amneziawg-tools —
// лишние поля не должны ломать разбор.
func TestParseDumpToleratesExtraTrailingFields(t *testing.T) {
	line := "cHVi\t(none)\t(none)\t10.0.0.5/32\t0\t0\t0\toff\textra\n"
	if _, err := runtime.ParseDump("dev\tdev\t1\toff\n" + line); err != nil {
		t.Fatalf("лишнее поле сломало разбор: %v", err)
	}
}

func TestParseDumpRejectsShortPeerLine(t *testing.T) {
	if _, err := runtime.ParseDump("dev\tdev\t1\toff\nmalo\tpoley\n"); err == nil {
		t.Fatal("ожидалась ошибка на укороченную строку пира")
	}
}

func TestParseDumpEmpty(t *testing.T) {
	peers, err := runtime.ParseDump("dev\tdev\t51820\toff\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 0 {
		t.Errorf("пиров %d, ожидалось 0", len(peers))
	}
	if _, err := runtime.ParseDump(""); err == nil {
		t.Fatal("ожидалась ошибка на пустой вывод")
	}
}
