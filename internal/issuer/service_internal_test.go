package issuer

import (
	"sort"
	"testing"
)

// Внутренний (white-box) тест: addrLess — неэкспортируемая функция, и
// проверка свойств тотального порядка на ней самой требует доступа к
// пакету issuer, а не issuer_test (где живут остальные тесты пакета).
// Намеренное исключение из общего правила «тесты пакета живут в
// issuer_test» — сделано специально ради закрытия Finding 1 ревью Task 10
// (см. отчёт task-10-report.md). Второй такой файл — keys_internal_test.go
// (ревью Task 4, находка «Осиротевший легаси-файл»): та же причина, доступ
// к неэкспортируемому символу пакета, нужному только тесту.

// addrsForOrderCheck — набор адресов вокруг границы .9/.10 (где строковое
// и численное сравнение расходятся) плюс неразбираемые значения, включая
// пустую строку: addrOf[pub] в service.go принимает значение "" ровно
// тогда, когда у пира в конфиге нет AllowedIPs — это реальный случай,
// а не гипотетический.
var addrsForOrderCheck = []string{
	"10.0.0.2/32",
	"10.0.0.9/32",
	"10.0.0.10/32",
	"10.0.0.100/32",
	"",             // пир без AllowedIPs
	"10.0.0.5abc", // испорченная запись, не разбирается
	"not-an-address",
}

func TestAddrLessIsIrreflexive(t *testing.T) {
	for _, a := range addrsForOrderCheck {
		if addrLess(a, a) {
			t.Errorf("addrLess(%q, %q) = true, строгий порядок не может быть рефлексивным", a, a)
		}
	}
}

func TestAddrLessIsAsymmetric(t *testing.T) {
	for _, a := range addrsForOrderCheck {
		for _, b := range addrsForOrderCheck {
			if addrLess(a, b) && addrLess(b, a) {
				t.Errorf("addrLess(%q,%q) и addrLess(%q,%q) одновременно true — нарушена асимметрия", a, b, b, a)
			}
		}
	}
}

// TestAddrLessIsTransitive — главная проверка Finding 1.
//
// Контрпример ревьюера: A="10.0.0.9" (разбирается), B="10.0.0.10"
// (разбирается), C="10.0.0.5abc" (не разбирается). До фикса addrLess
// сравнивал ЦЕЛИКОМ строково, как только хотя бы один из двух адресов не
// разбирался: A<B численно (9<10) истинно; B<C строково истинно
// ("10.0.0.10" < "10.0.0.5abc" — восьмой символ '1' < '5'); C<A строково
// тоже истинно ("10.0.0.5abc" < "10.0.0.9" — последний общий разряд
// '5' < '9'). Итог: A<B<C<A — цикл, строгий слабый порядок нарушен.
// sort.Slice на таком предикате не паникует и не проверяет свойства сам —
// он молча выдаёт неопределённый результат, поэтому здесь тестируется
// сам предикат по всем тройкам набора, а не косвенно через сортировку.
func TestAddrLessIsTransitive(t *testing.T) {
	for _, a := range addrsForOrderCheck {
		for _, b := range addrsForOrderCheck {
			for _, c := range addrsForOrderCheck {
				if addrLess(a, b) && addrLess(b, c) && !addrLess(a, c) {
					t.Errorf("нарушена транзитивность: %q < %q и %q < %q, но не %q < %q",
						a, b, b, c, a, c)
				}
			}
		}
	}
}

// TestAddrLessParseableAlwaysBeforeUnparseable — явное требование фикса:
// все неразбираемые адреса идут ПОСЛЕ всех разбираемых, независимо от
// того, с какой стороны вызова они переданы.
func TestAddrLessParseableAlwaysBeforeUnparseable(t *testing.T) {
	parseable := []string{"10.0.0.2/32", "10.0.0.9/32", "10.0.0.10/32", "10.0.0.100/32"}
	unparseable := []string{"", "10.0.0.5abc", "not-an-address"}
	for _, p := range parseable {
		for _, u := range unparseable {
			if !addrLess(p, u) {
				t.Errorf("addrLess(%q, %q) = false, разбираемый адрес должен идти раньше неразбираемого", p, u)
			}
			if addrLess(u, p) {
				t.Errorf("addrLess(%q, %q) = true, неразбираемый адрес не должен идти раньше разбираемого", u, p)
			}
		}
	}
}

// TestAddrLessTotalOrderAroundBoundary сортирует набор адресов вокруг
// границы .9/.10 плюс неразбираемые (включая пустую строку) и утверждает
// ПОЛНЫЙ ожидаемый порядок — ровно то, что требует Finding 1.
func TestAddrLessTotalOrderAroundBoundary(t *testing.T) {
	addrs := []string{
		"10.0.0.10/32",
		"",
		"10.0.0.2/32",
		"10.0.0.5abc",
		"10.0.0.9/32",
		"10.0.0.100/32",
	}
	sort.Slice(addrs, func(i, j int) bool { return addrLess(addrs[i], addrs[j]) })
	want := []string{
		"10.0.0.2/32", "10.0.0.9/32", "10.0.0.10/32", "10.0.0.100/32",
		// неразбираемые — после всех разбираемых, между собой по строке
		// ("" лексикографически меньше "10.0.0.5abc"):
		"", "10.0.0.5abc",
	}
	if len(addrs) != len(want) {
		t.Fatalf("длина %d, ожидалось %d", len(addrs), len(want))
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Fatalf("порядок = %v, ожидалось %v", addrs, want)
		}
	}
}
