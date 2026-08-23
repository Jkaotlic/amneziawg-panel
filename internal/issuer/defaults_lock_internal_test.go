package issuer

// Внутренний (white-box) тест: доступ к неэкспортированному s.mu нужен,
// чтобы держать мьютекс СНАРУЖИ вызова Defaults() и детерминированно
// проверить, что метод на нём блокируется, — тот же приём и то же
// обоснование файла, что у addrLess в service_internal_test.go.
//
// Отдельный файл, а не правка service_test.go/service_internal_test.go:
// задача 10 (web-слой) правит internal/issuer только ради этой находки
// (поправка 3 брифа), и новый файл гарантированно не пересекается со
// строками, которые параллельно правит другая задача в этом же пакете.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// TestDefaultsLocksMutex — поправка 3 задачи 10 (task-10-brief.md): до неё
// Defaults() не брал s.mu вовсе, и это было безопасно только потому, что
// оба тогдашних вызывающих (Add, Rotate) уже держали лок сами. Первый
// вызывающий СНАРУЖИ пакета (web.handleGetDefaults, GET .../defaults) лока
// не имеет и мог бы гоняться с конкурентным SetDefaults за bootstrap-записью
// defaults.json. Тест детерминированно доказывает захват мьютекса: держим
// s.mu снаружи и проверяем, что Defaults() блокируется до Unlock, а не
// проскакивает мимо.
func TestDefaultsLocksMutex(t *testing.T) {
	dir := t.TempDir()
	iface := config.Interface{
		ID:     "test",
		Client: config.Client{Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0"},
		// ПРЯМОЙ слэш, а не filepath.Join: DefaultsPath() строит путь через
		// path.Dir/path.Join (путь на целевом Linux-хосте, см. комментарий у
		// config.Interface.StateDir), а filepath.Join на Windows даёт обратный
		// слэш, в котором path.Dir разделителя не находит и тихо возвращает
		// "." — тогда Defaults() промахивается мимо t.TempDir() и пишет
		// defaults.json в каталог пакета (тот же приём и то же обоснование,
		// что у slashStorage в service_test.go).
		Storage: config.Storage{State: filepath.ToSlash(dir) + "/peers.json"},
	}
	// Defaults()/defaults() не трогают s.r вовсе — runtime.Runner не нужен.
	svc := New(iface, "", nil)

	svc.mu.Lock()
	done := make(chan store.Defaults, 1)
	go func() {
		done <- svc.Defaults()
	}()

	select {
	case <-done:
		t.Fatal("Defaults() вернулся, пока тест удерживал s.mu — метод не берёт мьютекс сам")
	case <-time.After(200 * time.Millisecond):
		// Ожидаемо: вызов заблокирован на s.mu, пока тест его держит.
	}

	svc.mu.Unlock()

	select {
	case got := <-done:
		if got.Endpoint != iface.Client.Endpoint {
			t.Errorf("Defaults() после снятия блокировки вернул %+v, ожидался эндпоинт из сида %q",
				got, iface.Client.Endpoint)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Defaults() не вернулся после освобождения мьютекса")
	}
}

// TestInternalDefaultsCallersDoNotDeadlock — обратная сторона поправки 3:
// Add и Rotate уже держат s.mu, когда им нужны умолчания, и обязаны звать
// НЕэкспортированный defaults() напрямую — иначе второй Lock изнутри уже
// удерживаемого s.mu (sync.Mutex не реентрантен) намертво блокирует их
// самих. Полные Add/Rotate дороги проверяют service_test.go; здесь —
// узкая, дешёвая проверка именно этого свойства: defaults() не блокируется,
// пока s.mu уже держит вызывающий (то есть звать его можно изнутри Add и
// Rotate без взаимной блокировки).
func TestInternalDefaultsCallersDoNotDeadlock(t *testing.T) {
	dir := t.TempDir()
	iface := config.Interface{
		ID:     "test",
		Client: config.Client{Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0"},
		// ПРЯМОЙ слэш, а не filepath.Join: DefaultsPath() строит путь через
		// path.Dir/path.Join (путь на целевом Linux-хосте, см. комментарий у
		// config.Interface.StateDir), а filepath.Join на Windows даёт обратный
		// слэш, в котором path.Dir разделителя не находит и тихо возвращает
		// "." — тогда Defaults() промахивается мимо t.TempDir() и пишет
		// defaults.json в каталог пакета (тот же приём и то же обоснование,
		// что у slashStorage в service_test.go).
		Storage: config.Storage{State: filepath.ToSlash(dir) + "/peers.json"},
	}
	svc := New(iface, "", nil)

	svc.mu.Lock()
	defer svc.mu.Unlock()

	done := make(chan struct{})
	go func() {
		svc.defaults() // НЕ Defaults(): вызывающий уже держит s.mu
		close(done)
	}()

	select {
	case <-done:
		// Ожидаемо: defaults() не берёт мьютекс и потому не блокируется,
		// хотя s.mu удерживает этот же тест.
	case <-time.After(2 * time.Second):
		t.Fatal("defaults() заблокировался, хотя не должен брать мьютекс сам — " +
			"вызов из Add/Rotate (они уже держат s.mu) привёл бы к deadlock")
	}
}
