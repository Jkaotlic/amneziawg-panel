//go:build readonly

package web_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/web"
)

// Компиляционное доказательство того, ради чего существует раздел 12.1
// спеки: в read-only сборке web.PeerMutator и web.MutatorRegistry не имеют
// НИ ОДНОГО метода — пустая структура удовлетворяет обоим. Значит в бинаре
// нет ни Add, ни Remove, ни Update, ни Rotate, ни SetDefaults — вызывать
// нечего, а не «выключено флагом».
//
// Эта строка и есть гейт: в полной сборке PeerMutator и MutatorRegistry
// требуют методов, и файл просто НЕ СКОМПИЛИРУЕТСЯ, если кто-нибудь снимет
// тег readonly или начнёт объявлять мутации вне тега. Проверка времени
// выполнения такого доказать не может — отсутствие символа не наблюдаемо
// изнутри программы.
var _ web.PeerMutator = struct{}{}
var _ web.MutatorRegistry = struct{}{}

// Этап A (раздел 12.1 спеки): бинарь физически не умеет писать.
func TestReadOnlyBuildHasNoMutationRoutes(t *testing.T) {
	if !web.ReadOnlyBuild {
		t.Fatal("сборка с тегом readonly не помечена как read-only")
	}
	h := newTestServer(t, twoIfaceRegistry(t))
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/ifaces/awg3/peers"},
		{http.MethodDelete, "/api/ifaces/awg3/peers/abc123"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/enable"},
		// Выдача конфига и QR регистрируется тем же registerMutations и в
		// read-only сборке обязана отсутствовать наравне с мутациями:
		// клиентский .conf содержит приватный ключ пира.
		{http.MethodGet, "/api/ifaces/awg3/peers/abc123/config"},
		{http.MethodGet, "/api/ifaces/awg3/peers/abc123/qr"},
	} {
		rec := doAuthed(t, h, c.method, c.path, strings.NewReader(`{"name":"x"}`))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: код = %d, ожидался 404/405 — обработчика не должно существовать",
				c.method, c.path, rec.Code)
		}
	}
}

// TestReadonlyBuildHasNoEditRoutes — задача 10 (правка пира, ротация,
// умолчания): три новых маршрута обязаны отсутствовать в read-only сборке
// наравне со старыми. PATCH — без завершающего слэша (поправка 1
// контролёра к брифу: DELETE и PATCH различаются как образцы net/http по
// методу, а не по слэшу).
func TestReadonlyBuildHasNoEditRoutes(t *testing.T) {
	srv := newTestServer(t, twoIfaceRegistry(t))
	for _, c := range []struct{ method, path string }{
		{http.MethodPatch, "/api/ifaces/awg3/peers/abc123"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/rotate"},
		{http.MethodPut, "/api/ifaces/awg3/defaults"},
	} {
		rec := doAuthed(t, srv, c.method, c.path, strings.NewReader("{}"))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: код %d — в read-only сборке маршрута быть не должно", c.method, c.path, rec.Code)
		}
	}
}

func TestReadOnlyIndexShowsBadge(t *testing.T) {
	rec := doAuthed(t, newTestServer(t, twoIfaceRegistry(t)), http.MethodGet, "/", nil)
	if !strings.Contains(rec.Body.String(), "только чтения") {
		t.Error("страница не сообщает, что панель в режиме только чтения")
	}
	// Разметка тоже не должна предлагать того, чего бинарь не умеет:
	// кнопка, дающая 404, — это не «панель только для чтения», это баг.
	// "/peers/" (со слэшем) заменяет прежний литерал "/api/peers/" (задача 11
	// перевела JS на динамическую сборку пути через api()/apiURL()) — см.
	// тот же комментарий в TestFullBuildIndexHasActionControls.
	for _, forbidden := range []string{"Добавить", "Действия", "/peers/"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Errorf("в read-only разметке есть элемент управления мутацией: %q", forbidden)
		}
	}
}
