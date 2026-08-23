//go:build !readonly

package web_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

type fakeMutator struct {
	added    string
	removed  string
	disabled string
	enabled  string
	err      error

	// Задача 10: правка пира, ротация, умолчания.
	lastPatch    issuer.PeerPatch
	rotated      string
	defaults     store.Defaults
	lastDefaults store.Defaults
}

func (m *fakeMutator) Add(name string) (*issuer.Issued, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.added = name
	return &issuer.Issued{ID: "abc123", Name: name, Address: "10.0.0.4/32",
		Config: "[Interface]\n", QRPNG: []byte("\x89PNG\r\n\x1a\n")}, nil
}
func (m *fakeMutator) Remove(id string) error  { m.removed = id; return m.err }
func (m *fakeMutator) Disable(id string) error { m.disabled = id; return m.err }
func (m *fakeMutator) Enable(id string) error  { m.enabled = id; return m.err }
func (m *fakeMutator) ConfigFor(id string) (string, string, error) {
	return "peer.conf", "[Interface]\n", m.err
}
func (m *fakeMutator) QRFor(id string) ([]byte, error) {
	return []byte("\x89PNG\r\n\x1a\n"), m.err
}
func (m *fakeMutator) Update(id string, patch issuer.PeerPatch) error {
	m.lastPatch = patch
	return m.err
}
func (m *fakeMutator) Rotate(id string) (*issuer.Issued, error) {
	if m.err != nil {
		return nil, m.err
	}
	m.rotated = id
	return &issuer.Issued{ID: id, Name: "ротированный", Address: "10.0.0.4/32",
		Config: "[Interface]\n", QRPNG: []byte("\x89PNG\r\n\x1a\n")}, nil
}
func (m *fakeMutator) Defaults() store.Defaults { return m.defaults }
func (m *fakeMutator) SetDefaults(d store.Defaults) error {
	m.lastDefaults = d
	return m.err
}

// fakeMutatorRegistry — тестовая реализация web.MutatorRegistry: единственный
// интерфейс "awg3" отдаёт заданный мутатор. Методы на указательном ресивере
// намеренно — TestTypedNilMutatorRegistryIsTreatedAsReadOnly передаёт
// типизированный nil-указатель этого типа как web.MutatorRegistry.
type fakeMutatorRegistry struct{ byID map[string]web.PeerMutator }

func (r *fakeMutatorRegistry) Mutator(id string) (web.PeerMutator, bool) {
	m, ok := r.byID[id]
	return m, ok
}

// newTestServerWithMutator строит пишущий обработчик с единственным
// интерфейсом "awg3", чей мутатор — m. Замена прежнего mutServer(t, m)
// (задача 10 перевела Server с одиночного PeerMutator на MutatorRegistry).
func newTestServerWithMutator(t *testing.T, m web.PeerMutator) http.Handler {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	mutators := &fakeMutatorRegistry{byID: map[string]web.PeerMutator{"awg3": m}}
	return web.NewServerWithMutator(cfg, reg, mutators).Handler()
}

func TestPostPeersCreates(t *testing.T) {
	m := &fakeMutator{}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`{"name":"мой-ноут"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("код = %d, ожидался 201, тело: %s", rec.Code, rec.Body)
	}
	if m.added != "мой-ноут" {
		t.Errorf("сервису передано имя %q", m.added)
	}
	var got struct {
		ID       string `json:"id"`
		Config   string `json:"config"`
		QRBase64 string `json:"qr_png_base64"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.Config == "" || got.QRBase64 == "" {
		t.Errorf("неполный ответ: %+v", got)
	}
}

func TestPostPeersRejectsBadJSON(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`не json`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидался 400", rec.Code)
	}
}

// TestPostPeersSurfacesValidationError — половина «разведения кодов» из ревью
// Task 11: ошибка ВВОДА обязана дойти до пользователя дословно. Иначе на
// пустое имя он получит «внутренняя ошибка» и не поймёт, что чинить.
func TestPostPeersSurfacesValidationError(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: имя пира не может быть пустым", issuer.ErrInvalidInput)}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`{"name":"  "}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидался 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "имя пира не может быть пустым") {
		t.Errorf("причина отказа не дошла до пользователя: %s", rec.Body)
	}
}

// TestPostPeersHidesInternalErrorText — вторая половина: ВНУТРЕННЯЯ ошибка
// наружу не уходит. Цепочка err на пути мутации проходит через wgconf,
// issuer и runtime, и однажды может снова понести в себе строку конфига с
// ключом (ровно это чинили в Task 11). Подробности — в лог администратора,
// клиенту — родовая формулировка.
func TestPostPeersHidesInternalErrorText(t *testing.T) {
	m := &fakeMutator{err: errors.New("пул адресов исчерпан")}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers",
		strings.NewReader(`{"name":"x"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("код = %d, ожидался 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "пул адресов исчерпан") {
		t.Errorf("текст внутренней ошибки ушёл клиенту: %s", rec.Body)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("ошибка отдана не в JSON: %v (%s)", err, rec.Body)
	}
	if body.Error == "" {
		t.Error("поле error пусто")
	}
}

func TestDeletePeer(t *testing.T) {
	m := &fakeMutator{}
	h := newTestServerWithMutator(t, m)
	if rec := doAuthed(t, h, http.MethodDelete, "/api/ifaces/awg3/peers/abc123", nil); rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if m.removed != "abc123" {
		t.Errorf("удалён %q", m.removed)
	}
}

// TestUnknownPeerIs404 — неизвестный id это ошибка запроса, а не сервера:
// 404 с внятной причиной, а не 500 «внутренняя ошибка».
func TestUnknownPeerIs404(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: abc123", issuer.ErrNotFound)}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "abc123") {
		t.Errorf("ответ не называет ненайденного пира: %s", rec.Body)
	}
}

func TestDisableAndEnable(t *testing.T) {
	m := &fakeMutator{}
	h := newTestServerWithMutator(t, m)
	if rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable", nil); rec.Code != http.StatusOK {
		t.Fatalf("disable: код = %d", rec.Code)
	}
	if rec := doAuthed(t, h, http.MethodPost, "/api/ifaces/awg3/peers/abc123/enable", nil); rec.Code != http.StatusOK {
		t.Fatalf("enable: код = %d", rec.Code)
	}
	if m.disabled != "abc123" || m.enabled != "abc123" {
		t.Errorf("disabled=%q enabled=%q", m.disabled, m.enabled)
	}
}

func TestGetConfigHasAttachmentHeader(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/api/ifaces/awg3/peers/abc123/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "attachment") || !strings.Contains(cd, "peer.conf") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestGetQRReturnsPNG(t *testing.T) {
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/api/ifaces/awg3/peers/abc123/qr", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "image/png" {
		t.Errorf("Content-Type = %q", rec.Header().Get("Content-Type"))
	}
}

func TestMutationsRequireAuth(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	req := httptest.NewRequest(http.MethodPost, "/api/ifaces/awg3/peers", strings.NewReader(`{"name":"x"}`))
	req.RemoteAddr = "10.0.0.2:40000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("код = %d, ожидался 401", rec.Code)
	}
}

// TestCrossSitePostDoesNotReachMutator — та же защита, что и в
// TestCrossSiteWriteIsRejected, но с настоящим мутатором за маршрутом:
// важен не только код ответа, но и то, что сервисный метод не был вызван.
// 403 при уже выполненной мутации ничего бы не стоил.
func TestCrossSitePostDoesNotReachMutator(t *testing.T) {
	m := &fakeMutator{}
	h := newTestServerWithMutator(t, m)
	req := httptest.NewRequest(http.MethodPost, "/api/ifaces/awg3/peers", strings.NewReader(`{"name":"чужой"}`))
	req.RemoteAddr = "10.0.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	req.Header.Set("Origin", "http://evil.example")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("код = %d, ожидался 403", rec.Code)
	}
	if m.added != "" {
		t.Errorf("мутатор вызван кросс-сайтовым запросом: добавлено имя %q", m.added)
	}
}

// TestTypedNilMutatorRegistryIsTreatedAsReadOnly — та же находка ревью
// Task 11, перенесённая на новый уровень косвенности (задача 10): раньше
// типизированный nil мог прийти как сам PeerMutator, теперь — как
// MutatorRegistry (его отдаёт NewServerWithMutator реестру мутаторов, а не
// одному мутатору напрямую). Интерфейс с nil-указателем внутри сам по себе
// НЕ равен nil, поэтому наивная проверка `m == nil` на нём не срабатывает:
// страница объявила бы панель пишущей, маршруты мутаций зарегистрировались
// бы, и первый же вызов уронил бы обработчик. Панель обязана считать такой
// реестр отсутствующим — и в разметке, и в маршрутах.
func TestTypedNilMutatorRegistryIsTreatedAsReadOnly(t *testing.T) {
	var typedNil *fakeMutatorRegistry // nil-указатель конкретного типа
	hash, _ := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	reg := &fakeRegistry{
		metas:   []issuer.IfaceMeta{{ID: "awg3", Title: "awg3", Interface: "awg3"}},
		listers: map[string]web.PeerLister{"awg3": &fakeLister{}},
	}
	h := web.NewServerWithMutator(cfg, reg, typedNil).Handler()

	rec := doAuthed(t, h, http.MethodGet, "/", nil)
	if !strings.Contains(rec.Body.String(), "только чтения") {
		t.Error("страница не сообщает о режиме только чтения, хотя реестр мутаторов фактически nil")
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/ifaces/awg3/peers"},
		{http.MethodDelete, "/api/ifaces/awg3/peers/abc123"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/disable"},
		{http.MethodPost, "/api/ifaces/awg3/peers/abc123/enable"},
	} {
		rec := doAuthed(t, h, c.method, c.path, strings.NewReader(`{"name":"x"}`))
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: код = %d, ожидался 404/405 — маршрут не должен быть зарегистрирован",
				c.method, c.path, rec.Code)
		}
	}
}

// TestFullBuildIndexHasActionControls — обратная сторона
// TestReadOnlyIndexShowsBadge: в полной сборке кнопки действий обязаны быть в
// разметке, иначе панель read-only не по тегу сборки, а по недосмотру в
// шаблоне, и оба теста прошли бы одновременно.
func TestFullBuildIndexHasActionControls(t *testing.T) {
	if web.ReadOnlyBuild {
		t.Fatal("полная сборка помечена как read-only")
	}
	rec := doAuthed(t, newTestServerWithMutator(t, &fakeMutator{}), http.MethodGet, "/", nil)
	// "/peers/" (со слэшем) — задача 11 перевела JS на api()/apiURL(), собирающие
	// путь конкретного пира динамически ("/peers/" + id + "/..."), поэтому
	// прежний литерал "/api/peers/" в разметке больше не встречается нигде —
	// ни в мутирующей, ни в read-only сборке. Строка "/peers/" со слэшем
	// остаётся эквивалентным маркером: она входит в исходный JS-текст
	// rowActions/peerAction/editform, а те определены ТОЛЬКО внутри
	// {{if not .ReadOnly}} (см. TestReadOnlyIndexShowsBadge). refresh() же
	// (общий для обеих сборок) обращается к "/peers" без слэша.
	for _, want := range []string{"Добавить", "Действия", "/peers/"} {
		if !strings.Contains(rec.Body.String(), want) {
			t.Errorf("в разметке нет %q", want)
		}
	}
	if strings.Contains(rec.Body.String(), "только чтения") {
		t.Error("полная сборка показывает плашку режима только чтения")
	}
}

// --- Задача 10: PATCH пира, ротация ключей, умолчания интерфейса ---

// TestPatchPeerPassesThroughToMutator — путь PATCH БЕЗ завершающего слэша
// (поправка 1 контролёра к брифу задачи 10: DELETE и PATCH не конфликтуют
// как образцы net/http, слэш не нужен). Явно пустой DNS в overrides обязан
// дойти до Update как ЗАДАННЫЙ пустым (*string, указывающий на ""), а не
// как отсутствующее поле (nil) — раздел 8 спеки о наследовании умолчаний.
func TestPatchPeerPassesThroughToMutator(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	body := `{"name":"новое","overrides":{"dns":""}}`
	rec := doAuthed(t, srv, http.MethodPatch, "/api/ifaces/awg3/peers/abc123", strings.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if m.lastPatch.Name == nil || *m.lastPatch.Name != "новое" {
		t.Fatal("имя не доехало до сервиса")
	}
	if m.lastPatch.Overrides == nil || m.lastPatch.Overrides.DNS == nil || *m.lastPatch.Overrides.DNS != "" {
		t.Fatal("явно пустой DNS обязан доехать как заданный, а не как отсутствующий")
	}
}

// TestPatchPeerOmittedFieldsStayNil — обратная сторона предыдущего теста:
// поле, которого нет в JSON вовсе, обязано остаться nil-указателем в
// PeerPatch (наследование/«не менять»), а не превратиться в пустое значение.
func TestPatchPeerOmittedFieldsStayNil(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	rec := doAuthed(t, srv, http.MethodPatch, "/api/ifaces/awg3/peers/abc123", strings.NewReader(`{"name":"новое"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if m.lastPatch.Address != nil {
		t.Errorf("address не присылался, а доехал как %v", *m.lastPatch.Address)
	}
	if m.lastPatch.Overrides != nil {
		t.Errorf("overrides не присылался, а доехал как %+v", m.lastPatch.Overrides)
	}
}

// TestMutationOnUnknownInterfaceIs404 — mutatorFor (общий для всех маршрутов
// мутаций) обязан отвечать 404 на неизвестный интерфейс, а не паниковать и
// не молча брать первый попавшийся мутатор (constraint 5 брифа задачи 10).
func TestMutationOnUnknownInterfaceIs404(t *testing.T) {
	h := newTestServerWithMutator(t, &fakeMutator{})
	rec := doAuthed(t, h, http.MethodPatch, "/api/ifaces/нет-такого/peers/abc123", strings.NewReader(`{}`))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("код = %d, ожидался 404 — интерфейс не существует", rec.Code)
	}
}

// TestRotateReturnsFreshConfigAndQR: старый конфиг у клиента уже не
// работает после ротации ключей, и оператору нужно чем-то заменить его
// немедленно — тем же откликом, что несёт выпуск нового пира.
func TestRotateReturnsFreshConfigAndQR(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	rec := doAuthed(t, srv, http.MethodPost, "/api/ifaces/awg3/peers/abc123/rotate", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "qr_png_base64") {
		t.Fatal("ответ ротации обязан нести конфиг и QR: старый у клиента уже не работает")
	}
	if m.rotated != "abc123" {
		t.Errorf("ротирован %q, ожидался abc123", m.rotated)
	}
}

// TestRotateSurfacesStateConflictAs409 — находка финального ревью I4:
// checkRotateStateMatchesServer раньше заворачивала ошибку в
// issuer.ErrPostcondition, statusFor давала ей 500, а writeError на 5xx
// заменяет текст на «внутренняя ошибка» — причина уходила только в journal,
// оператор её не видел вовсе. issuer.ErrStateConflict — собственный класс
// именно для этого раннего (ДО применения к устройству) отказа, и статус
// 409 подходит по смыслу «состояние конфликтует», а не «сломалось что-то
// внутри».
func TestRotateSurfacesStateConflictAs409(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: пир %s числится включённым в peers.json, но его блока "+
		"нет в серверном конфиге", issuer.ErrStateConflict, "abc123")}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPost, "/api/ifaces/awg3/peers/abc123/rotate", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("код = %d, ожидался 409: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "числится включённым в peers.json") {
		t.Errorf("причина расхождения не дошла до оператора (заменена на «внутренняя ошибка»?): %s", rec.Body)
	}
}

func TestGetDefaultsReturnsCurrentValues(t *testing.T) {
	m := &fakeMutator{defaults: store.Defaults{
		Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Keepalive: "25",
	}}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodGet, "/api/ifaces/awg3/defaults", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	var got store.Defaults
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Keepalive != "25" {
		t.Errorf("умолчания не доехали: %+v", got)
	}
}

func TestDefaultsGetPut(t *testing.T) {
	m := &fakeMutator{}
	srv := newTestServerWithMutator(t, m)
	rec := doAuthed(t, srv, http.MethodPut, "/api/ifaces/awg3/defaults",
		strings.NewReader(`{"endpoint":"1.2.3.4:51820","allowed_ips":"0.0.0.0/0","keepalive":"25","dns":""}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("код %d: %s", rec.Code, rec.Body.String())
	}
	if m.lastDefaults.Keepalive != "25" {
		t.Fatalf("умолчания не доехали: %+v", m.lastDefaults)
	}
}

// TestPutDefaultsSurfacesValidationError — умолчания проходят через
// ValidateDefaults (issuer.Service.SetDefaults); ошибка ввода обязана дойти
// до оператора дословно, тем же путём statusFor/writeError, что и у Add.
func TestPutDefaultsSurfacesValidationError(t *testing.T) {
	m := &fakeMutator{err: fmt.Errorf("%w: endpoint не задан", issuer.ErrInvalidInput)}
	rec := doAuthed(t, newTestServerWithMutator(t, m), http.MethodPut, "/api/ifaces/awg3/defaults",
		strings.NewReader(`{}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("код = %d, ожидался 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "endpoint не задан") {
		t.Errorf("причина отказа не дошла до пользователя: %s", rec.Body)
	}
}
