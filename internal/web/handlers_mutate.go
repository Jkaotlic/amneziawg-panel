//go:build !readonly

package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// PeerMutator — операции, меняющие серверный конфиг или умолчания
// интерфейса. В сборке с тегом readonly этот файл не компилируется, и
// обработчиков мутаций в бинаре нет.
type PeerMutator interface {
	Add(name string) (*issuer.Issued, error)
	Update(id string, patch issuer.PeerPatch) error
	Rotate(id string) (*issuer.Issued, error)
	Remove(id string) error
	Disable(id string) error
	Enable(id string) error
	ConfigFor(id string) (filename string, body string, err error)
	QRFor(id string) ([]byte, error)
	Defaults() store.Defaults
	SetDefaults(d store.Defaults) error
}

// MutatorRegistry — то, что нужно пишущей части сервера: найти PeerMutator
// конкретного интерфейса по id. Отдельный от Registry интерфейс по той же
// причине, по которой issuer.Registry разводит Lister и Mutator (см. её
// комментарий, internal/issuer/registry.go): в read-only сборке этот
// интерфейс пуст (см. handlers_mutate_readonly.go) — отдавать пишущий
// объект в такой сборке физически нечем.
type MutatorRegistry interface {
	Mutator(id string) (PeerMutator, bool)
}

const ReadOnlyBuild = false

func NewServerWithMutator(cfg *config.Config, reg Registry, m MutatorRegistry) *Server {
	s := NewServer(cfg, reg)
	if isNilMutatorRegistry(m) {
		// Интерфейс, внутри которого лежит nil-указатель конкретного типа,
		// САМ не равен nil: без этой проверки страница объявила бы панель
		// пишущей (ReadOnly вычисляется как s.mutators == nil), маршруты
		// зарегистрировались бы, и первый же вызов уронил бы обработчик по
		// nil-указателю где-то внутри реализации MutatorRegistry. Лучше
		// честно работать в режиме только чтения, чем врать в разметке и
		// падать на первой мутации (та же находка ревью Task 11, что и
		// раньше защищала одиночный PeerMutator, — здесь она защищает
		// реестр, который пришёл на его место).
		log.Print("реестр мутаторов не задан — панель работает в режиме только чтения")
		return s
	}
	s.mutators = m
	return s
}

// isNilMutatorRegistry отличает «реестра мутаторов нет» от «реестр есть» в
// том числе для типизированного nil. reflect здесь — единственный способ:
// сравнение интерфейса с nil на такое значение отвечает false.
func isNilMutatorRegistry(m MutatorRegistry) bool {
	if m == nil {
		return true
	}
	v := reflect.ValueOf(m)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// issuerMutatorRegistry оборачивает *issuer.Registry в MutatorRegistry —
// тот же повод, что у issuerRegistry в server.go: issuer.Registry.Mutator
// возвращает *issuer.Service, а не web.PeerMutator.
type issuerMutatorRegistry struct{ reg *issuer.Registry }

// AdaptMutators оборачивает *issuer.Registry в MutatorRegistry. Существует
// только в этой сборке (как и NewServerWithMutator): в read-only сборке
// подставлять мутаторы физически некуда.
func AdaptMutators(reg *issuer.Registry) MutatorRegistry { return issuerMutatorRegistry{reg} }

func (a issuerMutatorRegistry) Mutator(id string) (PeerMutator, bool) {
	s, ok := a.reg.Mutator(id)
	if !ok {
		return nil, false
	}
	return s, true
}

func (s *Server) registerMutations(mux *http.ServeMux) {
	if s.mutators == nil {
		return
	}
	mux.HandleFunc("POST /api/ifaces/{iface}/peers", s.handleAdd)
	// PATCH БЕЗ завершающего слэша (поправка 1 контролёра к брифу задачи 10):
	// в net/http образец включает метод, поэтому "DELETE /x" и "PATCH /x" —
	// разные образцы и не конфликтуют, завершающий слэш здесь не нужен.
	mux.HandleFunc("PATCH /api/ifaces/{iface}/peers/{id}", s.handlePatch)
	mux.HandleFunc("POST /api/ifaces/{iface}/peers/{id}/rotate", s.handleRotate)
	mux.HandleFunc("DELETE /api/ifaces/{iface}/peers/{id}", s.handleRemove)
	mux.HandleFunc("POST /api/ifaces/{iface}/peers/{id}/disable", s.handleDisable)
	mux.HandleFunc("POST /api/ifaces/{iface}/peers/{id}/enable", s.handleEnable)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/config", s.handleConfig)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers/{id}/qr", s.handleQR)
	mux.HandleFunc("GET /api/ifaces/{iface}/defaults", s.handleGetDefaults)
	mux.HandleFunc("PUT /api/ifaces/{iface}/defaults", s.handlePutDefaults)
}

// mutatorFor находит мутатора интерфейса по id из пути; при отсутствии сам
// пишет 404 — тот же приём, что и listerFor в server.go (неизвестный
// интерфейс это ошибка запроса, а не повод паниковать или молча взять
// первый попавшийся).
func (s *Server) mutatorFor(w http.ResponseWriter, r *http.Request) (PeerMutator, bool) {
	m, ok := s.mutators.Mutator(r.PathValue("iface"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("интерфейс %q не найден", r.PathValue("iface")))
		return nil, false
	}
	return m, true
}

// statusFor переводит класс ошибки сервиса в HTTP-код. Только 4xx доносят до
// клиента текст (см. writeError), поэтому классифицировать обязан вызывающий:
// «не найдено» и «некорректный ввод» описывают запрос пользователя, всё
// остальное — внутренности сервера, и наружу от них уходит только код.
//
// issuer.ErrNoPrivateKey отдельного case не требует: она объявлена как
// fmt.Errorf("%w: ...", ErrNotFound) (internal/issuer/keys.go), поэтому
// errors.Is(err, issuer.ErrNotFound) уже ловит её через цепочку Unwrap.
//
// issuer.ErrStateConflict (находка финального ревью, I4) — тоже 4xx: это
// расхождение peers.json с сервером, обнаруженное ДО применения мутации
// (checkRotateStateMatchesServer), а не внутренний сбой. 409 — по смыслу
// «состояние конфликтует»: запрос сам по себе корректен, но выполнить его
// сейчас нельзя, не потеряв метаданные пира. Раньше эта ошибка шла под
// issuer.ErrPostcondition (default-ветка, 500), и writeError стирала текст
// в «внутренняя ошибка» — оператор не видел причину.
func statusFor(err error) int {
	switch {
	case errors.Is(err, issuer.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, issuer.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, issuer.ErrStateConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func (s *Server) handleAdd(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("тело запроса не JSON вида {\"name\":\"...\"}"))
		return
	}
	issued, err := m.Add(body.Name)
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":            issued.ID,
		"name":          issued.Name,
		"address":       issued.Address,
		"config":        issued.Config,
		"qr_png_base64": base64.StdEncoding.EncodeToString(issued.QRPNG),
	})
}

// handlePatch правит имя, адрес и/или клиентские оверрайды уже выпущенного
// пира. Тело декодируется прямо в issuer.PeerPatch: её указатели различают
// «поле не прислали» и «поле прислали как пустое» (например,
// {"overrides":{"dns":""}} — явно пустой DNS, а не отсутствие DNS), и это
// различие обязано дойти до Update как есть — сюда оно доходит просто тем,
// что json.Decoder не трогает поля, отсутствующие в теле запроса.
func (s *Server) handlePatch(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var patch issuer.PeerPatch
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&patch); err != nil {
		writeError(w, http.StatusBadRequest,
			errors.New(`тело запроса не JSON вида {"name":..., "address":..., "overrides":{...}}`))
		return
	}
	if err := m.Update(r.PathValue("id"), patch); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleRotate выдаёт пиру новую пару ключей и PSK и возвращает готовый
// клиентский конфиг вместе с QR — тем же способом, что и выпуск нового пира
// (handleAdd): старый конфиг у клиента уже не работает после ротации, и
// оператору нужно немедленно чем-то его заменить, а не отдельным запросом
// за конфигом.
func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	issued, err := m.Rotate(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":            issued.ID,
		"name":          issued.Name,
		"address":       issued.Address,
		"config":        issued.Config,
		"qr_png_base64": base64.StdEncoding.EncodeToString(issued.QRPNG),
	})
}

func (s *Server) simpleAction(w http.ResponseWriter, r *http.Request, fn func(PeerMutator, string) error) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	if err := fn(m, r.PathValue("id")); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRemove(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, func(m PeerMutator, id string) error { return m.Remove(id) })
}

func (s *Server) handleDisable(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, func(m PeerMutator, id string) error { return m.Disable(id) })
}

func (s *Server) handleEnable(w http.ResponseWriter, r *http.Request) {
	s.simpleAction(w, r, func(m PeerMutator, id string) error { return m.Enable(id) })
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	name, body, err := m.ConfigFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+safeFilename(name)+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(body))
}

func (s *Server) handleQR(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	png, err := m.QRFor(r.PathValue("id"))
	if err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(png)
}

// handleGetDefaults отдаёт умолчания интерфейса как есть. m.Defaults() —
// это issuer.(*Service).Defaults(), которая сама берёт мьютекс сервиса
// (поправка 3 задачи 10, internal/issuer/service.go): этот обработчик — тот
// самый первый вызывающий СНАРУЖИ пакета issuer, ради которого мьютекс туда
// и добавлен, и здесь его брать заново не нужно и нечем — Service.mu не
// экспортирован.
func (s *Server) handleGetDefaults(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, m.Defaults())
}

func (s *Server) handlePutDefaults(w http.ResponseWriter, r *http.Request) {
	m, ok := s.mutatorFor(w, r)
	if !ok {
		return
	}
	var d store.Defaults
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&d); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("тело запроса не JSON с умолчаниями интерфейса"))
		return
	}
	if err := m.SetDefaults(d); err != nil {
		writeError(w, statusFor(err), err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// safeFilename оставляет в имени только [A-Za-z0-9._-]. Штатно сюда приходит
// slug из store ([a-z0-9-]) плюс ".conf", но peers.json — обычный файл на
// диске, который правят руками, а заголовок ответа не место для доверия к
// его содержимому: кавычка ломает разбор filename, а точки и слэши уводят
// сохранение файла не туда, куда рассчитывает пользователь.
func safeFilename(name string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '.', r == '-', r == '_':
			return r
		}
		return '-'
	}, strings.TrimSpace(name))
	if out == "" || out == "." || out == ".." {
		return "peer.conf"
	}
	return out
}
