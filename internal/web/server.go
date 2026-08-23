package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

//go:embed assets/index.html
var assets embed.FS

// PeerLister — единственное, что нужно read-only части сервера от ОДНОГО
// интерфейса. Узкий интерфейс позволяет тестировать HTTP без файловой
// системы.
type PeerLister interface {
	List() ([]issuer.PeerView, error)
}

// Registry — то, что нужно read-only части сервера от РЕЕСТРА интерфейсов:
// перечислить их и найти листер по id. Задача 10 переводит сервер с одного
// заранее выбранного интерфейса (config.Interface) на реестр — маршруты
// получают префикс /api/ifaces/{iface}/, а обработчик сам решает, какой
// интерфейс обслуживать, по сегменту пути.
type Registry interface {
	Metas() []issuer.IfaceMeta
	Lister(id string) (PeerLister, bool)
}

type Server struct {
	cfg  *config.Config
	reg  Registry
	auth *Auth
	tpl  *template.Template
	// mutators заполняется только в сборке без тега readonly (см.
	// handlers_mutate.go/handlers_mutate_readonly.go).
	mutators MutatorRegistry
}

func NewServer(cfg *config.Config, reg Registry) *Server {
	tpl := template.Must(template.ParseFS(assets, "assets/index.html"))
	return &Server{
		cfg:  cfg,
		reg:  reg,
		auth: NewAuth(cfg.Auth.User, cfg.Auth.Bcrypt),
		tpl:  tpl,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/ifaces", s.handleIfaces)
	mux.HandleFunc("GET /api/ifaces/{iface}/peers", s.handleListPeers)
	s.registerMutations(mux) // в сборке readonly — пустая функция
	// sameOriginOnly снаружи авторизации: кросс-сайтовый запрос не должен
	// доходить ни до проверки пароля (лишний bcrypt и лишняя запись в счётчик
	// неудач), ни тем более до обработчика.
	return sameOriginOnly(s.auth.Middleware(mux))
}

// sameOriginOnly отклоняет ПИШУЩИЕ запросы, пришедшие со страницы чужого
// источника (CSRF). Панель аутентифицируется Basic-авторизацией, а её браузер
// подставляет кэшированные учётные данные к любому запросу на этот источник —
// включая тот, что инициировала чужая вкладка. POST с телом text/plain
// уходит из чужой формы вообще без preflight, так что на CORS полагаться
// нельзя: он ограничивает чтение ОТВЕТА, а не отправку запроса, а мутации
// ответ и не нужен.
//
// Решение при ПОЛНОМ отсутствии заголовков источника — пропускать. Обоснование:
//   - браузер, способный быть орудием CSRF, всегда шлёт Origin на
//     кросс-оригинальные POST (это часть Fetch с 2016 года) и Sec-Fetch-Site
//     (с 2020-го); отсутствие обоих означает, что клиент не браузер — curl или
//     скрипт, — а он не носит с собой чужих ambient-учёток и потому не
//     является CSRF-вектором вовсе;
//   - отказ в этом случае сломал бы работу с панелью из терминала, то есть
//     заблокировал бы единственного администратора ради риска, которого в
//     этом сценарии нет. Тот же приоритет, что и в auth.go: ложная блокировка
//     легитимного пользователя — реальный ущерб, а не гипотетический.
//
// Читающие методы не проверяются: они не меняют состояние, а прочитать ответ
// чужая страница всё равно не сможет — заголовков CORS панель не отдаёт.
//
// Проверка стоит СНАРУЖИ маршрутизации по интерфейсам (задача 10): она не
// заглядывает в путь глубже метода, поэтому кросс-сайтовый POST отклоняется
// одинаково для любого /api/ifaces/{iface}/... — включая несуществующий
// iface, до которого обработчик всё равно не добрался бы.
func sameOriginOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isReadMethod(r.Method) || isSameOrigin(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Формат тела — тот же, что у всех прочих ошибок API ({"error": ...}):
		// хелпер страницы разбирает ответ через JSON.parse и на обычном тексте
		// показал бы «Unexpected token» вместо причины. writeJSON, а не
		// writeError, — чтобы не логировать одно и то же дважды: строка ниже
		// информативнее, в ней есть метод и путь.
		log.Printf("отклонён кросс-сайтовый запрос %s %s", r.Method, r.URL.Path)
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "запрос отклонён: он инициирован страницей стороннего сайта",
		})
	})
}

func isReadMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func isSameOrigin(r *http.Request) bool {
	// Origin точнее Sec-Fetch-Site и потому проверяется первым: он называет
	// конкретный источник, а не его отношение к целевому.
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" {
			return false // в том числе Origin: null — песочница или file://
		}
		return strings.EqualFold(u.Host, r.Host)
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "":
		return true // не браузер — см. комментарий к sameOriginOnly
	default:
		return false // cross-site, same-site
	}
}

// shutdownTimeout — сколько ждать завершения уже начатых запросов после
// сигнала остановки. Пока панель только читала, обрыв на сигнале стоил
// максимум одного GET. С появлением мутаций цена другая: обработчик в этот
// момент может находиться посреди инварианта раздела 6 спеки — между
// атомарной записью конфига и syncconf, или, хуже, между syncconf и
// проверкой постусловия, откуда начинается откат. Убить процесс там значит
// оставить файл и живое устройство в разном состоянии без всякого отката.
// Полный цикл (два снимка, запись, syncconf, при неудаче — откат) занимает
// доли секунды; 30 секунд — запас на порядок, после которого ждать уже
// бессмысленно.
const shutdownTimeout = 30 * time.Second

func (s *Server) ListenAndServe() error {
	// SIGTERM приходит от systemd при stop и restart — то есть ровно тогда,
	// когда администратор обновляет панель, возможно, в момент мутации.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("слушаю http://%s (интерфейсы: %s)", s.cfg.Listen, ifaceIDList(s.reg.Metas()))
	return s.serve(ctx, ln)
}

// ifaceIDList печатает id всех обслуживаемых интерфейсов через запятую — для
// строки старта в логе. Раньше здесь было единственное имя интерфейса
// (s.iface.Interface), пока сервер обслуживал ровно один; задача 10
// перевела его на реестр, обслуживающий их все одновременно.
func ifaceIDList(metas []issuer.IfaceMeta) string {
	ids := make([]string, 0, len(metas))
	for _, m := range metas {
		ids = append(ids, m.ID)
	}
	return strings.Join(ids, ", ")
}

// serve обслуживает ln до отмены ctx, после чего даёт уже начатым запросам
// доработать до конца (graceful shutdown) и только затем возвращает
// управление. Отделено от ListenAndServe, чтобы это поведение можно было
// проверить тестом на реальном сокете, не завися ни от сигналов, ни от
// адреса из конфига.
func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Printf("получен сигнал остановки: доканчиваю начатые запросы (не дольше %s)", shutdownTimeout)
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			// Единственный способ сюда попасть — истёкший shutdownTimeout:
			// обработчик не завершился за отведённое время. Молчать нельзя —
			// это как раз тот случай, когда мутация могла остаться незавершённой.
			return fmt.Errorf("остановка сервера: %w", err)
		}
		<-errc // Serve уже вернул ErrServerClosed, забираем, чтобы не оставлять горутину
		log.Print("сервер остановлен")
		return nil
	}
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Ifaces   []issuer.IfaceMeta
		ReadOnly bool
	}{Ifaces: s.reg.Metas(), ReadOnly: s.mutators == nil}
	if err := s.tpl.Execute(w, data); err != nil {
		log.Printf("шаблон: %v", err)
	}
}

func (s *Server) handleIfaces(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.reg.Metas())
}

// listerFor находит листер интерфейса по id из пути; при отсутствии сам
// пишет 404 клиенту, а не паникует и не молчаливо выбирает первый интерфейс
// — тот же id мог означать интерфейс, который просто не сконфигурирован.
func (s *Server) listerFor(w http.ResponseWriter, r *http.Request) (PeerLister, bool) {
	l, ok := s.reg.Lister(r.PathValue("iface"))
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("интерфейс %q не найден", r.PathValue("iface")))
		return nil, false
	}
	return l, true
}

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	l, ok := s.listerFor(w, r)
	if !ok {
		return
	}
	peers, err := l.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, peers)
}

// issuerRegistry оборачивает *issuer.Registry в Registry. Присвоить его
// напрямую нельзя: issuer.Registry.Lister возвращает *issuer.Service, а не
// web.PeerLister — в Go у методов с разными сигнатурами разные типы, даже
// если *issuer.Service фактически реализует PeerLister.
type issuerRegistry struct{ reg *issuer.Registry }

// Adapt оборачивает *issuer.Registry в Registry — единственный способ
// свести issuer.Registry.Lister (отдаёт *issuer.Service) к web.Registry.Lister
// (отдаёт web.PeerLister). Живёт в web, а не в issuer и не в cmd: cmd не
// должен знать про интерфейсы web (иначе пакеты образовали бы цикл смыслов
// туда-обратно), а issuer не должен знать про web вовсе.
func Adapt(reg *issuer.Registry) Registry { return issuerRegistry{reg} }

func (a issuerRegistry) Metas() []issuer.IfaceMeta { return a.reg.Metas() }

func (a issuerRegistry) Lister(id string) (PeerLister, bool) {
	s, ok := a.reg.Lister(id)
	if !ok {
		return nil, false
	}
	return s, true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("ответ: %v", err)
	}
}

// writeError логирует полную ошибку (для диагностики администратором) и
// решает, что из неё показать клиенту, по КЛАССУ кода:
//
//   - 4xx — ошибка запроса: пустое имя, кривой JSON, неизвестный id. Её текст
//     описывает то, что прислал сам пользователь, и без него он не поймёт,
//     что исправить. Тексты 4xx сочиняются здесь и в issuer (ErrInvalidInput,
//     ErrNotFound) целиком — ни ключей, ни PSK, ни путей в них нет.
//   - 5xx — внутренняя ошибка: наружу уходит только родовая формулировка.
//     Тело ответа оседает в истории браузера и промежуточных инструментах, а
//     цепочка err на пути мутации проходит через wgconf, issuer и runtime —
//     если туда однажды снова попадёт строка конфига с ключом (ровно это
//     чинили в Task 11), она не должна уйти клиенту через этот путь.
//
// Классификацию делает вызывающий (см. statusFor в handlers_mutate.go):
// сюда ошибка приходит уже с решённым кодом.
func writeError(w http.ResponseWriter, code int, err error) {
	log.Printf("ошибка %d: %v", code, err)
	msg := "внутренняя ошибка"
	if code >= 400 && code < 500 {
		msg = err.Error()
	}
	writeJSON(w, code, map[string]string{"error": msg})
}
