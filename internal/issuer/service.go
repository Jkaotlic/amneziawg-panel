package issuer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// ErrInvalidInput и ErrNotFound помечают ошибки, вызванные ЗАПРОСОМ
// пользователя, а не состоянием сервера: пустое имя, имя длиннее предела,
// неизвестный id. Их текст сочинён здесь целиком и не содержит ни ключей,
// ни PSK, ни путей — поэтому web-слой вправе показать его пользователю
// (4xx). Всё остальное — внутренние ошибки: наружу уходит родовая
// формулировка, подробности только в лог (см. web.writeError, защита из
// ревью Task 11).
var (
	ErrInvalidInput = errors.New("некорректные данные запроса")
	ErrNotFound     = errors.New("пир не найден")
)

// ErrStateConflict помечает расхождение peers.json с живым устройством,
// обнаруженное ДО применения мутации (см. checkRotateStateMatchesServer) —
// находка финального ревью I4. Не ErrInvalidInput: то, что прислал
// оператор, тут ни при чём — расхождение возникло раньше, само по себе. Не
// ErrPostcondition (apply.go): та означает «мутация УЖЕ применена к
// устройству, а после проверки состояние разошлось со снимком, изменения
// откачены» — здесь же применения не было вовсе, отказ ранний и объяснимый.
// Раньше эта ошибка была обёрнута именно в ErrPostcondition, statusFor давала
// ей 500, а writeError на 5xx стирает текст в «внутренняя ошибка» — причина
// уходила только в journal, оператор её не видел. Собственный класс даёт
// собственный (4xx) код в statusFor: 409 подходит по смыслу «состояние
// конфликтует», а не «сломалось что-то внутри».
var ErrStateConflict = errors.New("состояние пира разошлось с сервером")

type Service struct {
	iface   config.Interface
	listen  string
	r       runtime.Runner
	applier *Applier
	// keys — хранилище приватных ключей клиентских пиров (задача 4).
	// Появилось вместе с задачей 5: клиентский .conf больше не хранится
	// файлом в Storage.ClientConfigs, а собирается заново при каждой выдаче
	// из этого ключа, живого [Interface] сервера, оверрайдов пира и
	// умолчаний интерфейса (раздел 5.2 спеки).
	keys *KeyStore

	// defaultsLoggedOnce ограничивает строку про игнорируемую секцию client
	// (см. defaults() ниже) ОДНИМ разом за жизнь процесса на этот интерфейс.
	// defaults() дёргается лениво — из Add, Rotate, configFor и экспортированного
	// Defaults() — сколько угодно раз за время работы панели, и log.Printf без
	// этой защиты на каждый вызов заспамил бы журнал (находка ревью задачи 16).
	defaultsLoggedOnce sync.Once

	// mu сериализует ЦЕЛИКОМ — от чтения конфига до записи peers.json — и
	// мутации, и те чтения, которые пишут состояние. Под ним семь точек:
	// Add, Remove, Disable, Enable, List, ConfigFor, QRFor.
	//
	// МУТАЦИИ. Мьютекса внутри Applier для этого недостаточно: он защищает
	// только участок «снимок → запись → syncconf → постусловие», а выбор
	// свободного адреса и чтение состояния происходят ДО него. Два
	// одновременных Add (двойного клика по кнопке достаточно) успели бы оба
	// прочитать конфиг без нового пира, оба выбрать один и тот же первый
	// свободный адрес и оба его применить: AppendPeer ловит повтор публичного
	// ключа, но не повтор AllowedIPs — на устройстве оказались бы два пира с
	// одним адресом. Симметрично, оба сохранили бы СВОЮ копию peers.json, и
	// запись второго стёрла бы пира первого.
	//
	// ЧТЕНИЯ. List, ConfigFor и QRFor берут этот же мьютекс, и это не
	// перестраховка: loadState — не читатель, при любом расхождении с
	// конфигом он СОХРАНЯЕТ состояние. Пока мутация не завершена, на диске
	// законно лежит промежуточная пара «блока пира в конфиге уже нет, в
	// peers.json он ещё Enabled=true», а store.Reconcile такого пира не
	// выключает, а ВЫБРАСЫВАЕТ. Цена снятия лока с любого из трёх путей
	// конкретна: PSK отключаемого пира пропадает насовсем — в конфиге блока
	// уже нет, в метаданных записи больше нет, и оживить выданный клиенту
	// .conf нечем, — а освободившийся адрес уходит следующему клиенту.
	//
	// На атомарность rename здесь ссылаться НЕЛЬЗЯ: она защищает от рваного
	// ЧТЕНИЯ, а не от потерянной ЗАПИСИ по схеме load → чужой save → save.
	// Именно это рассуждение однажды и стояло в этом комментарии как
	// обоснование того, что read-пути лок не берут, — и стоило потери PSK
	// (ревью Task 13, Critical 2). Не возвращать.
	mu sync.Mutex
}

func New(iface config.Interface, listen string, r runtime.Runner) *Service {
	return &Service{
		iface:   iface,
		listen:  listen,
		r:       r,
		applier: NewApplier(r, iface.Interface, iface.Config, iface.Storage.Backups),
		keys:    NewKeyStore(iface.Storage.Keys),
	}
}

// Defaults читает умолчания интерфейса, при первом обращении создавая файл
// из секции client конфига. Ошибка чтения не роняет путь выдачи: она
// логируется, и панель работает на сиде — иначе один битый JSON лишил бы
// оператора доступа ко всем конфигам разом.
//
// Карта Extra в возвращаемом значении клонируется (cloneExtra) вторым
// рубежом защиты, а не потому что достижимый сегодня баг живёт здесь: сам
// алиасинг устранён в store.LoadDefaults (её ветка «файла ещё нет» —
// единственная, где он в принципе возможен, — теперь тоже клонирует, см.
// internal/store/defaults.go). Здесь seed вдобавок никогда не несёт
// непустую Extra: у config.Client, из которого он строится, такого поля
// нет вовсе. Клон оставлен на будущее — если LoadDefaults когда-нибудь
// перестанет копировать защитно (например, оптимизация переиспользует
// карту), эта строка не даст регрессии дотянуться до вызывающего кода
// (находка ревью «Долг задачи 2», task-5-report.md: раздел «Правки после
// ревью»).
//
// Берёт s.mu — отложенная находка ревью задачи 5: метод экспортирован, но
// до задачи 10 не брал мьютекс сам, и это было безопасно только потому, что
// ВСЕ тогдашние вызывающие (Add, Rotate, configFor) уже держали s.mu сами.
// GET /api/ifaces/{iface}/defaults (задача 10, web.handleGetDefaults) —
// первый вызывающий СНАРУЖИ пакета issuer, который s.mu подержать не может
// (поле не экспортировано), и его bootstrap-запись — создание defaults.json
// из сида при первом обращении, ниже — гонялась бы с одновременным
// SetDefaults: конкурентный PUT успевает сохранить присланные оператором
// умолчания, а GET, всё ещё выполняющий ветку created, следом перезаписывает
// их сидом из config.yaml поверх. Захват мьютекса здесь закрывает именно
// это окно. Выбор варианта — не «отдельный публичный метод», а именно лок в
// самом Defaults: два экспортируемых имени с разной семантикой блокировки
// («быстрый» и «безопасный Defaults») выглядели бы как случайность вызова
// не того метода, а не как осознанный контракт.
func (s *Service) Defaults() store.Defaults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.defaults()
}

// defaults — тело Defaults БЕЗ захвата мьютекса. sync.Mutex не реентрантен:
// вызывать эту версию можно только из кода, который s.mu уже держит сам
// (Add, Rotate, configFor — все трое сериализованы через s.mu.Lock() в
// начале своего тела). Второй Lock изнутри этих методов, если бы они звали
// экспортированный Defaults(), — гарантированный deadlock, а не гонка.
func (s *Service) defaults() store.Defaults {
	seed := store.Defaults{
		Endpoint: s.iface.Client.Endpoint, AllowedIPs: s.iface.Client.AllowedIPs,
		Keepalive: s.iface.Client.PersistentKeepalive, DNS: s.iface.Client.DNS,
		Jc: s.iface.Client.Jc, Jmin: s.iface.Client.Jmin, Jmax: s.iface.Client.Jmax,
	}
	d, created, err := store.LoadDefaults(s.iface.DefaultsPath(), seed)
	if err != nil {
		log.Printf("умолчания интерфейса %s: %v — работаю на значениях из config.yaml", s.iface.ID, err)
		seed.Version = store.DefaultsVersion
		return seed
	}
	if created {
		if err := d.Save(s.iface.DefaultsPath()); err != nil {
			log.Printf("создание defaults.json для %s: %v", s.iface.ID, err)
		}
	} else {
		// Файл уже существовал ДО этого вызова — секция client интерфейса в
		// config.yaml была сидом только при первом запуске и с этого момента
		// молча игнорируется. Печатаем это разово, а не на каждый вызов
		// defaults() — см. комментарий у поля Service.defaultsLoggedOnce.
		s.defaultsLoggedOnce.Do(func() {
			log.Printf("интерфейс %s: умолчания клиента читаются из %s — секция client в "+
				"config.yaml учтена только как сид при первом запуске и теперь игнорируется",
				s.iface.ID, s.iface.DefaultsPath())
		})
	}
	out := *d
	out.Extra = cloneExtra(d.Extra)
	return out
}

// cloneExtra возвращает независимую копию карты дополнительных client-side
// полей — см. комментарий у Defaults.
func cloneExtra(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SetDefaults сохраняет умолчания интерфейса после проверки ValidateDefaults
// (задача 3). Берёт s.mu не ради защиты собственного состояния Service (его
// здесь нет — умолчания живут только на диске), а чтобы конкурентная запись
// не гонялась сама с собой за одним и тем же defaults.json.
func (s *Service) SetDefaults(d store.Defaults) error {
	if err := ValidateDefaults(d); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return d.Save(s.iface.DefaultsPath())
}

// PeerView — то, что видит веб-интерфейс. Полных публичных ключей здесь
// нет: для опознания достаточно префикса, а показывать больше незачем.
//
// Overrides добавлен задачей 11: форма правки пира показывает плейсхолдером
// наследуемое из умолчаний значение и текущий персональный оверрайд поверх
// него, а PATCH ничего не возвращает, кроме {"status":"ok"} — List() здесь
// единственный источник. nil (в JSON — поле отсутствует благодаря omitempty)
// значит «оверрайдов нет вовсе», а не «оверрайды пустые»: то же самое
// различие, которое store.Overrides хранит указателями внутри себя (см. её
// комментарий), обязано пережить дорогу до браузера.
type PeerView struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Address        string           `json:"address"`
	PublicKeyShort string           `json:"public_key_short"`
	Enabled        bool             `json:"enabled"`
	LastHandshake  int64            `json:"last_handshake"`
	RxBytes        int64            `json:"rx_bytes"`
	TxBytes        int64            `json:"tx_bytes"`
	NeverConnected bool             `json:"never_connected"`
	CreatedAt      string           `json:"created_at"`
	Overrides      *store.Overrides `json:"overrides,omitempty"`
}

// readConf разбирает серверный конфиг с диска.
func (s *Service) readConf() (string, *wgconf.Config, error) {
	b, err := os.ReadFile(s.iface.Config)
	if err != nil {
		return "", nil, fmt.Errorf("чтение %s: %w", s.iface.Config, err)
	}
	c, err := wgconf.Parse(string(b))
	if err != nil {
		return "", nil, fmt.Errorf("разбор %s: %w", s.iface.Config, err)
	}
	return string(b), c, nil
}

// nameFromComment достаёт имя из строки "# awg3panel: <имя>" внутри блока.
func nameFromComment(block string) string {
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if after, ok := strings.CutPrefix(line, "# awg3panel:"); ok {
			return strings.TrimSpace(after)
		}
	}
	return ""
}

// loadState читает peers.json и приводит его в соответствие с конфигом.
//
// Пишет на диск, только если состояние ДЕЙСТВИТЕЛЬНО изменилось: List()
// опрашивается страницей раз в 10 секунд, и запись при каждом опросе —
// не порча (Save атомарен), но лишний износ. Неудачная запись логируется,
// но не приводит к ошибке: это read-путь, а данные к этому моменту уже
// вычислены и не должны пропадать из-за того, что их не удалось
// сохранить (ревью Task 10, Finding 2).
func (s *Service) loadState(raw string, c *wgconf.Config) (*store.State, error) {
	st, err := store.Load(s.iface.Storage.State)
	if err != nil {
		return nil, err
	}
	before := snapshotJSON(st)

	addrOf := map[string]string{}
	nameOf := map[string]string{}
	var pubs []string
	for _, p := range c.Peers {
		pub := p.Get("PublicKey")
		pubs = append(pubs, pub)
		addrOf[pub] = p.Get("AllowedIPs")
		if n := nameFromComment(p.Bytes(raw)); n != "" {
			nameOf[pub] = n
		}
	}
	st.Reconcile(pubs, func(pub string) string { return addrOf[pub] })
	// Имя из комментария имеет приоритет над сгенерированным peer-<id>,
	// но не затирает имя, заданное пользователем через панель.
	for i := range st.Peers {
		p := &st.Peers[i]
		if n, ok := nameOf[p.PublicKey]; ok && strings.HasPrefix(p.Name, "peer-") {
			p.Name = n
		}
	}

	if !bytes.Equal(before, snapshotJSON(st)) {
		if err := st.Save(s.iface.Storage.State); err != nil {
			log.Printf("сохранение %s: %v", s.iface.Storage.State, err)
		}
	}
	return st, nil
}

// snapshotJSON сериализует состояние для сравнения "было/стало". store.State
// содержит только строки, bool и слайс из таких же простых полей — сериализация
// этой конкретной структуры не может завершиться ошибкой, поэтому она здесь
// игнорируется осознанно, а не по невнимательности.
func snapshotJSON(st *store.State) []byte {
	b, _ := json.Marshal(st)
	return b
}

// List читает состав пиров и живой статус.
//
// Берёт s.mu, хотя выглядит как чистое чтение: через loadState он ПИШЕТ
// peers.json. Почему это обязано идти под общим локом — см. комментарий к
// полю Service.mu, раздел «ЧТЕНИЯ».
//
// Здесь только про цену: опрос страницы (раз в 10 секунд) ждёт окончания
// мутации, включая syncconf. Для панели с одним администратором это доли
// секунды раз в несколько дней — дешевле потерянного PSK.
func (s *Service) List() ([]PeerView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, c, err := s.readConf()
	if err != nil {
		return nil, err
	}
	st, err := s.loadState(raw, c)
	if err != nil {
		return nil, err
	}
	dumpText, err := s.r.Show(s.iface.Interface)
	if err != nil {
		return nil, fmt.Errorf("awg show: %w", err)
	}
	dump, err := runtime.ParseDump(dumpText)
	if err != nil {
		return nil, err
	}
	live := make(map[string]runtime.DumpPeer, len(dump))
	for _, p := range dump {
		live[p.PublicKey] = p
	}

	views := make([]PeerView, 0, len(st.Peers))
	for _, p := range st.Peers {
		v := PeerView{
			ID: p.ID, Name: p.Name, Address: p.Address,
			PublicKeyShort: shortKey(p.PublicKey),
			Enabled:        p.Enabled, CreatedAt: p.CreatedAt,
			// Указатель делится тем же объектом, что лежит в st.Peers, а не
			// клонируется: ничего не мутирует Overrides НА МЕСТЕ (Update
			// переставляет указатель pp.Overrides = patch.Overrides целиком,
			// см. её комментарий), поэтому alias безопасен даже после
			// возврата List() и снятия мьютекса.
			Overrides: p.Overrides,
		}
		if d, ok := live[p.PublicKey]; ok {
			v.LastHandshake = d.LatestHandshake
			v.RxBytes, v.TxBytes = d.RxBytes, d.TxBytes
		}
		// Отключённый пир не «никогда не подключался» — он просто выключен.
		v.NeverConnected = p.Enabled && v.LastHandshake == 0
		views = append(views, v)
	}
	sort.Slice(views, func(i, j int) bool {
		return addrLess(views[i].Address, views[j].Address)
	})
	return views, nil
}

// addrLess сравнивает адреса численно, чтобы 10.0.0.10 шёл после 10.0.0.9,
// а не между .1 и .2, как при строковой сортировке.
//
// Порядок обязан быть тотальным — sort.Slice требует строгий слабый
// порядок и при его нарушении не паникует, а молча даёт неопределённый
// результат. Прежняя версия сравнивала ЦЕЛИКОМ строково, если хотя бы один
// из двух адресов не разбирался, и это ловило цикл: A="10.0.0.9"
// (разбирается) < B="10.0.0.10" (разбирается) — численно, но B < C и
// C < A для неразбираемого C — строково (ревью Task 10, Finding 1).
// addrOf[pub] в loadState может быть пустой строкой (у пира в конфиге нет
// AllowedIPs) — она тоже не разбирается, так что триггер реален, а не
// гипотетический.
//
// Разбиение по случаям: оба разбираются → численно; ровно один не
// разбирается → он идёт ПОСЛЕ разбираемого, с какой бы стороны вызова ни
// оказался; оба не разбираются → строковый тай-брейк. Это тотальный
// порядок: иррефлексивность, асимметрия и транзитивность проверены на
// разбираемых и неразбираемых адресах в TestAddrLess* (service_internal_test.go).
func addrLess(a, b string) bool {
	ia, ea := netip.ParseAddr(HostIP(a))
	ib, eb := netip.ParseAddr(HostIP(b))
	switch {
	case ea == nil && eb == nil:
		return ia.Less(ib)
	case ea == nil:
		return true // a разбирается, b — нет: разбираемые всегда раньше
	case eb == nil:
		return false // a не разбирается, b разбирается: a идёт позже
	default:
		return a < b // оба не разбираются — строковый тай-брейк
	}
}

// ListenAddr возвращает адрес, на котором слушает демон (s.listen — то же
// значение cfg.Listen, с которым Service был создан через New).
//
// Единственный потребитель — CLI-мутации (cmd/awg3panel/cli.go,
// refuseIfDaemonRunning, Task 14): Service.mu (см. комментарий к полю)
// сериализует мутации только внутри ОДНОГО процесса, а CLI-команда — это
// отдельный процесс со своим экземпляром Service и своим мьютексом. Чтобы
// CLI мог хотя бы посоветоваться сам с собой о том, не занят ли этот адрес
// демоном, ему нужен доступ к этому значению — без протаскивания
// *config.Config через сигнатуру runCLI, которая фиксирована планом задачи.
func (s *Service) ListenAddr() string {
	return s.listen
}

// ServerPublicKey вычисляет публичный ключ сервера из приватного через
// awg pubkey — единый источник, без отдельного .pub-файла, который может
// разъехаться с конфигом (раздел 7.3 спеки).
func (s *Service) ServerPublicKey() (string, error) {
	_, c, err := s.readConf()
	if err != nil {
		return "", err
	}
	priv := c.Interface.Get("PrivateKey")
	if priv == "" {
		return "", fmt.Errorf("в серверном [Interface] нет PrivateKey")
	}
	return s.r.PubKey(priv)
}

// --- Мутации (Task 13). Любая из них проходит через Applier.Apply, то есть
// через полный инвариант раздела 6 спеки: снимок → бэкап → атомарная запись →
// syncconf → проверка постусловия → откат при расхождении. Обхода нет и не
// должно появиться: awg3.conf меняется только текстовой хирургией блоков
// [Peer] из wgconf, секция [Interface] копируется побайтово. ---

// Issued — результат выпуска пира.
type Issued struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Config  string `json:"config"`
	QRPNG   []byte `json:"-"`
}

const maxNameLen = 40

// validateName приводит имя к каноническому виду и отвергает то, что нельзя
// записать в конфиг. Сообщения об ошибках НЕ повторяют само имя: оно уедет в
// лог через writeError, а лог — не место для пользовательских данных сверх
// необходимого (CLAUDE.md, п. 4; ревью Task 11).
func validateName(name string) (string, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return "", fmt.Errorf("%w: имя пира не может быть пустым", ErrInvalidInput)
	}
	if len([]rune(n)) > maxNameLen {
		return "", fmt.Errorf("%w: имя длиннее %d символов", ErrInvalidInput, maxNameLen)
	}
	if strings.ContainsAny(n, "\r\n") {
		return "", fmt.Errorf("%w: имя содержит перевод строки", ErrInvalidInput)
	}
	// Те же символы отвергает wgconf.PeerSpec.validate — имя уезжает в конфиг
	// комментарием, и заголовок секции внутри него был бы инъекцией. Проверка
	// продублирована здесь не ради второй линии обороны, а ради КОДА ответа:
	// отказ из wgconf случился бы уже внутри Apply и ушёл бы пользователю как
	// 500 «внутренняя ошибка», из которой невозможно понять, что не так с
	// именем. Здесь он остаётся тем, чем является, — ошибкой ввода (400).
	if strings.ContainsAny(n, "[]") {
		return "", fmt.Errorf("%w: имя содержит квадратные скобки", ErrInvalidInput)
	}
	return n, nil
}

// sameHost сравнивает два адреса по ХОСТОВОЙ части, игнорируя маску:
// "10.0.0.4/32" и "10.0.0.4/24" — один и тот же адрес, и второй занимает
// его ничуть не меньше первого. Если хотя бы один из двух не разбирается как
// IP, сравнение падает обратно на строковое равенство — так неразбираемый
// мусор в конфиге не начинает молча совпадать со всем подряд.
func sameHost(a, b string) bool {
	ha := HostIP(strings.TrimSpace(a))
	hb := HostIP(strings.TrimSpace(b))
	ipa, ea := netip.ParseAddr(ha)
	ipb, eb := netip.ParseAddr(hb)
	if ea == nil && eb == nil {
		return ipa == ipb
	}
	return ha != "" && ha == hb
}

// peerHoldingAddress возвращает секцию первого пира конфига, чьи AllowedIPs
// содержат адрес addr. AllowedIPs разбивается по запятой: пир вправе нести
// несколько префиксов, и адрес, спрятанный вторым в списке, занят ровно так
// же, как единственный.
func peerHoldingAddress(c *wgconf.Config, addr string) (*wgconf.Section, bool) {
	if strings.TrimSpace(addr) == "" {
		return nil, false
	}
	for _, sec := range c.Peers {
		for _, part := range strings.Split(sec.Get("AllowedIPs"), ",") {
			if sameHost(part, addr) {
				return sec, true
			}
		}
	}
	return nil, false
}

// usedAddresses собирает все занятые адреса: живые пиры плюс отключённые,
// чьи адреса обязаны остаться зарезервированными до включения обратно.
func usedAddresses(c *wgconf.Config, st *store.State) []string {
	var used []string
	for _, p := range c.Peers {
		used = append(used, strings.Split(p.Get("AllowedIPs"), ",")...)
	}
	for _, p := range st.Peers {
		if !p.Enabled && p.Address != "" {
			used = append(used, p.Address)
		}
	}
	return used
}

// Add выпускает нового пира: генерирует ключи, выделяет адрес, добавляет блок
// [Peer] в серверный конфиг и возвращает готовый клиентский конфиг с QR.
//
// Порядок шагов выбран так, чтобы ВСЁ, что может отказать без последствий,
// отказывало ДО применения к живому устройству: клиентский конфиг и QR
// собираются раньше Apply, хотя нужны только после него. Иначе отказ рендера
// (неполная обфускация, противоречивая тройка джиттера) оставлял бы пира на
// сервере, а оператору возвращал ошибку — то есть расхождение между тем, что
// видит оператор, и тем, что применено. После Apply остаются только шаги
// записи на диск, и первый из них — приватный ключ (задача 5): пир без
// ключа в хранилище бесполезен — выдать ему конфиг нечем, — а ключ без пира
// на сервере лечит Rotate.
//
// Если keys.Put здесь откажет, st.Upsert и st.Save НИЖЕ НЕ ВЫПОЛНЯТСЯ (см.
// return сразу после keys.Put): пир остаётся на устройстве, но НЕ отслежен
// в peers.json до следующего согласования (Reconcile внутри List/ConfigFor/
// QRFor). Это осознанный размен, а не пропущенный шаг: записать метаданные
// без ключа значило бы показать панели пира, которому нечем выдать
// конфиг, — а отсутствие ключа в хранилище лечится тем же Rotate, что и
// любой другой пир без ключа (находка ревью задачи 5: прежняя версия этого
// комментария утверждала обратное — что пир «хотя бы виден в панели» — это
// было верно для старого порядка шагов, где метаданные писались раньше
// ключа, и осталось в тексте после смены порядка).
//
// Клиентский конфиг собирается через Effective(Defaults(), nil, ...) — тот
// же путь, которым позже пойдёт ConfigFor (у свежего пира оверрайдов ещё
// нет). Единая точка сборки — не только DRY: раньше Add печатал поля прямо
// из s.iface.Client.*, минуя Defaults() и Extra, и первый же ConfigFor после
// правки умолчаний вернул бы клиенту ДРУГОЙ конфиг, чем показанный при
// выпуске.
func (s *Service) Add(name string) (*Issued, error) {
	n, err := validateName(name)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, c, err := s.readConf()
	if err != nil {
		return nil, err
	}
	st, err := s.loadState(raw, c)
	if err != nil {
		return nil, err
	}
	obf, err := ExtractObfuscation(c.Interface)
	if err != nil {
		return nil, err
	}
	addr, err := AllocateAddress(c.Interface.Get("Address"), usedAddresses(c, st))
	if err != nil {
		return nil, err
	}
	serverPub, err := s.ServerPublicKey()
	if err != nil {
		return nil, err
	}
	priv, err := s.r.GenKey()
	if err != nil {
		return nil, fmt.Errorf("генерация ключа: %w", err)
	}
	pub, err := s.r.PubKey(priv)
	if err != nil {
		return nil, fmt.Errorf("вычисление публичного ключа: %w", err)
	}
	psk, err := s.r.GenPSK()
	if err != nil {
		return nil, fmt.Errorf("генерация PSK: %w", err)
	}

	e := Effective(s.defaults(), nil, c.Interface.Get("MTU"))
	clientConf, err := RenderClientConfig(ClientParams{
		PrivateKey: priv, Address: addr, ServerPublicKey: serverPub, PresharedKey: psk,
		Endpoint: e.Endpoint, AllowedIPs: e.AllowedIPs, Keepalive: e.Keepalive,
		DNS: e.DNS, MTU: e.MTU, Obfuscation: obf,
		Jc: e.Jc, Jmin: e.Jmin, Jmax: e.Jmax, Extra: e.Extra,
	})
	if err != nil {
		return nil, fmt.Errorf("сборка клиентского конфига: %w", err)
	}
	qr, err := QRPNG(clientConf)
	if err != nil {
		return nil, fmt.Errorf("генерация QR: %w", err)
	}

	spec := wgconf.PeerSpec{Name: n, PublicKey: pub, PresharedKey: psk, AllowedIPs: addr}
	mutate := func(text string) (string, error) { return wgconf.AppendPeer(text, spec) }
	if err := s.applier.Apply(mutate, Expect{Added: []string{pub}}); err != nil {
		return nil, err
	}

	id := store.PeerID(pub)
	slug := st.UniqueSlug(n)
	if err := s.keys.Put(id, priv); err != nil {
		return nil, fmt.Errorf("пир добавлен на сервер, но сохранить приватный ключ не удалось: %w", err)
	}
	st.Upsert(store.Peer{
		ID: id, Name: n, PublicKey: pub, Address: addr, Slug: slug,
		CreatedAt: time.Now().UTC().Format(time.RFC3339), Enabled: true,
	})
	if err := st.Save(s.iface.Storage.State); err != nil {
		return nil, fmt.Errorf("пир добавлен на сервер, но записать метаданные не удалось: %w", err)
	}
	log.Printf("выпущен пир id=%s адрес=%s", id, addr)

	return &Issued{ID: id, Name: n, Address: addr, Config: clientConf, QRPNG: qr}, nil
}

// peerByID читает конфиг и метаданные и возвращает КОПИЮ записи пира.
//
// Именно копию, а не *store.Peer: указатель от store.Get смотрит внутрь
// слайса State.Peers и действителен только до следующего Upsert, Delete или
// Reconcile (см. комментарий к store.Get). Все мутации ниже держат запись
// пира через вызов Apply — долгий, с записью файла, syncconf и возможным
// откатом, — и дописывают в неё PSK уже после него. Работа с копией делает
// запись в устаревший слот физически невозможной: настоящая запись берётся
// отдельным Get непосредственно перед изменением и Save (см. updatePeer).
func (s *Service) peerByID(id string) (string, *wgconf.Config, *store.State, store.Peer, error) {
	raw, c, err := s.readConf()
	if err != nil {
		return "", nil, nil, store.Peer{}, err
	}
	st, err := s.loadState(raw, c)
	if err != nil {
		return "", nil, nil, store.Peer{}, err
	}
	p, ok := st.Get(id)
	if !ok {
		return "", nil, nil, store.Peer{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return raw, c, st, *p, nil
}

// updatePeer изменяет ЖИВУЮ запись пира и сразу сохраняет состояние.
// Указатель берётся здесь и умирает здесь же: между Get и Save не
// вклинивается ничего, что могло бы переаллоцировать State.Peers.
func (s *Service) updatePeer(st *store.State, id string, fn func(*store.Peer)) error {
	p, ok := st.Get(id)
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	fn(p)
	return st.Save(s.iface.Storage.State)
}

func (s *Service) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, st, p, err := s.peerByID(id)
	if err != nil {
		return err
	}
	if p.Enabled {
		pub := p.PublicKey
		mutate := func(text string) (string, error) {
			return wgconf.RemovePeerByPublicKey(text, pub)
		}
		if err := s.applier.Apply(mutate, Expect{Removed: []string{pub}}); err != nil {
			return err
		}
	}
	st.Delete(id)
	if err := st.Save(s.iface.Storage.State); err != nil {
		return err
	}
	// Ключ удаляется ПОСЛЕДНИМ, после успешного st.Save: если запись
	// метаданных отказала, пир формально ещё существует (не был бы найден на
	// следующем чтении, если бы ключ уже пропал, — Rotate не лечит
	// отсутствующего в peers.json пира). Отказ удаления — не повод срывать
	// уже состоявшееся удаление пира с сервера и из метаданных: он лишь
	// логируется, тем же best-effort стилем, каким раньше игнорировалась
	// ошибка удаления legacy clients/<slug>.conf.
	if err := s.keys.Delete(id); err != nil {
		log.Printf("удаление приватного ключа пира id=%s: %v", id, err)
	}
	log.Printf("удалён пир id=%s", id)
	return nil
}

// Disable вырезает блок [Peer] из конфига, сохраняя PSK и адрес в peers.json:
// без них обратное включение выдало бы клиенту другой туннель.
func (s *Service) Disable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, c, st, p, err := s.peerByID(id)
	if err != nil {
		return err
	}
	if !p.Enabled {
		return nil // идемпотентно
	}
	sec, ok := wgconf.FindPeer(c, p.PublicKey)
	if !ok {
		// Защитная ветка: через loadState она недостижима — Reconcile
		// оставляет Enabled=true только пирам, найденным в конфиге, а
		// отключённые отсеиваются проверкой выше. Класс всё равно проставлен:
		// это состояние, требующее вмешательства человека, и если ветка
		// когда-нибудь оживёт, оператор должен прочитать причину, а не
		// «внутреннюю ошибку», неотличимую от случайного сбоя.
		return fmt.Errorf("%w: пир %s есть в метаданных, но не в конфиге", ErrInvalidInput, id)
	}
	psk := sec.Get("PresharedKey")
	addr := sec.Get("AllowedIPs")
	// Пир без PresharedKey отключать НЕЛЬЗЯ: сохранять в peers.json нечего, а
	// Enable собирает блок через wgconf.AppendPeer, который требует непустой
	// PresharedKey, — то есть обратно такой пир уже не вернуть, и ключевой
	// материал останется только в бэкапе awg3.conf. Пиры, заведённые вручную
	// до установки панели, бывают без PSK (на боевом сервере такой есть),
	// поэтому это рабочий сценарий, а не теория. Отказ ДО касания живого
	// устройства честнее, чем молча оборвать клиента навсегда.
	if psk == "" {
		return fmt.Errorf("%w: у пира %s нет PresharedKey в серверном конфиге — "+
			"отключение сделало бы его невосстановимым", ErrInvalidInput, id)
	}

	// PSK сохраняется ДО применения, пир при этом остаётся включённым.
	// Apply защищает пару «файл ↔ устройство», но не пару «конфиг ↔
	// peers.json»: если писать PSK после вырезания блока, смерть процесса
	// или отказ st.Save (диск полон, EIO) в этом промежутке уничтожают
	// единственную копию PSK — без всякой конкуренции. Порядок «сначала
	// сохранить секрет, потом убрать его источник» переносит риск в
	// безобидную сторону: лишняя копия PSK у включённого пира не мешает
	// ничему и вычищается ближайшим Reconcile (store.go: у пира,
	// присутствующего в конфиге, PresharedKey обнуляется).
	if err := s.updatePeer(st, id, func(p *store.Peer) {
		p.PresharedKey = psk
		p.Address = addr
	}); err != nil {
		return fmt.Errorf("сохранение PSK перед отключением: %w", err)
	}

	pub := p.PublicKey
	mutate := func(text string) (string, error) {
		return wgconf.RemovePeerByPublicKey(text, pub)
	}
	if err := s.applier.Apply(mutate, Expect{Removed: []string{pub}}); err != nil {
		return err
	}
	// Пометка «выключен» — строго ПОСЛЕ успешного применения: при отказе пир
	// остаётся включённым и в конфиге, и в метаданных, то есть панель не
	// врёт про состояние устройства.
	if err := s.updatePeer(st, id, func(p *store.Peer) {
		p.Enabled = false
	}); err != nil {
		return err
	}
	log.Printf("отключён пир id=%s", id)
	return nil
}

func (s *Service) Enable(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, st, p, err := s.peerByID(id)
	if err != nil {
		return err
	}
	if p.Enabled {
		return nil // идемпотентно
	}
	if p.PresharedKey == "" {
		return fmt.Errorf("%w: у пира %s не сохранён PSK — восстановить подключение нельзя, "+
			"выпустите нового", ErrInvalidInput, id)
	}
	spec := wgconf.PeerSpec{
		Name: p.Name, PublicKey: p.PublicKey,
		PresharedKey: p.PresharedKey, AllowedIPs: p.Address,
	}
	// Проверка занятости адреса стоит ВНУТРИ замыкания, а не выше по коду:
	// сюда Apply передаёт текст, прочитанный уже под своим мьютексом и после
	// предварительной сверки с устройством, — то есть самый свежий, какой
	// вообще доступен. Пока пир отключён, его адрес зарезервирован только в
	// peers.json: блока [Peer] в конфиге нет, и занять адрес мимо панели
	// может как пир, заведённый руками, так и второй процесс (CLI против
	// демона — остаточная гонка, оставленная незакрытой сознательно).
	// Собственных рубежей против этого не было: AppendPeer ловит повтор
	// PublicKey, но не повтор AllowedIPs, а checkPostcondition выводит
	// exp.Added из-под ВСЕХ проверок пиров, — и Enable молча
	// разводил двух клиентов на одном IP (ревью финальное, I3).
	mutate := func(text string) (string, error) {
		c, err := wgconf.Parse(text)
		if err != nil {
			return "", fmt.Errorf("исходный конфиг не разбирается: %w", err)
		}
		if other, taken := peerHoldingAddress(c, p.Address); taken {
			return "", fmt.Errorf("%w: адрес %s пира %s занят другим пиром %s в серверном конфиге — "+
				"включение развело бы два клиента на одном IP; освободите адрес "+
				"или выпустите нового пира", ErrInvalidInput, p.Address, id,
				shortKey(other.Get("PublicKey")))
		}
		return wgconf.AppendPeer(text, spec)
	}
	if err := s.applier.Apply(mutate, Expect{Added: []string{p.PublicKey}}); err != nil {
		return err
	}
	// PSK стирается из метаданных только после того, как он снова оказался в
	// конфиге. Стереть его раньше (или на пути отказа) значит потерять
	// единственную копию: в конфиге пира нет, и оживить выданный клиенту
	// файл будет уже нечем.
	if err := s.updatePeer(st, id, func(p *store.Peer) {
		p.Enabled = true
		p.PresharedKey = "" // снова живёт в конфиге
	}); err != nil {
		return err
	}
	log.Printf("включён пир id=%s", id)
	return nil
}

// normalizeAddress приводит адрес пира к виду "IP/32". Оператор вправе
// написать и "10.0.0.7", и "10.0.0.7/32" — в серверном конфиге это одна и
// та же строка AllowedIPs, и различие форм привело бы к тому, что usedAddresses
// не узнаёт занятый адрес в другой записи.
func normalizeAddress(s string) (string, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return "", fmt.Errorf("%w: адрес пуст", ErrInvalidInput)
	}
	if !strings.Contains(v, "/") {
		v += "/32"
	}
	pfx, err := netip.ParsePrefix(v)
	if err != nil {
		return "", fmt.Errorf("%w: адрес %q не разбирается: %v", ErrInvalidInput, s, err)
	}
	if !pfx.Addr().Is4() || pfx.Bits() != 32 {
		return "", fmt.Errorf("%w: адрес пира должен быть одиночным IPv4 вида 10.0.0.7/32", ErrInvalidInput)
	}
	return pfx.String(), nil
}

// checkAddressFree проверяет, что адрес лежит в подсети сервера и не занят
// кем-то, кроме самого пира selfID.
func checkAddressFree(c *wgconf.Config, st *store.State, selfID, addr string) error {
	serverAddr := c.Interface.Get("Address")
	net, err := netip.ParsePrefix(serverAddr)
	if err != nil {
		return fmt.Errorf("Address сервера %q не разбирается: %w", serverAddr, err)
	}
	want, _ := netip.ParsePrefix(addr) // уже нормализован
	if !net.Contains(want.Addr()) {
		return fmt.Errorf("%w: адрес %s вне подсети сервера %s", ErrInvalidInput, addr, net)
	}
	if want.Addr() == net.Addr() || want.Addr().String() == HostIP(serverAddr) {
		return fmt.Errorf("%w: адрес %s занят самим сервером", ErrInvalidInput, addr)
	}
	for _, p := range st.Peers {
		if p.ID == selfID {
			continue
		}
		if p.Address == addr {
			return fmt.Errorf("%w: адрес %s уже занят пиром %q", ErrInvalidInput, addr, p.Name)
		}
	}
	if sec, ok := peerHoldingAddress(c, addr); ok {
		if pub := sec.Get("PublicKey"); pub != "" {
			if own, found := st.Get(selfID); !found || own.PublicKey != pub {
				return fmt.Errorf("%w: адрес %s занят пиром в серверном конфиге", ErrInvalidInput, addr)
			}
		}
	}
	return nil
}

// PeerPatch — частичная правка пира. Указатели различают «поле не прислали»
// и «поле прислали». Overrides заменяются ЦЕЛИКОМ, а не сливаются по полям:
// сброс оверрайда в наследование выражается его отсутствием в присланном
// объекте, и слияние сделало бы сброс невыразимым (раздел 8 спеки).
type PeerPatch struct {
	Name      *string          `json:"name"`
	Address   *string          `json:"address"`
	Overrides *store.Overrides `json:"overrides"`
}

// Update правит имя, адрес и/или клиентские оверрайды уже выпущенного пира.
//
// Серверный конфиг трогается только теми полями, что в нём реально хранятся —
// имя (комментарий блока) и адрес (AllowedIPs) — и только если у пира вообще
// есть блок [Peer]: у отключённого его нет, менять там нечего, а новое имя
// или адрес уедут на сервер при следующем Enable (он строит блок из
// актуальной записи peers.json). Оверрайды в awg3.conf не попадают никогда —
// они участвуют только в сборке клиентского конфига (configFor).
//
// Патч без единого действительного изменения возвращается ДО бэкапа и
// Apply: мутация ради нуля изменений — лишний риск на живом устройстве.
func (s *Service) Update(id string, patch PeerPatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, c, st, p, err := s.peerByID(id)
	if err != nil {
		return err
	}

	newName := p.Name
	if patch.Name != nil {
		n, err := validateName(*patch.Name)
		if err != nil {
			return err
		}
		newName = n
	}
	newAddr := p.Address
	if patch.Address != nil {
		a, err := normalizeAddress(*patch.Address)
		if err != nil {
			return err
		}
		if err := checkAddressFree(c, st, id, a); err != nil {
			return err
		}
		newAddr = a
	}
	if patch.Overrides != nil {
		if err := ValidateOverrides(patch.Overrides); err != nil {
			return err
		}
	}

	nameChanged := newName != p.Name
	addrChanged := newAddr != p.Address
	if !nameChanged && !addrChanged && patch.Overrides == nil {
		return nil // нечего менять — до syncconf дело не доходит
	}

	// Серверный конфиг трогаем, только если пир в нём есть и меняется то, что
	// в нём записано: имя (комментарий) или адрес (AllowedIPs).
	sec, inConf := wgconf.FindPeer(c, p.PublicKey)
	if inConf && (nameChanged || addrChanged) {
		spec := wgconf.PeerSpec{
			Name: newName, PublicKey: p.PublicKey,
			PresharedKey: sec.Get("PresharedKey"), AllowedIPs: newAddr,
		}
		exp := Expect{}
		if addrChanged {
			exp.Modified = []ExpectedPeerChange{{
				PublicKey: p.PublicKey, AllowedIPs: newAddr, HandshakeMayReset: true,
			}}
		}
		mutate := func(text string) (string, error) {
			return wgconf.ReplacePeerBlock(text, p.PublicKey, spec)
		}
		if err := s.applier.Apply(mutate, exp); err != nil {
			return err
		}
	}

	if err := s.updatePeer(st, id, func(pp *store.Peer) {
		pp.Name = newName
		pp.Address = newAddr
		if patch.Overrides != nil {
			pp.Overrides = normalizeOverrides(patch.Overrides)
		}
	}); err != nil {
		return err
	}
	log.Printf("изменён пир id=%s (имя:%v адрес:%v оверрайды:%v)",
		id, nameChanged, addrChanged, patch.Overrides != nil)
	return nil
}

// normalizeOverrides возвращает nil, если o не хранит НИ ОДНОГО значимого
// поля (все указатели nil и Extra пуст) — такой объект неотличим по
// содержанию от «оверрайдов нет вовсе» и не должен занимать это место в
// peers.json (находка ревью задачи 11).
//
// index.html пересобирает и шлёт "overrides" целиком при КАЖДОМ сохранении
// формы правки пира — включая случай «менял только имя» — а пир без единого
// персонального значения даёт для этого поля пустой, но НЕ nil указатель
// (JSON "overrides":{}, не отсутствие ключа: см. комментарий у PeerPatch).
// Без этой нормализации naive `pp.Overrides = patch.Overrides` превратил бы
// nil в &store.Overrides{} на первом же сохранении ЛЮБОЙ формы, разрушив
// именно то различие, ради которого PeerView.Overrides введён.
//
// Явно пустая строка (например, DNS — указатель на "") НЕ считается пустым
// полем: она несёт собственный сигнал «наследовать нельзя, задано явно
// пусто» (раздел 5.3 спеки) и обязана остаться отличимой от отсутствия
// поля — именно поэтому проверка смотрит на nil-ность УКАЗАТЕЛЕЙ, а не на
// нулевые значения того, на что они указывают.
func normalizeOverrides(o *store.Overrides) *store.Overrides {
	if o == nil {
		return nil
	}
	if o.DNS != nil || o.AllowedIPs != nil || o.Keepalive != nil || o.MTU != nil ||
		o.Endpoint != nil || o.Jc != nil || o.Jmin != nil || o.Jmax != nil || len(o.Extra) > 0 {
		return o
	}
	return nil
}

// Rotate выдаёт пиру новую пару ключей и новый PSK, сохраняя id, имя и адрес.
//
// id намеренно НЕ пересчитывается от нового публичного ключа: он назначается
// при выпуске и живёт дальше как исторический (раздел 7.2 спеки). Иначе
// ротация меняла бы URL пира, имя файла с приватным ключом и все ссылки,
// которые оператор успел кому-то отдать.
//
// На устройстве смена публичного ключа — это не изменение пира, а замена
// одного другим, поэтому ожидание описывается как Removed+Added.
func (s *Service) Rotate(id string) (*Issued, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.checkRotateStateMatchesServer(id); err != nil {
		return nil, err
	}

	_, c, st, p, err := s.peerByID(id)
	if err != nil {
		return nil, err
	}
	priv, err := s.r.GenKey()
	if err != nil {
		return nil, fmt.Errorf("генерация ключа: %w", err)
	}
	pub, err := s.r.PubKey(priv)
	if err != nil {
		return nil, fmt.Errorf("вычисление публичного ключа: %w", err)
	}
	psk, err := s.r.GenPSK()
	if err != nil {
		return nil, fmt.Errorf("генерация PSK: %w", err)
	}

	// Всё, что может отказать без последствий, — до применения к устройству.
	obf, err := ExtractObfuscation(c.Interface)
	if err != nil {
		return nil, err
	}
	serverPub, err := s.ServerPublicKey()
	if err != nil {
		return nil, err
	}
	e := Effective(s.defaults(), p.Overrides, c.Interface.Get("MTU"))
	clientConf, err := RenderClientConfig(ClientParams{
		PrivateKey: priv, Address: p.Address, ServerPublicKey: serverPub, PresharedKey: psk,
		Endpoint: e.Endpoint, AllowedIPs: e.AllowedIPs, Keepalive: e.Keepalive,
		DNS: e.DNS, MTU: e.MTU, Obfuscation: obf,
		Jc: e.Jc, Jmin: e.Jmin, Jmax: e.Jmax, Extra: e.Extra,
	})
	if err != nil {
		return nil, fmt.Errorf("сборка клиентского конфига: %w", err)
	}
	qr, err := QRPNG(clientConf)
	if err != nil {
		return nil, fmt.Errorf("генерация QR: %w", err)
	}

	if _, inConf := wgconf.FindPeer(c, p.PublicKey); inConf {
		spec := wgconf.PeerSpec{
			Name: p.Name, PublicKey: pub, PresharedKey: psk, AllowedIPs: p.Address,
		}
		mutate := func(text string) (string, error) {
			return wgconf.ReplacePeerBlock(text, p.PublicKey, spec)
		}
		if err := s.applier.Apply(mutate, Expect{
			Added: []string{pub}, Removed: []string{p.PublicKey},
		}); err != nil {
			return nil, err
		}
	}

	// Ключ на диск — после применения: ключ без пира на сервере бесполезен,
	// а пир без ключа — ровно тот случай, который эта команда и лечит (пока
	// peers.json ещё совпадает с сервером — расхождение отсеяно проверкой в
	// самом начале функции, до генерации этого самого ключа).
	if err := s.keys.Put(id, priv); err != nil {
		return nil, fmt.Errorf("ключи пира заменены на сервере, но сохранить приватный ключ не удалось: %w", err)
	}
	wasEnabled := p.Enabled
	if err := s.updatePeer(st, id, func(pp *store.Peer) {
		pp.PublicKey = pub
		if !wasEnabled {
			// У отключённого пира блока в конфиге нет — PSK негде жить, кроме
			// peers.json (та же причина, по которой его хранит Disable).
			pp.PresharedKey = psk
		}
	}); err != nil {
		// Голая ошибка здесь выглядела бы так же, как отказ на любом более
		// раннем и безобидном шаге — но к этому моменту устройство и
		// хранилище ключей УЖЕ несут новый ключ, только peers.json не успел:
		// та же асимметрия цены, что и у соседнего keys.Put, и то же самое
		// расхождение, которое ловит checkRotateStateMatchesServer при
		// следующем обращении к этому пиру.
		return nil, fmt.Errorf("ключи пира заменены на сервере и в хранилище, но записать новые "+
			"метаданные не удалось: %w — peers.json теперь расходится с сервером, следующая "+
			"попытка откажет тем же расхождением", err)
	}
	log.Printf("ротация ключей пира id=%s", id)
	return &Issued{ID: id, Name: p.Name, Address: p.Address, Config: clientConf, QRPNG: qr}, nil
}

// checkRotateStateMatchesServer обнаруживает расхождение peers.json с
// серверным конфигом ДО обычного peerByID — тот вызывает loadState →
// store.Reconcile на КАЖДОМ обращении, а для пира, который ЧИСЛИТСЯ
// включённым (Enabled=true), но не найден в текущем конфиге, Reconcile
// действует не отказом, а «самолечением»: молча УДАЛЯЕТ такую запись из
// peers.json (см. её собственный комментарий — «нет в конфиге, включён →
// удалить, убран из конфига мимо панели») и, если конфиг сейчас содержит
// пира на том же адресе, заводит взамен новую запись с ДРУГИМ id, посчитанным
// от текущего публичного ключа устройства.
//
// Это осмысленный компромисс, когда пира ДЕЙСТВИТЕЛЬНО убрали руками мимо
// панели, — но губительный ровно тогда, когда причина расхождения другая:
// прошлая ротация успела заменить ключ пира на устройстве (Apply прошёл), а
// следующий шаг (keys.Put/updatePeer) отказал ДО того, как новый PublicKey
// попал в peers.json. Тогда peers.json ещё хранит СТАРЫЙ ключ, конфиг — уже
// НОВЫЙ, и первый же вызов ЛЮБОГО метода, идущего через peerByID (не только
// повторная ротация — так же сработали бы List, ConfigFor, Enable, Disable,
// Update), молча стирает id/slug/created_at/оверрайды этого пира и подменяет
// его фантомной записью — то есть гарантия задачи 9 «id переживает ротацию»
// нарушается тем же кодом, который её обеспечивает.
//
// Проверено эмпирически (находка ревью задач 8-9, раздел «Правка после
// ревью: расхождение состояния в Rotate», task-8-9-report.md): буквальное
// описание симптома находки («повторный Rotate трактует inConf==false как
// «отключён» и молча пишет третий ключ, возвращая nil») в реальности не
// воспроизводится — Reconcile успевает стереть улику раньше, чем тело Rotate
// до неё доберётся, и повторный вызов падает на peerByID с ErrNotFound.
// Настоящая потеря происходит МОЛЧА, на файле, ещё до этого возврата.
// Поэтому проверка здесь читает peers.json НАПРЯМУЮ через store.Load, минуя
// loadState/Reconcile целиком, — самолечению просто нечего лечить, если оно
// не вызывается.
//
// Класс ошибки — ErrStateConflict, не ErrPostcondition (находка финального
// ревью, I4): см. комментарий у ErrStateConflict. Текст НЕ советует «откройте
// список пиров, чтобы согласовать состояние» — этот совет и есть
// разрушительное действие: список опрашивается вебом каждые 10 секунд, а
// один List() на расходящемся состоянии — это и есть то самое самолечение
// Reconcile, описанное выше в комментарии к функции, — оно выбрасывает
// запись и заводит новую с другим id, теряя id, slug, дату выпуска и
// персональные оверрайды пира. Структурная починка (согласование, не
// выбрасывающее запись) в этой версии не сделана — текст честно предупреждает
// о цене автоматического согласования вместо того, чтобы советовать вызвать
// его вручную.
func (s *Service) checkRotateStateMatchesServer(id string) error {
	_, c, err := s.readConf()
	if err != nil {
		return err
	}
	st, err := store.Load(s.iface.Storage.State)
	if err != nil {
		return nil // peerByID прочитает то же самое и вернёт содержательную ошибку сам
	}
	p, ok := st.Get(id)
	if !ok || !p.Enabled {
		return nil // нет записи или пир легитимно отключён — блока и не должно быть
	}
	if _, inConf := wgconf.FindPeer(c, p.PublicKey); inConf {
		return nil
	}
	return fmt.Errorf("%w: пир %s числится включённым в peers.json, но его блока нет в серверном "+
		"конфиге — состояние разошлось с сервером (похоже, предыдущая ротация заменила ключ на "+
		"устройстве, но не успела записать его в peers.json); ротация не выполнена, чтобы не "+
		"потерять метаданные пира; состояние согласуется автоматически при следующем обновлении "+
		"списка пиров, но пир при этом потеряет id, дату выпуска и персональные оверрайды",
		ErrStateConflict, id)
}

// ConfigFor собирает клиентский конфиг заново. Как и List, берёт s.mu: путь
// проходит через peerByID → loadState, а тот пишет peers.json (см.
// комментарий к полю Service.mu).
func (s *Service) ConfigFor(id string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.configFor(id)
}

// configFor собирает клиентский конфиг заново при каждом обращении: из
// приватного ключа, живого [Interface] сервера, оверрайдов пира и умолчаний
// интерфейса. Файла, который мог бы устареть, больше нет (раздел 5.2 спеки,
// задача 5) — раньше .conf собирался один раз при Add и лежал в
// Storage.ClientConfigs, и правка обфускации/DNS/маршрутов молча делала
// выданные файлы негодными без единого способа об этом узнать.
//
// БЕЗ захвата мьютекса: sync.Mutex не реентрантен, а QRFor обязан взять
// мьютекс на всю свою работу и при этом переиспользовать эту логику.
// Вызывать только под s.mu.
func (s *Service) configFor(id string) (string, string, error) {
	_, c, st, p, err := s.peerByID(id)
	if err != nil {
		return "", "", err
	}
	priv, err := s.privateKey(st, p)
	if err != nil {
		return "", "", err
	}
	obf, err := ExtractObfuscation(c.Interface)
	if err != nil {
		return "", "", err
	}
	serverPub, err := s.ServerPublicKey()
	if err != nil {
		return "", "", err
	}
	// PSK живёт в конфиге, пока пир включён, и в peers.json — пока выключен.
	psk := p.PresharedKey
	if sec, ok := wgconf.FindPeer(c, p.PublicKey); ok {
		psk = sec.Get("PresharedKey")
	}
	e := Effective(s.defaults(), p.Overrides, c.Interface.Get("MTU"))
	body, err := RenderClientConfig(ClientParams{
		PrivateKey: priv, Address: p.Address, ServerPublicKey: serverPub, PresharedKey: psk,
		Endpoint: e.Endpoint, AllowedIPs: e.AllowedIPs, Keepalive: e.Keepalive,
		DNS: e.DNS, MTU: e.MTU, Obfuscation: obf,
		Jc: e.Jc, Jmin: e.Jmin, Jmax: e.Jmax, Extra: e.Extra,
	})
	if err != nil {
		return "", "", err
	}
	return store.Slug(p.Name) + ".conf", body, nil
}

// privateKey отдаёт приватный ключ пира, при необходимости однократно
// перенося его из легаси-файла clients/<slug>.conf (панель версии 3.0,
// задача 4). st пока не используется телом функции — оставлен в сигнатуре
// как у вызывающего peerByID: связка «свежее состояние + запись пира» может
// понадобиться следующему шагу миграции (например, отметке «ключ перенесён»
// в метаданных), и здесь она уже под рукой.
func (s *Service) privateKey(st *store.State, p store.Peer) (string, error) {
	priv, err := s.keys.Get(p.ID)
	if err == nil {
		return priv, nil
	}
	if !errors.Is(err, ErrNoPrivateKey) {
		return "", err
	}
	if p.Slug == "" {
		// Пустой Slug — пир никогда не выпускался панелью: Add всегда
		// проставляет его через st.UniqueSlug. Легаси-файла для миграции
		// нет и не может появиться — это пир, заведённый вручную в
		// awg3.conf до установки панели. Класс ошибки прежний
		// (ErrNoPrivateKey), но текст — конкретная подсказка, а не общая
		// формулировка: до задачи 5 configFor называл причину именно так, и
		// такие пиры на боевом сервере этой панели реально есть (находка
		// ревью задачи 5 — подсказка потерялась при переносе проверки сюда).
		return "", fmt.Errorf("%w: пир %s заведён вручную до установки панели — "+
			"выпустите нового пира, если конфиг нужен", ErrNoPrivateKey, p.ID)
	}
	legacyDir := s.iface.Storage.ClientConfigs
	if legacyDir == "" {
		return "", ErrNoPrivateKey
	}
	legacy := filepath.Join(legacyDir, p.Slug+".conf")
	if merr := MigrateLegacyKey(s.keys, s.r, p.ID, legacy, p.PublicKey); merr != nil {
		log.Printf("миграция ключа пира id=%s: %v", p.ID, merr)
		return "", ErrNoPrivateKey
	}
	log.Printf("приватный ключ пира id=%s перенесён в хранилище ключей", p.ID)
	// MigrateLegacyKey вернула nil: ключ уже надёжно лежит в хранилище, даже
	// если удалить легаси-файл не удалось (рулинг ревью задачи 4,
	// «Осиротевший легаси-файл») — это состояние доверяем как успех и не
	// перепроверяем факт удаления файла, дальше keys.Get обязан сработать.
	return s.keys.Get(p.ID)
}

func (s *Service) QRFor(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Именно configFor, а не ConfigFor: вторая взяла бы тот же нереентрантный
	// мьютекс повторно и намертво заблокировала бы вызывающего.
	_, body, err := s.configFor(id)
	if err != nil {
		return nil, err
	}
	return QRPNG(body)
}
