package issuer_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// slashStorage строит Storage.* внутри каталога dir путями с ПРЯМЫМ слэшем.
// config.Interface.DefaultsPath вычисляет каталог состояния через path.Dir
// (см. комментарий у Interface.StateDir — путь на целевом Linux-хосте, а не
// на машине разработки), а filepath.Join на Windows даёт обратный слэш, в
// котором path.Dir не находит разделителя и тихо возвращает "." — тогда
// Service.Defaults()/SetDefaults() промахиваются мимо t.TempDir() и уходят
// писать defaults.json в текущий каталог процесса (проверено эмпирически при
// разработке задачи 5). os.* при этом одинаково успешно работает что с
// прямым, что с обратным слэшем на Windows, поэтому подмена безопасна и для
// обычных файловых операций (ReadFile/WriteFile/MkdirAll/ReadDir).
func slashStorage(dir string) config.Storage {
	base := filepath.ToSlash(dir)
	return config.Storage{
		State:         base + "/peers.json",
		Backups:       base + "/backups",
		Keys:          base + "/keys",
		ClientConfigs: base + "/clients",
	}
}

// serviceEnv — окружение задачи 5: временный каталог, Fake поверх образца
// awg3.conf и config.Interface со всеми путями внутри этого каталога.
// env.iface нужен тестам, которые заглядывают в Storage.* напрямую (задача
// 5), env.fake — задачам 7 и 13 (инъекция отказов устройства).
type serviceEnv struct {
	svc   *issuer.Service
	fake  *runtime.Fake
	iface config.Interface
}

func newServiceEnv(t *testing.T) *serviceEnv {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(liveConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = slashStorage(dir)
	iface := cfg.Interfaces[0]
	f := runtime.NewFake(liveConf)
	f.ConfPath = confPath
	return &serviceEnv{svc: issuer.New(iface, cfg.Listen, f), fake: f, iface: iface}
}

// bootstrapSeed — состояние, СЕМАНТИЧЕСКИ идентичное тому, что Reconcile
// произведёт для liveConf на первом чтении (те же поля store.Peer, тот же
// Version у store.State) — построено через реальные типы store.State/
// store.Peer и store.PeerID, а не руками собранной JSON-строкой, поэтому
// совпадение по полям гарантировано конструкцией, а не ручной сверкой.
// Используется в TestListDoesNotRewriteStateWhenUnchanged и
// TestListRewritesStateWhenPeerAppears (round 3 фикса ревью Task 10) как
// проверяемый пробник: сеется в компактном виде (json.Marshal, БЕЗ
// MarshalIndent и БЕЗ завершающего \n), тогда как store.Save всегда пишет
// json.MarshalIndent(..., "", "  ") плюс "\n" — форматирование на решение
// loadState "писать или нет" не влияет вообще (сравнение идёт по
// json.Marshal РАЗОБРАННОЙ структуры), поэтому компактность — это метка,
// которая либо переживёт вызов List() целиком (байт в байт), либо исчезнет
// (если Save был вызван) — независимо от mtime, гранулярности файловой
// системы и прав доступа.
func bootstrapSeed() store.State {
	return store.State{Version: 1, Peers: []store.Peer{
		{ID: store.PeerID(meKey), Name: "me", PublicKey: meKey, Address: "10.0.0.2/32", Enabled: true},
		{ID: store.PeerID(papaKey), Name: "papa", PublicKey: papaKey, Address: "10.0.0.3/32", Enabled: true},
	}}
}

func service(t *testing.T) (*issuer.Service, *runtime.Fake, *config.Config) {
	t.Helper()
	return serviceWithConf(t, liveConf)
}

// serviceWithConf — то же, что service, но с произвольным серверным конфигом:
// нужен тестам, которым важен состав конфига (пир без PresharedKey, узкая
// подсеть), а не два стандартных пира liveConf.
func serviceWithConf(t *testing.T, conf string) (*issuer.Service, *runtime.Fake, *config.Config) {
	t.Helper()
	return serviceWithRunner(t, conf, nil)
}

// serviceWithRunner — то же, но позволяет обернуть фейковое устройство своим
// Runner'ом. Нужен тестам, которым надо вклиниться в конкретный момент
// применения (например, в syncconf — когда файл конфига уже переписан, а
// устройство ещё нет).
func serviceWithRunner(t *testing.T, conf string, wrap func(*runtime.Fake) runtime.Runner) (*issuer.Service, *runtime.Fake, *config.Config) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = slashStorage(dir)
	f := runtime.NewFake(conf)
	f.ConfPath = confPath
	var r runtime.Runner = f
	if wrap != nil {
		r = wrap(f)
	}
	return issuer.New(cfg.Interfaces[0], cfg.Listen, r), f, cfg
}

func TestListAdoptsExistingPeers(t *testing.T) {
	s, _, _ := service(t)
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("пиров %d, ожидалось 2", len(peers))
	}
	// Имена берутся из комментария # awg3panel: <имя> в блоке, если он есть.
	names := map[string]bool{}
	for _, p := range peers {
		names[p.Name] = true
	}
	if !names["me"] || !names["papa"] {
		t.Errorf("имена не подхвачены из комментариев: %+v", peers)
	}
}

func TestListMergesLiveStatus(t *testing.T) {
	s, _, _ := service(t)
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.LastHandshake == 0 {
			t.Errorf("пир %s: handshake не подтянулся из dump", p.Name)
		}
		if p.RxBytes == 0 {
			t.Errorf("пир %s: счётчики не подтянулись", p.Name)
		}
		if p.NeverConnected {
			t.Errorf("пир %s помечен как ни разу не подключавшийся, хотя handshake есть", p.Name)
		}
	}
}

func TestListMarksNeverConnected(t *testing.T) {
	s, f, _ := service(t)
	for k := range f.Handshakes {
		f.Handshakes[k] = 0
	}
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	// Цикл — единственное утверждение теста, поэтому пустой список означал бы
	// ноль проверок при зелёном результате (находка Important 4 финального
	// ревью). Ошибка List раньше и вовсе глоталась через `peers, _ :=`.
	if len(peers) != 2 {
		t.Fatalf("пиров %d, ожидалось 2 — иначе цикл ниже ничего не проверяет", len(peers))
	}
	for _, p := range peers {
		if !p.NeverConnected {
			t.Errorf("пир %s должен быть помечен как ни разу не подключавшийся", p.Name)
		}
	}
}

func TestListPersistsState(t *testing.T) {
	s, _, cfg := service(t)
	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatalf("peers.json не создан при первом чтении: %v", err)
	}
}

func TestListNeverExposesFullPublicKey(t *testing.T) {
	s, _, _ := service(t)
	peers, err := s.List()
	// Это утверждение о БЕЗОПАСНОСТИ, и оно жило внутри цикла по `peers, _ :=`:
	// при ошибке List тест был зелёным, не проверив ровным счётом ничего
	// (находка Important 4 финального ревью).
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("пиров %d, ожидалось 2 — иначе проверка утечки ключа ничего не проверяет", len(peers))
	}
	for _, p := range peers {
		if len(p.PublicKeyShort) > 12 {
			t.Errorf("в представление утёк полный публичный ключ: %q", p.PublicKeyShort)
		}
		// Префикс обязан ОСТАТЬСЯ префиксом настоящего ключа: пустая строка
		// тоже короче 12 символов, и одной проверки длины мало.
		if p.PublicKeyShort == "" {
			t.Error("PublicKeyShort пуст — пира станет невозможно опознать")
		}
	}
}

func TestServerPublicKeyDerivedFromPrivate(t *testing.T) {
	s, _, _ := service(t)
	pub, err := s.ServerPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	if pub == "" {
		t.Fatal("публичный ключ сервера пуст")
	}
	// Фейк возвращает pub-<первые 8 символов приватного>.
	if pub != "pub-c2VydmVy" {
		t.Errorf("публичный ключ = %q — он должен вычисляться из приватного через awg pubkey", pub)
	}
}

// TestListenAddrReturnsConfigListen покрывает Service.ListenAddr — геттер,
// добавленный в Task 14 для CLI-мутаций: им проверяется, не занят ли адрес
// cfg.Listen кем-то другим (предположительно работающим `awg3panel serve`),
// прежде чем мутировать состояние в обход внутрипроцессного Service.mu.
func TestListenAddrReturnsConfigListen(t *testing.T) {
	s, _, cfg := service(t)
	if got := s.ListenAddr(); got != cfg.Listen {
		t.Errorf("ListenAddr() = %q, ожидался cfg.Listen = %q", got, cfg.Listen)
	}
}

func TestListSortedByAddress(t *testing.T) {
	s, _, _ := service(t)
	peers, _ := s.List()
	if peers[0].Address != "10.0.0.2/32" || peers[1].Address != "10.0.0.3/32" {
		t.Errorf("порядок не по адресу: %v, %v", peers[0].Address, peers[1].Address)
	}
}

// TestListPreservesRenameOverStaleComment покрывает случай 3 приоритета
// имён в loadState: пользователь переименовал пира через панель, а в
// awg3.conf остался старый комментарий "# awg3panel: <другое имя>". Условие
// strings.HasPrefix(p.Name, "peer-") в loadState существует ровно ради
// этого — оно не даёт устаревшему комментарию затереть имя, заданное
// пользователем.
//
// Нужен ДВОЙНОЙ вызов List(): одного недостаточно, потому что сценарий
// состоит из двух разных состояний peers.json, и оба должны быть пройдены
// через реальный код loadState, а не просто засеяны с потолка:
//  1. первый вызов — легитимное бутстрап-подхватывание: пир ещё не в
//     peers.json, имя генерируется как "peer-<id>", и ИМЕННО потому что оно
//     начинается с "peer-", комментарий конфига законно его перезаписывает
//     (это ПОЛОВИНА логики приоритета — то, что делает комментарий вообще
//     полезным);
//  2. переименование через панель — имитируется прямой правкой peers.json
//     (ровно так это сделал бы будущий Rename()-эндпоинт: правит только
//     метаданные, awg3.conf не трогает — см. Enable/Disable/Remove в плане
//     Task 11+, которые действуют по этому же принципу);
//  3. второй вызов List() — тот самый момент, где регрессия (например,
//     наивная замена HasPrefix-проверки на сравнение "имя изменилось с
//     последнего раза") откатила бы имя обратно к устаревшему комментарию.
//     Эффект виден только здесь, а не на шаге 1.
func TestListPreservesRenameOverStaleComment(t *testing.T) {
	s, _, cfg := service(t)

	// Шаг 1: бутстрап — имя "me" подхватывается из комментария, потому что
	// текущее имя ("peer-<id>") ещё сгенерированное.
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var meID string
	for _, p := range peers {
		if p.Name == "me" {
			meID = p.ID
		}
	}
	if meID == "" {
		t.Fatalf("пир 'me' не подхвачен из комментария на первом чтении: %+v", peers)
	}

	// Шаг 2: имитация переименования через панель напрямую в peers.json.
	// Комментарий в awg3.conf ("# awg3panel: me") остаётся прежним —
	// расхождение с реальным именем создано намеренно.
	st, err := store.Load(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := st.Get(meID)
	if !ok {
		t.Fatalf("пир %s не найден в peers.json после первого чтения", meID)
	}
	p.Name = "новое имя"
	if err := st.Save(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatal(err)
	}

	// Шаг 3: второе чтение не должно откатить имя к устаревшему комментарию.
	peers2, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var gotName string
	var found bool
	for _, pv := range peers2 {
		if pv.ID == meID {
			gotName = pv.Name
			found = true
		}
	}
	if !found {
		t.Fatalf("пир %s пропал со второго чтения", meID)
	}
	if gotName != "новое имя" {
		t.Errorf("имя = %q, ожидалось «новое имя» — переименование через панель откатилось "+
			"к устаревшему комментарию конфига", gotName)
	}
}

// --- Дополнительно к брифу: закрытие дыр в покрытии, найденных при проверке
// нетривиальности каждого из трёх пунктов (см. отчёт Task 10). ---

// TestListDisabledPeerNeverConnectedStaysFalse проверяет именно то различение,
// ради которого существует NeverConnected: отключённый пир с нулевым
// handshake — не «никогда не подключался», он просто выключен. Ни один тест
// выше этого не ловит: во всех фикстурах liveConf оба пира из awg3.conf и
// поэтому Enabled == true у всех, что делает условие "p.Enabled &&" в
// service.go недостижимым для проверки. Здесь отключённый пир существует
// только в peers.json (в awg3.conf его нет — таков контракт disable, см.
// store.Reconcile), поэтому это единственный способ дать сабораж
// "убрать проверку p.Enabled" реальный шанс быть пойманным.
func TestListDisabledPeerNeverConnectedStaysFalse(t *testing.T) {
	s, _, cfg := service(t)
	st := &store.State{Version: 1, Peers: []store.Peer{{
		ID: "disabled0001", Name: "старый", PublicKey: "ZGlzYWJsZWQtcGVlci1ub3QtaW4tY29uZmY9",
		Address: "10.0.0.9/32", Enabled: false, CreatedAt: "2026-01-01T00:00:00Z",
	}}}
	if err := st.Save(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatal(err)
	}
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range peers {
		if p.ID != "disabled0001" {
			continue
		}
		found = true
		if p.Enabled {
			t.Fatalf("пир должен остаться отключённым: %+v", p)
		}
		if p.NeverConnected {
			t.Errorf("отключённый пир не должен помечаться как ни разу не подключавшийся: %+v", p)
		}
	}
	if !found {
		t.Fatal("отключённый пир из peers.json не попал в список")
	}
}

// TestListDoesNotRewriteStateWhenUnchanged проверяет, что List() не пишет
// peers.json на каждый вызов: страница опрашивает List() раз в 10 секунд,
// и лишняя запись при неизменном состоянии — не порча (Save атомарен), но
// ненужный износ.
//
// Round 3 фикса ревью Task 10: раньше это проверялось через mtime
// (os.Stat(...).ModTime()) — оказалось недействительно на Linux: замер
// показал, что на файловой системе контейнера golang:1.26 две подряд
// идущих записи в один и тот же путь получают идентичный до наносекунды
// ModTime, детерминированно (5/5), то есть тест ничего не проверял в этом
// окружении. Теперь проверка идёт по содержимому файла (см. bootstrapSeed
// — компактный пробник, который переживает вызов байт в байт, если Save
// не вызывался, и не зависит ни от времени, ни от ФС, ни от прав).
func TestListDoesNotRewriteStateWhenUnchanged(t *testing.T) {
	s, _, cfg := service(t)

	seedBytes, err := json.Marshal(bootstrapSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Interfaces[0].Storage.State, seedBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, seedBytes) {
		t.Errorf("peers.json перезаписан без изменения состояния:\nбыло:  %s\nстало: %s", seedBytes, got)
	}
}

// TestListRewritesStateWhenPeerAppears — контроль от переусердствовавшего
// фикса: если состояние ДЕЙСТВИТЕЛЬНО изменилось (появился новый пир),
// запись обязана произойти. Без этого теста "писать только при изменении"
// можно было бы выродить в "не писать никогда".
//
// Round 3: тот же переход с mtime на содержимое, что и в
// TestListDoesNotRewriteStateWhenUnchanged, и по той же причине —
// одинаковый ModTime двух подряд идущих записей на некоторых Linux ФС
// делал прежнюю версию этого теста провальной ложноотрицательно (падал
// 5/5 под root в golang:1.26, хотя запись фактически происходила).
// Компактный пробник обязан ИСЧЕЗНУТЬ: файл должен обзавестись отступами
// store.Save (json.MarshalIndent) и публичным ключом нового пира.
func TestListRewritesStateWhenPeerAppears(t *testing.T) {
	s, f, cfg := service(t)

	seedBytes, err := json.Marshal(bootstrapSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Interfaces[0].Storage.State, seedBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	newConf := liveConf + `
[Peer]
# awg3panel: third
PublicKey = ` + addKey + `
AllowedIPs = 10.0.0.4/32
`
	if err := os.WriteFile(cfg.Interfaces[0].Config, []byte(newConf), 0o600); err != nil {
		t.Fatal(err)
	}
	f.Conf = newConf

	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, seedBytes) {
		t.Fatal("peers.json не перезаписан после появления нового пира — состояние изменилось, а запись не произошла")
	}
	if !bytes.Contains(got, []byte(addKey)) {
		t.Errorf("после записи в peers.json нет публичного ключа нового пира: %s", got)
	}
	// store.Save всегда пишет json.MarshalIndent(s, "", "  ") плюс "\n" —
	// компактный пробник этого формата не имеет, так что оба признака
	// однозначно отличают запись Save от нетронутого пробника. Номер версии
	// в префиксе берётся из store.StateVersion, а не литералом: тест
	// проверяет ФОРМАТ записи (отступы MarshalIndent), а не то, какая именно
	// версия формата сейчас актуальна, — иначе он ломался бы при каждом
	// следующем подъёме StateVersion, как уже случилось при переходе 1 → 2
	// (задача 2, peers.json v2).
	wantPrefix := fmt.Sprintf("{\n  \"version\": %d,\n", store.StateVersion)
	if !bytes.HasPrefix(got, []byte(wantPrefix)) {
		t.Errorf("запись не похожа на формат store.Save (ожидались отступы MarshalIndent): %s", got)
	}
	if !bytes.HasSuffix(got, []byte("\n")) {
		t.Error("store.Save обязан завершать файл переводом строки, а запись — нет")
	}
}

// TestListSurvivesStateWriteFailure — read-путь не должен падать из-за
// невозможности записать peers.json. Данные уже вычислены (конфиг
// разобран, live-статус подтянут) — неудачная запись обязана лишь
// залогироваться, а не уронить весь ответ, иначе опрос раз в 10 секунд
// начнёт получать ошибку там, где мог бы получить данные.
//
// Меняем состав пиров, чтобы второй вызов реально нашёл расхождение и
// попытался сохранить его — иначе (с фиксом из
// TestListDoesNotRewriteStateWhenUnchanged) запись не произошла бы вовсе
// и тест ничего бы не проверил.
//
// Запись блокируется и на файле, и на каталоге: на Windows перезапись
// существующего файла блокируется его собственным атрибутом «только
// чтение» (проверено эмпирически — os.Rename поверх read-only файла
// возвращает "Access is denied"); на Unix то же самое обеспечивает
// отсутствие права записи в каталог (право на это даёт каталог, а не сам
// файл).
//
// ВАЖНО (fix round 2, ре-ревью): DAC-права — не uid-независимый механизм.
// Продакшн-сервис этого проекта работает от root (systemd User=root,
// см. спеку раздел про песочницу) — а root игнорирует биты доступа и
// свободно переписывает read-only файл/каталог. Проверено эмпирически в
// контейнере golang:1.26 от root: os.Chmod(file,0o400)+os.Chmod(dir,0o500)
// НЕ мешает os.Rename поверх read-only файла — запись проходит молча. Та
// же проверка для chattr +i (Linux immutable-атрибут — единственный
// файловый механизм, который в теории должен связывать и root) тоже не
// подошла: в контейнере по умолчанию нет CAP_LINUX_IMMUTABLE, chattr
// падает с "Operation not permitted" даже под root — то есть и этот путь
// недоступен без привилегированного контейнера. Структурный трюк
// (Storage.State через несуществующий каталог, "ENOTDIR") uid-независим,
// но ломает не только Save, а и Load той же ошибкой на обеих платформах
// (проверено тем же контейнером) — то есть не изолирует "запись не
// удалась, но чтение уже отработало", а тестирует другой, не относящийся
// к Finding 2 сценарий (авария ещё до Reconcile). Ни один из известных
// лёгких и переносимых механизмов не бьёт root без спецпривилегий
// контейнера (CAP_SYS_ADMIN для mount, CAP_LINUX_IMMUTABLE для chattr).
//
// Поэтому тест устроен так: пытается заблокировать запись правами (лучшее
// доступное на Windows и на не-root Unix), а после вызова ПРОВЕРЯЕТ, что
// блокировка действительно сработала — по факту (содержимое peers.json не
// изменилось), а не по предположению. Если содержимое ВСЁ-ТАКИ изменилось
// (запись прошла несмотря на chmod — типичный случай root), тест не
// притворяется, что что-то проверил: он SKIP, а не PASS, с честной
// причиной. Когда блокировка сработала — утверждения полноценные: и
// данные, и факт логирования (см. log.SetOutput ниже).
func TestListSurvivesStateWriteFailure(t *testing.T) {
	s, f, cfg := service(t)
	if _, err := s.List(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}

	newConf := liveConf + `
[Peer]
# awg3panel: third
PublicKey = ` + addKey + `
AllowedIPs = 10.0.0.4/32
`
	if err := os.WriteFile(cfg.Interfaces[0].Config, []byte(newConf), 0o600); err != nil {
		t.Fatal(err)
	}
	f.Conf = newConf

	if err := os.Chmod(cfg.Interfaces[0].Storage.State, 0o400); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(cfg.Interfaces[0].Storage.State)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Chmod(dir, 0o700)
		os.Chmod(cfg.Interfaces[0].Storage.State, 0o600)
	})

	// Перехватываем глобальный вывод log — в пакете нет t.Parallel(), так
	// что подмена безопасна; восстанавливаем через t.Cleanup в любом
	// случае, включая Skip/Fatal.
	var logBuf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&logBuf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	peers, listErr := s.List()

	after, statErr := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if !bytes.Equal(before, after) {
		t.Skip("окружение не блокирует запись через права доступа (содержимое peers.json " +
			"изменилось несмотря на chmod) — похоже, тест запущен с привилегиями, которые " +
			"игнорируют DAC (root/Administrator; продакшн-сервис тоже работает от root). " +
			"Пропускаем, а не притворяемся, что путь отказа записи проверен.")
	}

	if listErr != nil {
		t.Fatalf("List() не должен падать из-за неудачной записи состояния: %v", listErr)
	}
	if len(peers) != 3 {
		t.Fatalf("данные должны быть вычислены несмотря на неудачную запись: пиров %d, ожидалось 3", len(peers))
	}
	if logBuf.Len() == 0 {
		t.Error("неудачная запись состояния должна быть залогирована, лог пуст")
	}
}

// TestListSortsNumericallyNotLexically — прямая проверка того, что
// TestListSortedByAddress выше НЕ пришпиливает: адреса 10.0.0.2/32 и
// 10.0.0.3/32 дают одинаковый порядок и при строковой, и при численной
// сортировке (совпадают по длине и позиции различающейся цифры). Добавляем
// третьего пира с адресом 10.0.0.10/32 — при строковой сортировке "10" встаёт
// перед "2", при численной 10 идёт последним. Это единственная фикстура в
// пакете, различающая два вида сортировки.
func TestListSortsNumericallyNotLexically(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	conf := liveConf + `
[Peer]
# awg3panel: ten
PublicKey = dGVuLXB1YmxpYy1rZXktZmFrZS0wMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.0.0.10/32
`
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage.State = filepath.Join(dir, "peers.json")
	cfg.Interfaces[0].Storage.Backups = filepath.Join(dir, "backups")
	cfg.Interfaces[0].Storage.ClientConfigs = filepath.Join(dir, "clients")
	f := runtime.NewFake(conf)
	f.ConfPath = confPath
	s := issuer.New(cfg.Interfaces[0], cfg.Listen, f)

	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 3 {
		t.Fatalf("пиров %d, ожидалось 3", len(peers))
	}
	got := []string{peers[0].Address, peers[1].Address, peers[2].Address}
	want := []string{"10.0.0.2/32", "10.0.0.3/32", "10.0.0.10/32"}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("порядок = %v, ожидалось %v (численная, а не строковая сортировка)", got, want)
			break
		}
	}
}

// --- Задача 5: клиентский .conf собирается на лету, а не читается с диска. ---

// TestConfigForRendersFromCurrentState — конфиг обязан отражать умолчания
// интерфейса НА МОМЕНТ ЗАПРОСА, а не на момент выпуска: правка defaults.json
// после Add обязана быть видна в следующем же ConfigFor. Раньше .conf
// собирался один раз при Add и застывал в clients/<slug>.conf — правка
// параметров молча делала выданные файлы негодными (см. task-5-brief.md).
func TestConfigForRendersFromCurrentState(t *testing.T) {
	env := newServiceEnv(t)
	issued, err := env.svc.Add("телефон")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Меняем умолчание DNS уже ПОСЛЕ выпуска.
	d := env.svc.Defaults()
	d.DNS = "10.0.0.1"
	if err := env.svc.SetDefaults(d); err != nil {
		t.Fatal(err)
	}

	_, body, err := env.svc.ConfigFor(issued.ID)
	if err != nil {
		t.Fatalf("ConfigFor: %v", err)
	}
	if !strings.Contains(body, "DNS = 10.0.0.1") {
		t.Fatalf("конфиг собран не по текущим умолчаниям:\n%s", body)
	}
	if !strings.Contains(body, "PrivateKey") {
		t.Fatal("в собранном конфиге обязан быть приватный ключ пира")
	}
}

// TestAddStoresPrivateKeyNotClientFile — источник правды для приватного
// ключа теперь keys/<id>.key, а clients/<slug>.conf больше не создаётся.
func TestAddStoresPrivateKeyNotClientFile(t *testing.T) {
	env := newServiceEnv(t)
	issued, err := env.svc.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(env.iface.Storage.Keys, issued.ID+".key")); err != nil {
		t.Fatalf("приватный ключ не сохранён: %v", err)
	}
	entries, _ := os.ReadDir(env.iface.Storage.ClientConfigs)
	if len(entries) != 0 {
		t.Fatal("выданные .conf больше не сохраняются на диск")
	}
}

// TestConfigForMigratesLegacyFileOnce моделирует состояние «панель версии
// 3.0»: приватный ключ пира лежит только в выданном ранее clients/<slug>.conf
// (хранилища ключей ещё не существовало), в keys/ его нет. Первый же
// ConfigFor обязан перенести ключ в хранилище и убрать легаси-файл.
func TestConfigForMigratesLegacyFileOnce(t *testing.T) {
	env := newServiceEnv(t)
	issued, err := env.svc.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	// Смоделировать состояние «панель версии 3.0»: ключ лежит только в .conf.
	priv, _ := issuer.NewKeyStore(env.iface.Storage.Keys).Get(issued.ID)
	os.MkdirAll(env.iface.Storage.ClientConfigs, 0o700)
	legacy := filepath.Join(env.iface.Storage.ClientConfigs, "telefon.conf")
	os.WriteFile(legacy, []byte("[Interface]\nPrivateKey = "+priv+"\n"), 0o600)
	os.Remove(filepath.Join(env.iface.Storage.Keys, issued.ID+".key"))

	if _, _, err := env.svc.ConfigFor(issued.ID); err != nil {
		t.Fatalf("ConfigFor после миграции: %v", err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("легаси-файл обязан исчезнуть после успешной миграции")
	}
	if _, err := issuer.NewKeyStore(env.iface.Storage.Keys).Get(issued.ID); err != nil {
		t.Fatalf("ключ не появился в хранилище: %v", err)
	}
}

// TestConfigForAppliesOverrideExtraOverDefaultsExtra закрывает долг задачи 3
// (см. task-5-brief.md, «Долг задачи 3»): связка Effective → ClientParams.
// Extra → RenderClientConfig протестирована по частям (задача 3), но нигде
// не собрана целиком. configFor — первое место, где цепочка реальна: сюда
// задаём extra-поле в умолчаниях интерфейса И персональный оверрайд пира с
// ДВУМЯ полями (нужны оба, иначе алфавитный порядок нечем отличить от
// случайного) и проверяем итоговый текст — оверрайд обязан ЗАМЕНИТЬ extra
// умолчаний целиком (params.go: Effective копирует карту оверрайда, а не
// сливает по ключам), а порядок печати — быть детерминированным
// (RenderClientConfig сортирует ключи через sort.Strings).
//
// Проверки идут через wgconf.Parse + Section.Get/Items, а не strings.Contains/
// Index по сырому тексту (находка самопроверки задач 8-9, task-8-9-report.md).
// PrivateKey, PresharedKey и HeaderProtectionKey в этом конфиге — случайные
// base64-строки (runtime.Fake.GenKey/GenPSK читают crypto/rand), а короткая
// алфавитно-цифровая подстрока вроде "Z9" способна случайно встретиться
// ВНУТРИ одной из них. На практике это раз в несколько сотен прогонов ложно
// ВАЛИТ тест на корректной реализации (поля Z9 в конфиге нет, но
// strings.Contains нашёл "Z9" внутри чужого PresharedKey) и симметрично
// способно ложно ПРОПУСТИТЬ регрессию, если бы Z9 в конфиге остался по-
// настоящему — совпадение по случайной подстроке ничем не отличалось бы от
// совпадения по значащей. Сравнение значения КОНКРЕТНОГО поля секции после
// разбора устраняет класс целиком: секрет соседнего поля физически не может
// подменить собой чтение другого имени ключа.
func TestConfigForAppliesOverrideExtraOverDefaultsExtra(t *testing.T) {
	env := newServiceEnv(t)
	issued, err := env.svc.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}

	d := env.svc.Defaults()
	d.Extra = map[string]string{"Z9": "default-only"}
	if err := env.svc.SetDefaults(d); err != nil {
		t.Fatal(err)
	}

	st, err := store.Load(env.iface.Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := st.Get(issued.ID)
	if !ok {
		t.Fatalf("пир %s не найден в peers.json", issued.ID)
	}
	p.Overrides = &store.Overrides{Extra: map[string]string{"I2": "second", "I1": "first"}}
	if err := st.Save(env.iface.Storage.State); err != nil {
		t.Fatal(err)
	}

	_, body, err := env.svc.ConfigFor(issued.ID)
	if err != nil {
		t.Fatalf("ConfigFor: %v", err)
	}
	c, err := wgconf.Parse(body)
	if err != nil {
		t.Fatalf("выданный клиентский конфиг не разбирается: %v", err)
	}
	if v := c.Interface.Get("Z9"); v != "" {
		t.Errorf("оверрайд обязан ЗАМЕНИТЬ extra умолчаний, а не слить с ним: поле Z9 = %q найдено в конфиге:\n%s", v, body)
	}
	if v := c.Interface.Get("I1"); v != "first" {
		t.Fatalf("I1 = %q, ожидалось \"first\" — в конфиге нет полей оверрайда пира:\n%s", v, body)
	}
	if v := c.Interface.Get("I2"); v != "second" {
		t.Fatalf("I2 = %q, ожидалось \"second\" — в конфиге нет полей оверрайда пира:\n%s", v, body)
	}
	// Порядок печати — по позиции в c.Interface.Items (порядок строк ПОСЛЕ
	// разбора), а не по смещению подстроки в сыром тексте: тот же принцип
	// «сравнивать структуру, а не текст», что и выше.
	i1, i2 := -1, -1
	for i, kv := range c.Interface.Items {
		switch kv.Key {
		case "I1":
			i1 = i
		case "I2":
			i2 = i
		}
	}
	if i1 == -1 || i2 == -1 {
		t.Fatalf("I1/I2 не найдены среди полей секции [Interface]: %+v", c.Interface.Items)
	}
	if i1 > i2 {
		t.Errorf("порядок extra-полей не детерминирован (ожидался алфавитный: I1 раньше I2): %+v", c.Interface.Items)
	}
}

// Было: TestDefaultsReturnsIndependentExtraCopy. Убран по находке ревью
// задачи 5 — тест проходил независимо от того, существует ли Service.
// cloneExtra вообще: после первого SetDefaults defaults.json уже есть на
// диске, и каждый следующий Defaults() идёт через ветку json.Unmarshal в
// store.LoadDefaults, которая и так аллоцирует новую карту при разборе.
// Единственная ветка с реальным алиасингом — «файла ещё нет, копируем
// сид» — в Service.Defaults() недостижима: сид строится из s.iface.Client.*
// (config.Client), у которого поля Extra нет вовсе, так что сид туда
// никогда не попадает непустым. Настоящий дефект жил в store.LoadDefaults
// и починен там же (internal/store/defaults.go, cloneExtra) — тест на него
// теперь в internal/store/defaults_test.go:
// TestLoadDefaultsSeedDoesNotShareExtraMap, где ветка «файла нет» реально
// достижима и различима.

// TestConfigForManuallyAddedPeerExplainsWhy — находка ревью задачи 5:
// пир с пустым Slug никогда не выпускался панелью (Add всегда его
// проставляет через st.UniqueSlug) — это пир, заведённый вручную в
// awg3.conf до установки панели. До задачи 5 configFor называл причину
// прямо: «он заведён вручную до установки панели — выпустите нового пира,
// если конфиг нужен». При переносе проверки в privateKey текст подменился
// общей формулировкой ErrNoPrivateKey — конкретная подсказка потерялась,
// хотя у владельца этой панели такие пиры на боевом сервере реально есть
// (liveConf: me и papa заведены точно так же — без Slug, без ключа в
// хранилище).
func TestConfigForManuallyAddedPeerExplainsWhy(t *testing.T) {
	env := newServiceEnv(t)
	peers, err := env.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) == 0 {
		t.Fatal("фикстура сломана: в liveConf нет ни одного пира")
	}
	id := peers[0].ID

	_, _, err = env.svc.ConfigFor(id)
	if err == nil {
		t.Fatal("ожидалась ошибка: у пира из liveConf нет ни сохранённого ключа, ни Slug")
	}
	if !errors.Is(err, issuer.ErrNoPrivateKey) {
		t.Errorf("ошибка не классифицирована как ErrNoPrivateKey: %v", err)
	}
	if !strings.Contains(err.Error(), "заведён вручную") {
		t.Errorf("текст ошибки не объясняет оператору причину (пир заведён руками "+
			"до установки панели): %v", err)
	}
}

// --- Задача 8: правка пира — имя, адрес, оверрайды. ---

// issuedPublicKey читает peers.json и возвращает ТЕКУЩИЙ публичный ключ пира
// id. В отличие от issued.ID (переживает любую правку, включая ротацию),
// публичный ключ меняет Rotate (задача 9) — тестам, которые ищут блок пира в
// серверном конфиге ПОСЛЕ мутации, нужен свежий ключ из состояния, а не тот,
// что вернул Add.
func issuedPublicKey(t *testing.T, env *serviceEnv, id string) string {
	t.Helper()
	st, err := store.Load(env.iface.Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := st.Get(id)
	if !ok {
		t.Fatalf("пир %s не найден в peers.json", id)
	}
	return p.PublicKey
}

func TestUpdateRenameKeepsServerConfigPeersIntact(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	name := "папин телефон"
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{Name: &name}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	raw := readConf(t, env.iface.Config)
	if !strings.Contains(raw, "# awg3panel: папин телефон") {
		t.Fatal("имя в комментарии блока не обновилось")
	}
	c, _ := wgconf.Parse(raw)
	sec, _ := wgconf.FindPeer(c, issuedPublicKey(t, env, issued.ID))
	if sec.Get("AllowedIPs") != issued.Address {
		t.Fatal("переименование не должно трогать адрес")
	}
	// Имя файла при скачивании считается от ТЕКУЩЕГО имени.
	name2, _, err := env.svc.ConfigFor(issued.ID)
	if err != nil || !strings.HasPrefix(name2, store.Slug("папин телефон")) {
		t.Fatalf("имя файла = %q, %v", name2, err)
	}
}

func TestUpdateAddressChangesAllowedIPs(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	addr := "10.0.0.77/32"
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{Address: &addr}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	c, _ := wgconf.Parse(readConf(t, env.iface.Config))
	sec, _ := wgconf.FindPeer(c, issuedPublicKey(t, env, issued.ID))
	if sec.Get("AllowedIPs") != "10.0.0.77/32" {
		t.Fatalf("AllowedIPs = %q", sec.Get("AllowedIPs"))
	}
	_, body, _ := env.svc.ConfigFor(issued.ID)
	if !strings.Contains(body, "Address = 10.0.0.77/32") {
		t.Fatal("новый адрес обязан появиться в клиентском конфиге")
	}
}

func TestUpdateAddressRejectsOccupied(t *testing.T) {
	env := newServiceEnv(t)
	a, _ := env.svc.Add("первый")
	b, _ := env.svc.Add("второй")
	before := readConf(t, env.iface.Config)
	occupied := b.Address
	err := env.svc.Update(a.ID, issuer.PeerPatch{Address: &occupied})
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Fatalf("занятый адрес обязан быть ошибкой ввода, получено: %v", err)
	}
	if readConf(t, env.iface.Config) != before {
		t.Fatal("отказ обязан случиться ДО всякой записи в конфиг")
	}
}

// TestUpdateAddressRejectsServerOwnAddress — непокрытая до этого ветка
// checkAddressFree: адрес пира не может совпасть с адресом самого сервера
// (Address = 10.0.0.1/24 в serverConf, т.е. HostIP = 10.0.0.1). В отличие
// от TestUpdateAddressRejectsOccupied (адрес занят ДРУГИМ ПИРОМ), здесь
// адрес не занят никаким пиром вовсе — ни в peers.json, ни в живом
// конфиге, — и единственный способ поймать конфликт — явное сравнение с
// HostIP(serverAddr).
func TestUpdateAddressRejectsServerOwnAddress(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	before := readConf(t, env.iface.Config)
	serverOwn := "10.0.0.1" // HostIP от Address сервера (10.0.0.1/24, serverConf)
	err := env.svc.Update(issued.ID, issuer.PeerPatch{Address: &serverOwn})
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Fatalf("адрес самого сервера обязан быть ошибкой ввода, получено: %v", err)
	}
	if readConf(t, env.iface.Config) != before {
		t.Fatal("отказ обязан случиться ДО всякой записи в конфиг")
	}
}

func TestUpdateOverridesDoNotTouchServerConfig(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	before := readConf(t, env.iface.Config)
	dns := "10.0.0.1"
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{
		Overrides: &store.Overrides{DNS: &dns}}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if readConf(t, env.iface.Config) != before {
		t.Fatal("правка клиентских параметров не имеет отношения к серверному конфигу")
	}
	_, body, _ := env.svc.ConfigFor(issued.ID)
	if !strings.Contains(body, "DNS = 10.0.0.1") {
		t.Fatal("оверрайд не доехал до конфига")
	}
}

// TestListExposesOverrides — задача 11: форма правки пира в UI показывает
// плейсхолдером наследуемое значение и текущий персональный оверрайд поверх
// него (раздел 9 спеки). Единственный источник данных для этой формы —
// List(), и без Overrides в PeerView взять текущие значения неоткуда:
// PATCH ничего не возвращает, кроме {"status":"ok"}. Явно пустой DNS обязан
// доехать как заданный указателем на "", а не потеряться и не превратиться
// в отсутствующее поле — иначе на стороне UI неотличимо от «наследовать».
func TestListExposesOverrides(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	dns := ""
	mtu := "1280"
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{
		Overrides: &store.Overrides{DNS: &dns, MTU: &mtu},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	peers, err := env.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	var got *issuer.PeerView
	for i := range peers {
		if peers[i].ID == issued.ID {
			got = &peers[i]
		}
	}
	if got == nil {
		t.Fatal("выпущенный пир не найден в списке")
	}
	if got.Overrides == nil {
		t.Fatal("Overrides не доехали до PeerView")
	}
	if got.Overrides.DNS == nil || *got.Overrides.DNS != "" {
		t.Fatal("явно пустой DNS обязан остаться заданным пустым, а не потеряться")
	}
	if got.Overrides.MTU == nil || *got.Overrides.MTU != "1280" {
		t.Fatal("MTU-оверрайд не доехал до PeerView")
	}
}

// TestListPeerWithoutOverridesHasNilOverrides — обратная сторона предыдущего
// теста: пир без единого оверрайда обязан отдавать Overrides == nil (и,
// следовательно, поле "overrides" отсутствует в JSON целиком благодаря
// omitempty), а не пустой объект. UI различает эти два случая: nil значит
// «все поля наследуются», непустой объект — «часть полей персональна».
func TestListPeerWithoutOverridesHasNilOverrides(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	peers, err := env.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.ID == issued.ID && p.Overrides != nil {
			t.Fatalf("свежевыпущенный пир без оверрайдов обязан отдавать Overrides=nil, получено %+v", p.Overrides)
		}
	}
}

// TestUpdateWithEmptyOverridesObjectStaysNil — находка ревью задачи 11:
// форма правки пира в index.html пересобирает и шлёт "overrides" целиком
// при КАЖДОМ сохранении, включая случай «менял только имя» — для пира без
// персональных оверрайдов это указатель на пустую store.Overrides{}, а не
// отсутствующее поле (JSON "overrides":{}, не отсутствие ключа). Без
// нормализации Update дословно присвоил бы pp.Overrides этот непустой, но
// бессодержательный указатель, и List() после такого сохранения начал бы
// врать про наличие персональных настроек — то самое различие (nil значит
// «оверрайдов нет вовсе»), ради которого PeerView.Overrides введён.
func TestUpdateWithEmptyOverridesObjectStaysNil(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	newName := "новый-телефон"
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{
		Name: &newName, Overrides: &store.Overrides{},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	peers, err := env.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	var got *issuer.PeerView
	for i := range peers {
		if peers[i].ID == issued.ID {
			got = &peers[i]
		}
	}
	if got == nil {
		t.Fatal("переименованный пир не найден в списке")
	}
	if got.Name != newName {
		t.Fatalf("имя не доехало: %q", got.Name)
	}
	if got.Overrides != nil {
		t.Fatalf("пустой объект overrides в патче обязан нормализоваться в nil, получено %+v", got.Overrides)
	}
}

// TestUpdateWithOnlyExtraOverridesIsNotNormalizedAway — граница той же
// нормализации: объект с ЕДИНСТВЕННЫМ непустым полем (Extra) несёт реальную
// информацию и обязан остаться персональным оверрайдом, а не схлопнуться в
// nil вместе с по-настоящему пустыми объектами.
func TestUpdateWithOnlyExtraOverridesIsNotNormalizedAway(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{
		Overrides: &store.Overrides{Extra: map[string]string{"I1": "x"}},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	peers, err := env.svc.List()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.ID != issued.ID {
			continue
		}
		if p.Overrides == nil || p.Overrides.Extra["I1"] != "x" {
			t.Fatalf("оверрайд только с extra не должен нормализоваться в nil, получено %+v", p.Overrides)
		}
	}
}

func TestUpdateEmptyPatchIsNoop(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	callsBefore := len(env.fake.Calls)
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{}); err != nil {
		t.Fatalf("пустой патч: %v", err)
	}
	for _, c := range env.fake.Calls[callsBefore:] {
		if strings.HasPrefix(c, "syncconf") {
			t.Fatal("патч без изменений не должен доходить до syncconf: бэкап и применение " +
				"ради нуля изменений — лишний риск на живом устройстве")
		}
	}
}

func TestUpdateDisabledPeerSkipsServerMutation(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	if err := env.svc.Disable(issued.ID); err != nil {
		t.Fatal(err)
	}
	before := readConf(t, env.iface.Config)
	addr := "10.0.0.55/32"
	name := "новое имя"
	if err := env.svc.Update(issued.ID, issuer.PeerPatch{Name: &name, Address: &addr}); err != nil {
		t.Fatalf("правка отключённого пира обязана работать: %v", err)
	}
	if readConf(t, env.iface.Config) != before {
		t.Fatal("у отключённого пира блока в конфиге нет — трогать конфиг не за чем")
	}
	// А после включения новый адрес обязан оказаться на сервере.
	if err := env.svc.Enable(issued.ID); err != nil {
		t.Fatal(err)
	}
	c, _ := wgconf.Parse(readConf(t, env.iface.Config))
	sec, _ := wgconf.FindPeer(c, issuedPublicKey(t, env, issued.ID))
	if sec.Get("AllowedIPs") != "10.0.0.55/32" {
		t.Fatalf("после включения AllowedIPs = %q", sec.Get("AllowedIPs"))
	}
}

// --- Задача 9: ротация ключей пира. ---

// TestRotateKeepsIDNameAddressAndReplacesKeys.
//
// Отличие от буквального текста брифа: число блоков в конфиге ДО ротации
// берётся с диска (peersBefore), а не пришпилено литералом "1" — newServiceEnv
// стартует с двумя пирами из liveConf (me, papa), поэтому после Add("телефон")
// в конфиге три блока, а не один. Проверяемое свойство ("ротация не должна
// плодить блоки") от этого не меняется: peersBefore вычисляется тем же
// wgconf.Parse из того же файла непосредственно перед вызовом Rotate.
func TestRotateKeepsIDNameAddressAndReplacesKeys(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	oldPub := issuedPublicKey(t, env, issued.ID)
	oldPriv, _ := issuer.NewKeyStore(env.iface.Storage.Keys).Get(issued.ID)
	before, _ := wgconf.Parse(readConf(t, env.iface.Config))
	peersBefore := len(before.Peers)

	rotated, err := env.svc.Rotate(issued.ID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if rotated.ID != issued.ID {
		t.Fatal("id пира обязан пережить ротацию: он в URL, в имени файла ключа и в ссылках оператора")
	}
	if rotated.Name != issued.Name || rotated.Address != issued.Address {
		t.Fatalf("имя/адрес изменились: %+v", rotated)
	}
	newPriv, _ := issuer.NewKeyStore(env.iface.Storage.Keys).Get(issued.ID)
	if newPriv == oldPriv {
		t.Fatal("приватный ключ обязан смениться")
	}
	c, _ := wgconf.Parse(readConf(t, env.iface.Config))
	if _, ok := wgconf.FindPeer(c, oldPub); ok {
		t.Fatal("старый публичный ключ обязан исчезнуть из конфига")
	}
	if _, ok := wgconf.FindPeer(c, issuedPublicKey(t, env, issued.ID)); !ok {
		t.Fatal("новый публичный ключ обязан появиться в конфиге")
	}
	if len(c.Peers) != peersBefore {
		t.Fatalf("пиров в конфиге %d, ожидалось %d: ротация не должна плодить блоки", len(c.Peers), peersBefore)
	}
}

func TestRotateRestoresPeerWithoutPrivateKey(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("ручной")
	// Смоделировать пира, заведённого мимо панели: ключа в хранилище нет.
	os.Remove(filepath.Join(env.iface.Storage.Keys, issued.ID+".key"))
	if _, _, err := env.svc.ConfigFor(issued.ID); !errors.Is(err, issuer.ErrNoPrivateKey) {
		t.Fatalf("ожидалась ErrNoPrivateKey, получено %v", err)
	}
	if _, err := env.svc.Rotate(issued.ID); err != nil {
		t.Fatalf("Rotate обязан чинить такого пира: %v", err)
	}
	if _, _, err := env.svc.ConfigFor(issued.ID); err != nil {
		t.Fatalf("после ротации конфиг обязан выдаваться: %v", err)
	}
}

func TestRotateDisabledPeerKeepsPSKInState(t *testing.T) {
	env := newServiceEnv(t)
	issued, _ := env.svc.Add("телефон")
	env.svc.Disable(issued.ID)
	before := readConf(t, env.iface.Config)

	if _, err := env.svc.Rotate(issued.ID); err != nil {
		t.Fatalf("Rotate отключённого: %v", err)
	}
	if readConf(t, env.iface.Config) != before {
		t.Fatal("у отключённого пира блока в конфиге нет — ротация его не трогает")
	}
	st, _ := store.Load(env.iface.Storage.State)
	p, _ := st.Get(issued.ID)
	if p.PresharedKey == "" {
		t.Fatal("новый PSK отключённого пира обязан лечь в peers.json: больше ему негде жить")
	}
	if err := env.svc.Enable(issued.ID); err != nil {
		t.Fatalf("включение после ротации: %v", err)
	}
}

// TestRotateRefusesWhenStateDivergesFromServer — находка ревью (Important):
// peers.json может разойтись с сервером ТАК, что пир числится включённым
// (Enabled=true), а его блока [Peer] в конфиге уже нет. На практике это след
// прежней ротации, которая успела заменить ключ на устройстве (Apply прошёл),
// но отказала на следующем шаге (keys.Put/updatePeer) ДО того, как новый
// PublicKey попал в peers.json. Смоделировано здесь напрямую (см. описание
// сценария в брифе ревью), а не через инъекцию отказа в реальный Rotate: так
// проще и не зависит от того, на каком именно шаге случился отказ — конечное
// состояние на диске одно и то же в обоих случаях.
//
// ВАЖНО: буквальный текст находки предполагал, что повторный Rotate прочитает
// «устаревший p.PublicKey» и, не найдя его в конфиге, пропустит Apply и молча
// перезапишет ключ, вернув nil. Эмпирическая проверка (task-8-9-report.md,
// раздел «Правка после ревью: расхождение состояния в Rotate») показала иной
// механизм: peerByID вызывает loadState → store.Reconcile НА КАЖДОМ обращении,
// а Reconcile для «включён, но не в конфиге» не отказывает, а САМОЛЕЧИТ —
// молча удаляет запись и (если её публичный ключ сейчас держит НА УСТРОЙСТВЕ
// какой-то другой пир) заводит взамен новую с ДРУГИМ id. Из-за этого
// повторный Rotate на непочиненном коде падает с ErrNotFound — не с тихим
// успехом, — но цена та же: peers.json на диске уже переписан, id/slug/
// created_at пира потеряны безвозвратно ДО того, как Rotate вообще вернул
// ответ. Поэтому тест проверяет не только код ошибки, но и то, что peers.json
// НЕ ТРОНУТ вообще — это и есть настоящий инвариант, который защищает id
// пира (раздел 7.2 спеки, тот же принцип, что и в TestRotateKeepsIDName...).
func TestRotateRefusesWhenStateDivergesFromServer(t *testing.T) {
	env := newServiceEnv(t)
	issued, err := env.svc.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	oldPub := issuedPublicKey(t, env, issued.ID)
	oldPriv, err := issuer.NewKeyStore(env.iface.Storage.Keys).Get(issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(env.iface.Storage.State)
	if err != nil {
		t.Fatal(err)
	}

	// Смоделировать след прервавшейся ротации: пир по-прежнему Enabled=true в
	// peers.json (Rotate не трогает Enabled вовсе), но блока [Peer] с ЕГО
	// ключом в конфиге уже нет — как будто предыдущая попытка успела заменить
	// ключ на устройстве и тут же отказала, не записав это в метаданные.
	stripped, err := wgconf.RemovePeerByPublicKey(readConf(t, env.iface.Config), oldPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.iface.Config, []byte(stripped), 0o600); err != nil {
		t.Fatal(err)
	}
	env.fake.Conf = stripped

	_, rotateErr := env.svc.Rotate(issued.ID)
	if rotateErr == nil {
		t.Fatal("ожидалась ошибка: peers.json разошёлся с сервером (пир включён, блока в конфиге нет)")
	}
	if errors.Is(rotateErr, issuer.ErrInvalidInput) {
		t.Errorf("расхождение состояния — не вина ввода оператора, ErrInvalidInput не подходит: %v", rotateErr)
	}
	// Находка финального ревью I4: раньше эта ошибка была обёрнута в
	// ErrPostcondition, statusFor давала 500, а writeError заменяла текст на
	// «внутренняя ошибка» — оператор не видел причину вовсе. ErrStateConflict
	// — собственный класс именно для этого раннего, ДО-применения отказа
	// (в отличие от ErrPostcondition, которая означает «мутация УЖЕ применена
	// к устройству и откачена» — здесь применения не было вовсе).
	if !errors.Is(rotateErr, issuer.ErrStateConflict) {
		t.Errorf("расхождение состояния обязано быть ErrStateConflict, чтобы дойти до оператора текстом (см. statusFor): %v", rotateErr)
	}
	if errors.Is(rotateErr, issuer.ErrPostcondition) {
		t.Errorf("расхождение ДО применения — не ErrPostcondition (та означает «применено и откачено»): %v", rotateErr)
	}

	newPriv, _ := issuer.NewKeyStore(env.iface.Storage.Keys).Get(issued.ID)
	if newPriv != oldPriv {
		t.Error("ротация не должна была перезаписать приватный ключ при отказе до применения")
	}
	if readConf(t, env.iface.Config) != stripped {
		t.Error("ротация не должна была трогать серверный конфиг при отказе до применения")
	}
	// Главная проверка находки: peers.json не тронут ВООБЩЕ, а не просто
	// «PublicKey не тот». Без этой проверки store.Reconcile внутри
	// следующего же peerByID молча стёр бы id/slug/created_at пира — тем
	// самым кодом, который по заданию задачи 9 обязан их сохранять.
	stateAfter, err := os.ReadFile(env.iface.Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	if string(stateAfter) != string(stateBefore) {
		t.Errorf("peers.json изменился при отказе до применения:\nбыло:  %s\nстало: %s", stateBefore, stateAfter)
	}
	st, err := store.Load(env.iface.Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := st.Get(issued.ID)
	if !ok {
		t.Fatal("пир пропал из peers.json — id, слаг и остальные метаданные потеряны")
	}
	if p.PublicKey != oldPub {
		t.Errorf("PublicKey в метаданных изменился при отказе до применения: %q, было %q", p.PublicKey, oldPub)
	}
}

// TestDefaultsLogsIgnoredSeedOnceWhenFileAlreadyExists — находка ревью
// задачи 16 (Important): README обещал строку в лог о том, что секция
// client в config.yaml игнорируется, раз defaults.json уже существует, — а
// кода под это не было вовсе. defaults() дёргается ЛЕНИВО (Add, Rotate,
// configFor, экспортированный Defaults) на протяжении всей жизни процесса,
// а не один раз при старте, поэтому наивное log.Printf на каждый вызов
// заспамило бы журнал при обычной работе панели — лог обязан напечататься
// РОВНО один раз за жизнь Service, отсюда sync.Once на самом Service.
func TestDefaultsLogsIgnoredSeedOnceWhenFileAlreadyExists(t *testing.T) {
	svc, _, cfg := service(t)
	// defaults.json уже лежит на диске ДО первого обращения к Defaults() —
	// то самое состояние «оператор правил client: в config.yaml, но файл
	// умолчаний уже существует, и правка молча игнорируется».
	existing := store.Defaults{Endpoint: "9.9.9.9:1", AllowedIPs: "10.0.0.0/8"}
	if err := existing.Save(cfg.Interfaces[0].DefaultsPath()); err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&logBuf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	svc.Defaults()
	svc.Defaults()
	svc.Defaults()

	got := logBuf.String()
	if count := strings.Count(got, "игнорируется"); count != 1 {
		t.Fatalf("ожидалась ровно одна строка лога про игнорируемую секцию client, получено %d в:\n%s", count, got)
	}
}

// TestDefaultsDoesNotLogOnFirstRun — зеркальная проверка: когда
// defaults.json ещё не было и создаётся из сида впервые, секция client
// НЕ игнорируется (она и есть источник сида), и предупреждать не о чем.
func TestDefaultsDoesNotLogOnFirstRun(t *testing.T) {
	svc, _, _ := service(t)

	var logBuf bytes.Buffer
	prevOut := log.Writer()
	prevFlags := log.Flags()
	log.SetOutput(&logBuf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})

	svc.Defaults()

	if got := logBuf.String(); strings.Contains(got, "игнорируется") {
		t.Fatalf("первый запуск (defaults.json ещё не было) не должен упоминать игнорируемый client::\n%s", got)
	}
}
