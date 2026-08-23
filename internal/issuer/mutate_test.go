package issuer_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

func TestAddIssuesWorkingConfig(t *testing.T) {
	s, _, cfg := service(t)
	got, err := s.Add("мой-ноут")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	if got.Address != "10.0.0.4/32" {
		t.Errorf("адрес = %q, ожидался первый свободный 10.0.0.4/32", got.Address)
	}
	c, err := wgconf.Parse(got.Config)
	if err != nil {
		t.Fatalf("выданный конфиг не разбирается: %v", err)
	}
	if c.Interface.Get("S1") != "17" || c.Interface.Get("HeaderProtectionKey") == "" {
		t.Error("в выданном конфиге нет обфускации сервера — клиент не подключится")
	}
	if c.Peers[0].Get("Endpoint") != cfg.Interfaces[0].Client.Endpoint {
		t.Errorf("Endpoint = %q", c.Peers[0].Get("Endpoint"))
	}
	if len(got.QRPNG) == 0 {
		t.Error("QR не сгенерирован")
	}
}

// TestAddWritesServerPeerAndKey — было TestAddWritesServerPeerAndClientFile.
// Задача 5: клиентский .conf больше не сохраняется файлом (собирается на
// лету в ConfigFor), поэтому проверка «конфиг сохранён для повторного
// скачивания» переведена на её новый источник правды — приватный ключ в
// keys/<id>.key. Смысл теста не изменился: выданный пир остаётся доступным
// для повторной выдачи и после того, как исходный ответ Add() потерян.
func TestAddWritesServerPeerAndKey(t *testing.T) {
	s, f, cfg := service(t)
	got, err := s.Add("мой-ноут")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	sc, _ := wgconf.Parse(string(b))
	if len(sc.Peers) != 3 {
		t.Fatalf("пиров в серверном конфиге %d, ожидалось 3", len(sc.Peers))
	}
	if !strings.Contains(f.Conf, got.Address) {
		t.Error("новый пир не применён к устройству")
	}
	// Приватный ключ сохраняется в хранилище ключей — им ConfigFor соберёт
	// конфиг заново при следующем обращении.
	entries, err := os.ReadDir(cfg.Interfaces[0].Storage.Keys)
	if err != nil || len(entries) != 1 {
		t.Fatalf("приватный ключ не сохранён: %v, %d файлов", err, len(entries))
	}
	if entries[0].Name() != got.ID+".key" {
		t.Errorf("имя файла ключа = %q, ожидалось %q", entries[0].Name(), got.ID+".key")
	}
	// И, симметрично, .conf на диск больше не пишется.
	if entries, err := os.ReadDir(cfg.Interfaces[0].Storage.ClientConfigs); err == nil && len(entries) != 0 {
		t.Errorf("клиентский .conf не должен сохраняться на диск: %d файлов", len(entries))
	}
}

// TestRemoveDeletesStoredKey — Remove больше не удаляет файл в clients/ (его
// не существует), а удаляет приватный ключ пира из keys/: ключ мёртвого пира
// не должен переживать сам этот тест на диске бессрочно.
func TestRemoveDeletesStoredKey(t *testing.T) {
	s, _, cfg := service(t)
	issued, err := s.Add("временный")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(cfg.Interfaces[0].Storage.Keys, issued.ID+".key")
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("фикстура сломана: ключ не сохранён после Add: %v", err)
	}
	if err := s.Remove(issued.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(keyPath); !os.IsNotExist(err) {
		t.Errorf("приватный ключ удалённого пира обязан исчезнуть из хранилища: %v", err)
	}
}

func TestAddDoesNotTouchExistingPeers(t *testing.T) {
	s, _, cfg := service(t)
	before, _ := os.ReadFile(cfg.Interfaces[0].Config)
	if _, err := s.Add("ноут"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(cfg.Interfaces[0].Config)
	if !strings.HasPrefix(string(after), string(before)) {
		t.Fatal("добавление изменило существующее содержимое конфига")
	}
}

func TestAddRejectsBadNames(t *testing.T) {
	s, _, _ := service(t)
	for _, bad := range []string{"", "   ", strings.Repeat("я", 41)} {
		if _, err := s.Add(bad); err == nil {
			t.Errorf("имя %q: ожидалась ошибка", bad)
		}
	}
}

func TestRemoveDropsPeerEverywhere(t *testing.T) {
	s, _, cfg := service(t)
	issued, err := s.Add("временный")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Remove(issued.ID); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	b, _ := os.ReadFile(cfg.Interfaces[0].Config)
	sc, _ := wgconf.Parse(string(b))
	if len(sc.Peers) != 2 {
		t.Errorf("пиров %d, ожидалось 2 — конфиг должен вернуться к исходному составу", len(sc.Peers))
	}
	peers, _ := s.List()
	for _, p := range peers {
		if p.ID == issued.ID {
			t.Error("удалённый пир остался в списке")
		}
	}
}

func TestDisableEnableRoundTrip(t *testing.T) {
	s, _, cfg := service(t)
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.Interfaces[0].Config)

	if err := s.Disable(issued.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	mid, _ := os.ReadFile(cfg.Interfaces[0].Config)
	if strings.Contains(string(mid), issued.Address) {
		t.Error("отключённый пир остался в серверном конфиге")
	}
	peers, _ := s.List()
	var found bool
	for _, p := range peers {
		if p.ID == issued.ID {
			found = true
			if p.Enabled {
				t.Error("пир помечен включённым после Disable")
			}
		}
	}
	if !found {
		t.Fatal("отключённый пир пропал из списка — его нельзя будет вернуть")
	}

	if err := s.Enable(issued.ID); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	after, _ := os.ReadFile(cfg.Interfaces[0].Config)
	afterC, _ := wgconf.Parse(string(after))
	beforeC, _ := wgconf.Parse(string(before))
	if len(afterC.Peers) != len(beforeC.Peers) {
		t.Fatalf("после Enable пиров %d, было %d", len(afterC.Peers), len(beforeC.Peers))
	}
	// Ключ, адрес и PSK обязаны совпасть — иначе старый конфиг у клиента мёртв.
	var restored, orig *wgconf.Section
	for _, p := range afterC.Peers {
		if p.Get("AllowedIPs") == issued.Address {
			restored = p
		}
	}
	for _, p := range beforeC.Peers {
		if p.Get("AllowedIPs") == issued.Address {
			orig = p
		}
	}
	if restored == nil || orig == nil {
		t.Fatal("пир не восстановлен")
	}
	for _, k := range []string{"PublicKey", "PresharedKey", "AllowedIPs"} {
		if restored.Get(k) != orig.Get(k) {
			t.Errorf("%s после восстановления = %q, было %q", k, restored.Get(k), orig.Get(k))
		}
	}
}

func TestDisabledAddressIsNotReused(t *testing.T) {
	s, _, _ := service(t)
	first, _ := s.Add("первый")
	if err := s.Disable(first.ID); err != nil {
		t.Fatal(err)
	}
	second, err := s.Add("второй")
	if err != nil {
		t.Fatal(err)
	}
	if second.Address == first.Address {
		t.Errorf("адрес %s переиспользован под другого пира — вернуть первого станет нельзя", second.Address)
	}
}

func TestConfigForReturnsSavedConfig(t *testing.T) {
	s, _, _ := service(t)
	issued, _ := s.Add("планшет")
	name, body, err := s.ConfigFor(issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if body != issued.Config {
		t.Error("повторно выданный конфиг отличается от исходного")
	}
	if !strings.HasSuffix(name, ".conf") {
		t.Errorf("имя файла = %q", name)
	}
}

func TestConfigForUnknownID(t *testing.T) {
	s, _, _ := service(t)
	if _, _, err := s.ConfigFor("нет-такого"); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestQRForReturnsPNG(t *testing.T) {
	s, _, _ := service(t)
	issued, _ := s.Add("часы")
	png, err := s.QRFor(issued.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(png) < 8 || string(png[1:4]) != "PNG" {
		t.Error("ответ не PNG")
	}
}

// TestAddRemoveAddCycleOnServerWithoutPeers — Размен 1 финального ревью:
// панель могла загнать себя в необратимое состояние.
//
// serverConf — это ровно [Interface] без единого блока [Peer], то есть и
// свежеподнятый сервер, и любой сервер, с которого удалили последнего пира.
// В таком конфиге Interface.EndByte равен концу файла, поэтому лишний
// разделитель из AppendPeer растягивал секцию на байт, и
// assertInterfaceUntouched законно отказывал (незыблемое правило 2
// срабатывало правильно — виноват был AppendPeer). При этом удаление
// ПОСЛЕДНЕГО пира проходило без возражений: «удалить всех можно, добавить
// обратно уже нельзя».
//
// Цикл проверяется целиком, а не только первое добавление: именно вторая
// половина (удалить единственного → добавить снова) воспроизводит то, как
// панель загоняет себя в угол за несколько нажатий на живом сервере, где
// пиры изначально есть.
func TestAddRemoveAddCycleOnServerWithoutPeers(t *testing.T) {
	s, _, cfg := serviceWithConf(t, serverConf)

	iface := func(what string) string {
		t.Helper()
		b, err := os.ReadFile(cfg.Interfaces[0].Config)
		if err != nil {
			t.Fatal(err)
		}
		c, err := wgconf.Parse(string(b))
		if err != nil {
			t.Fatalf("%s: конфиг не разбирается: %v", what, err)
		}
		return c.Interface.Bytes(string(b))
	}
	ifaceStart := iface("исходный конфиг")

	first, err := s.Add("первый")
	if err != nil {
		t.Fatalf("добавление первого пира в конфиг без пиров: %v — панель не может завести "+
			"ни одного пира на сервере, где их ещё нет", err)
	}
	if got := iface("после первого добавления"); got != ifaceStart {
		t.Errorf("секция [Interface] изменилась при добавлении первого пира:\nбыло:  %q\nстало: %q",
			ifaceStart, got)
	}

	if err := s.Remove(first.ID); err != nil {
		t.Fatalf("удаление единственного пира: %v", err)
	}
	if got := iface("после удаления единственного"); got != ifaceStart {
		t.Errorf("секция [Interface] изменилась при удалении единственного пира:\nбыло:  %q\nстало: %q",
			ifaceStart, got)
	}
	afterRemove, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := wgconf.Parse(string(afterRemove))
	if err != nil {
		t.Fatal(err)
	}
	if len(rc.Peers) != 0 {
		t.Fatalf("после удаления единственного пира их осталось %d, ожидалось 0", len(rc.Peers))
	}

	second, err := s.Add("второй")
	if err != nil {
		t.Fatalf("повторное добавление после удаления всех пиров: %v — панель загнала себя "+
			"в необратимое состояние", err)
	}
	if got := iface("после повторного добавления"); got != ifaceStart {
		t.Errorf("секция [Interface] изменилась при повторном добавлении:\nбыло:  %q\nстало: %q",
			ifaceStart, got)
	}
	b, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := wgconf.Parse(string(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.Peers) != 1 {
		t.Fatalf("пиров в конфиге %d, ожидался 1", len(sc.Peers))
	}
	if sc.Peers[0].Get("AllowedIPs") != second.Address {
		t.Errorf("адрес пира в конфиге = %q, ожидался %q",
			sc.Peers[0].Get("AllowedIPs"), second.Address)
	}
	// Освободившийся адрес обязан переиспользоваться: пир удалён насовсем,
	// резервировать его больше не за кем.
	if second.Address != first.Address {
		t.Errorf("адрес после удаления и повторного добавления = %q, ожидался освободившийся %q",
			second.Address, first.Address)
	}
}

// --- Fix round 1, Critical 1: отключение пира без PresharedKey ---

// confWithoutPSK — серверный конфиг с пиром БЕЗ PresharedKey. Это не
// гипотетическая фикстура: на боевом сервере main из шести пиров у одного
// PresharedKey отсутствует, то есть сценарий ждёт первого нажатия кнопки.
const confWithoutPSK = serverConf + `
[Peer]
# awg3panel: заведён вручную
PublicKey = ` + meKey + `
AllowedIPs = 10.0.0.2/32
`

// TestDisableRefusesPeerWithoutPSK: у такого пира PSK нельзя сохранить —
// его нет в конфиге, — а wgconf.PeerSpec.validate требует непустой
// PresharedKey, поэтому Enable отказал бы навсегда. Отключение сделало бы
// пира невосстановимым через панель: ключевой материал остался бы только в
// бэкапе awg3.conf. Отказаться честнее, чем молча уничтожить доступ.
func TestDisableRefusesPeerWithoutPSK(t *testing.T) {
	s, f, cfg := serviceWithConf(t, confWithoutPSK)
	before, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	deviceBefore := f.Conf

	err = s.Disable(store.PeerID(meKey))
	if err == nil {
		t.Fatal("ожидался отказ: у пира нет PresharedKey, отключение сделало бы его невосстановимым")
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не помечена как ошибка ввода (%v) — пользователь получит "+
			"«внутренняя ошибка» вместо причины", err)
	}

	after, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("конфиг изменён, хотя отказ обязан произойти до любой записи")
	}
	if f.Conf != deviceBefore {
		t.Error("состояние устройства изменено, хотя отказ обязан произойти до применения")
	}
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			t.Errorf("вызван syncconf при отказе до применения: %v", f.Calls)
			break
		}
	}
}

// --- Fix round 1, Important 3: PSK записывается ДО вырезания блока ---

// hookedRunner — фейковое устройство с перехватом syncconf. Позволяет
// заглянуть на диск в момент, когда файл конфига УЖЕ переписан, а устройство
// вот-вот получит новое состояние: это ровно та точка, где смерть процесса
// или отказ записи оставляют файл и метаданные в разном состоянии.
type hookedRunner struct {
	*runtime.Fake
	onSyncConf func()
}

func (h *hookedRunner) SyncConf(iface, path string) error {
	if h.onSyncConf != nil {
		h.onSyncConf()
	}
	return h.Fake.SyncConf(iface, path)
}

func syncCalls(f *runtime.Fake) int {
	var n int
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			n++
		}
	}
	return n
}

// TestDisableSavesPSKBeforeCuttingConfig: Apply защищает пару «файл ↔
// устройство», но не пару «конфиг ↔ peers.json». Если PSK пишется в
// метаданные ПОСЛЕ вырезания блока, то смерть процесса или отказ st.Save в
// этом промежутке уничтожают единственную копию PSK — без всякой
// конкуренции. Поэтому PSK обязан оказаться на диске раньше, чем блок
// исчезнет из конфига.
func TestDisableSavesPSKBeforeCuttingConfig(t *testing.T) {
	var hook *hookedRunner
	s, _, cfg := serviceWithRunner(t, liveConf, func(f *runtime.Fake) runtime.Runner {
		hook = &hookedRunner{Fake: f}
		return hook
	})
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}

	var pskAtSync, confAtSync string
	// Хук ставится ПОСЛЕ Add, поэтому срабатывает только на syncconf отключения.
	hook.onSyncConf = func() {
		b, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
		if err != nil {
			t.Errorf("чтение peers.json в момент syncconf: %v", err)
			return
		}
		var st store.State
		if err := json.Unmarshal(b, &st); err != nil {
			t.Errorf("разбор peers.json в момент syncconf: %v", err)
			return
		}
		if p, ok := st.Get(issued.ID); ok {
			pskAtSync = p.PresharedKey
		}
		c, err := os.ReadFile(cfg.Interfaces[0].Config)
		if err != nil {
			t.Errorf("чтение конфига в момент syncconf: %v", err)
			return
		}
		confAtSync = string(c)
	}

	if err := s.Disable(issued.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	if confAtSync == "" {
		t.Fatal("хук не сработал — тест ничего не проверил")
	}
	if strings.Contains(confAtSync, issued.Address) {
		t.Fatal("проверка бессодержательна: на момент syncconf блок пира ещё был в файле конфига")
	}
	if pskAtSync == "" {
		t.Error("к моменту вырезания блока PSK ещё не записан в peers.json — " +
			"смерть процесса или отказ записи здесь уничтожают единственную копию")
	}
}

// TestDisableFailsBeforeTouchingDeviceWhenStateUnwritable — тот же инвариант
// со стороны отказа ЗАПИСИ СОСТОЯНИЯ (все прочие тесты отказа инъецируют
// только отказы устройства через runtime.Fake). Если peers.json записать
// нельзя, отключение обязано провалиться ДО того, как блок вырежут из
// конфига: иначе пир уходит с устройства, а его PSK не сохранён нигде.
//
// Блокировка правами — лучшее, что доступно переносимо; под root DAC
// игнорируется, поэтому тест сначала ПРОВЕРЯЕТ, что блокировка сработала, и
// честно пропускается вместо ложного PASS (тот же приём и та же причина, что
// в TestListSurvivesStateWriteFailure).
func TestDisableFailsBeforeTouchingDeviceWhenStateUnwritable(t *testing.T) {
	s, f, cfg := service(t)
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	confBefore, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	stateBefore, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	syncsBefore := syncCalls(f)

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

	disableErr := s.Disable(issued.ID)

	stateAfter, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stateBefore, stateAfter) {
		t.Skip("окружение не блокирует запись через права доступа (содержимое peers.json " +
			"изменилось несмотря на chmod) — похоже, тест запущен с привилегиями, которые " +
			"игнорируют DAC (root/Administrator). Пропускаем, а не притворяемся, что путь " +
			"отказа записи состояния проверен.")
	}

	if disableErr == nil {
		t.Fatal("ожидалась ошибка: сохранить PSK в peers.json не удалось")
	}
	confAfter, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(confBefore, confAfter) {
		t.Error("блок пира вырезан из конфига, хотя PSK сохранить не удалось — " +
			"единственная копия PSK потеряна")
	}
	if syncCalls(f) != syncsBefore {
		t.Error("вызван syncconf, хотя PSK сохранить не удалось — пир снят с устройства безвозвратно")
	}
}

// TestDisabledPeerSurvivesStateWriteFailureAfterApply — Important 2
// финального ревью: окно потери PSK со стороны СЛУЖБЫ, а не store.
//
// Сценарий целиком: Disable сохраняет PSK (пир при этом ещё Enabled=true) →
// Apply успешен, блок [Peer] вырезан из конфига → запись «Enabled=false»
// падает. На диске остаётся Enabled=true с PSK, а в конфиге пира нет. До
// правки следующий же loadState → store.Reconcile промахивался мимо обеих
// веток switch и ВЫБРАСЫВАЛ запись вместе с единственной копией PSK, попутно
// освобождая адрес под следующего клиента.
//
// Отказ записи внедряется подменой peers.json КАТАЛОГОМ, а не chmod: rename
// поверх каталога отказывает и на Linux (EISDIR), и на Windows
// (ERROR_ACCESS_DENIED), тогда как chmod под root игнорируется — тест
// скипался бы ровно там, где его и прогоняют (см. длинный разбор в
// TestListSurvivesStateWriteFailure).
func TestDisabledPeerSurvivesStateWriteFailureAfterApply(t *testing.T) {
	var hook *hookedRunner
	s, _, cfg := serviceWithRunner(t, liveConf, func(f *runtime.Fake) runtime.Runner {
		hook = &hookedRunner{Fake: f}
		return hook
	})
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}

	// Хук ставится ПОСЛЕ Add и срабатывает один раз: на syncconf отключения,
	// то есть внутри Apply — когда PSK уже сохранён, а блок из файла уже
	// вырезан. Дальше Apply завершится успешно, и упадёт именно та запись,
	// что помечает пира выключенным.
	var savedState []byte
	var once sync.Once
	hook.onSyncConf = func() {
		once.Do(func() {
			b, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
			if err != nil {
				t.Errorf("чтение peers.json в момент syncconf: %v", err)
				return
			}
			savedState = b
			if err := os.Remove(cfg.Interfaces[0].Storage.State); err != nil {
				t.Errorf("подмена peers.json каталогом (удаление): %v", err)
				return
			}
			if err := os.Mkdir(cfg.Interfaces[0].Storage.State, 0o700); err != nil {
				t.Errorf("подмена peers.json каталогом (создание): %v", err)
			}
		})
	}

	if err := s.Disable(issued.ID); err == nil {
		t.Fatal("ожидалась ошибка: пометить пира выключенным в peers.json не удалось")
	}
	if savedState == nil {
		t.Fatal("хук не сработал — тест ничего не проверил")
	}

	// Возвращаем на место ровно то содержимое, которое лежало на диске в
	// момент отказа. Именно в таком виде диск остаётся после EIO или гибели
	// процесса — каталог был только способом сломать запись.
	if err := os.Remove(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.Interfaces[0].Storage.State, savedState, 0o600); err != nil {
		t.Fatal(err)
	}

	// Проверка, что окно действительно воспроизведено, а не просто «что-то
	// упало»: без неё тест мог бы пройти на состоянии, к находке отношения
	// не имеющем.
	var onDisk store.State
	if err := json.Unmarshal(savedState, &onDisk); err != nil {
		t.Fatal(err)
	}
	p, ok := onDisk.Get(issued.ID)
	if !ok || !p.Enabled || p.PresharedKey == "" {
		t.Fatalf("окно не воспроизведено: на диске ожидались Enabled=true и непустой PSK, получено %+v", p)
	}
	confAfter, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(confAfter), issued.Address) {
		t.Fatal("окно не воспроизведено: блок [Peer] всё ещё в конфиге, то есть Apply не отработал")
	}

	// Первое же чтение зовёт Reconcile — ту самую точку, где запись
	// выбрасывалась.
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, v := range peers {
		if v.ID != issued.ID {
			continue
		}
		found = true
		if v.Enabled {
			t.Error("пира нет в конфиге, но панель показывает его включённым")
		}
	}
	if !found {
		t.Fatal("пир выброшен из состояния вместе с единственной копией PSK: выданный клиенту " +
			"конфиг больше не оживить, а его адрес уйдёт следующему")
	}
	// Payload: PSK действительно пережил — иначе Enable откажет по
	// ErrInvalidInput «не сохранён PSK».
	if err := s.Enable(issued.ID); err != nil {
		t.Errorf("включить пира обратно не удалось — PSK потерян: %v", err)
	}
}

// --- Fix round 1, Critical 2: read-пути пишут peers.json и обязаны
// сериализоваться с мутациями ---

// TestStateWritingReadsCannotInterleaveWithMutation.
//
// loadState — не читатель: при любом расхождении с конфигом он СОХРАНЯЕТ
// состояние. Его вызывают List, ConfigFor и QRFor. Пока мутация не
// завершена, на диске законно лежит промежуточная пара «блока пира в
// конфиге уже нет, в peers.json он ещё Enabled=true», а store.Reconcile
// такого пира не выключает, а ВЫБРАСЫВАЕТ — вместе с единственной копией
// PSK. Схема потери — load → чужой save → save: атомарность rename от неё
// не защищает, она защищает только от рваного чтения.
//
// Конкретное губительное чередование (read-путь, разорванный планировщиком
// между store.Load и st.Save так, что его запись ложится ПОСЛЕ записи
// мутации) воспроизвести из теста нельзя: точек внедрения между этими
// двумя шагами в продакшн-коде нет и заводить их ради теста неправильно.
// Поэтому тест утверждает свойство, закрывающее ВЕСЬ класс чередований:
// пока идёт мутация, ни один путь, пишущий peers.json, не выполняется.
// Проверка payload'а ниже (пир на месте, PSK жив, Enable работает) — не
// гейт: в этом конкретном чередовании запись мутации всё равно ложится
// последней. Гейт — именно то, что ни один из трёх вызовов не успевает
// завершиться внутри окна.
func TestStateWritingReadsCannotInterleaveWithMutation(t *testing.T) {
	var hook *hookedRunner
	s, _, _ := serviceWithRunner(t, liveConf, func(f *runtime.Fake) runtime.Runner {
		hook = &hookedRunner{Fake: f}
		return hook
	})
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}

	// Каждый вызов сторожится СВОИМ каналом: общий на троих сигнал «все
	// закончили» не отличает «ни один не пролез» от «пролез один, а двое
	// ждут» — проверено саботажем (снят мьютекс только с List: общая
	// проверка этого не заметила).
	var listErr, cfgErr, qrErr error
	listDone := make(chan struct{})
	cfgDone := make(chan struct{})
	qrDone := make(chan struct{})
	var hookRan bool
	// Хук ставится ПОСЛЕ Add: срабатывает на syncconf отключения, то есть
	// внутри критической секции мутации, когда файл конфига уже переписан.
	// once — потому что syncconf будет и позже (проверка Enable в конце), а
	// вклиниться нужно ровно один раз.
	var once sync.Once
	hook.onSyncConf = func() {
		once.Do(func() {
			hookRan = true
			go func() { defer close(listDone); _, listErr = s.List() }()
			go func() { defer close(cfgDone); _, _, cfgErr = s.ConfigFor(issued.ID) }()
			go func() { defer close(qrDone); _, qrErr = s.QRFor(issued.ID) }()

			// Проверка направлена в безопасную сторону: на медленной машине
			// ожидание только надёжнее, а пролезший вызов отрабатывает за
			// миллисекунды.
			time.Sleep(200 * time.Millisecond)
			for name, ch := range map[string]chan struct{}{
				"List": listDone, "ConfigFor": cfgDone, "QRFor": qrDone,
			} {
				select {
				case <-ch:
					t.Errorf("%s отработал ВНУТРИ окна мутации: он пишет peers.json, "+
						"и его запись способна затереть пира вместе с PSK", name)
				default:
				}
			}
		})
	}

	if err := s.Disable(issued.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	// Мьютекс свободен — отложенные вызовы обязаны отработать.
	<-listDone
	<-cfgDone
	<-qrDone

	if !hookRan {
		t.Fatal("хук не сработал — тест ничего не проверил")
	}
	for name, err := range map[string]error{"List": listErr, "ConfigFor": cfgErr, "QRFor": qrErr} {
		if err != nil {
			t.Errorf("%s после мутации вернул ошибку: %v", name, err)
		}
	}

	// Payload: пир пережил конкурентные чтения вместе с PSK.
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range peers {
		if p.ID == issued.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("пир исчез из peers.json после конкурентного чтения")
	}
	if err := s.Enable(issued.ID); err != nil {
		t.Errorf("включить пира обратно не удалось — PSK потерян: %v", err)
	}
}

// --- Fix round 1, Important 4: классы ошибок дописаны до конца ---

// TestEnableWithoutStoredPSKIsInputError: сообщение «не сохранён PSK,
// выпустите нового» — это ровно то, что оператор должен прочитать, а не
// «внутренняя ошибка». Состояние с отключённым пиром без PSK остаётся
// достижимым (правка peers.json руками, пир, отключённый более ранней
// версией панели до запрета из Critical 1), поэтому ветка живая.
func TestEnableWithoutStoredPSKIsInputError(t *testing.T) {
	s, _, cfg := service(t)
	st := &store.State{Version: 1, Peers: []store.Peer{{
		ID: store.PeerID(addKey), Name: "старый", PublicKey: addKey,
		Address: "10.0.0.9/32", Enabled: false, // PresharedKey пуст
	}}}
	if err := st.Save(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatal(err)
	}

	err := s.Enable(store.PeerID(addKey))
	if err == nil {
		t.Fatal("ожидалась ошибка: PSK не сохранён, восстановить пира нечем")
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не помечена как ошибка ввода (%v) — оператор увидит "+
			"«внутренняя ошибка» вместо причины", err)
	}
}

// TestAddOnExhaustedPoolIsInputError: исчерпание пула адресов — состояние,
// которое оператор может исправить (удалить пира, расширить подсеть), а не
// сбой сервера. Родовая «внутренняя ошибка» здесь бесполезна.
func TestAddOnExhaustedPoolIsInputError(t *testing.T) {
	// В /30 адресуемы 10.0.0.1 и 10.0.0.2 (10.0.0.0 — сеть, 10.0.0.3 —
	// широковещательный): первый занят сервером, второй — пиром me из
	// liveConf. Свободных адресов нет с самого начала.
	narrow := strings.Replace(liveConf, "Address = 10.0.0.1/24", "Address = 10.0.0.1/30", 1)
	if narrow == liveConf {
		t.Fatal("тестовая правка не сработала — строка Address не найдена в liveConf")
	}
	s, _, _ := serviceWithConf(t, narrow)

	_, err := s.Add("лишний")
	if err == nil {
		t.Fatal("ожидалась ошибка: свободных адресов в /30 нет")
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не помечена как ошибка ввода (%v) — оператор увидит "+
			"«внутренняя ошибка» вместо «пул адресов исчерпан»", err)
	}
}

// --- Дополнительно к брифу: пути ОТКАЗА. ---
//
// Тесты выше проверяют только счастливый путь, а главное свойство этой
// задачи — то, что происходит, когда применение к живому устройству пошло
// не так: файл, метаданные и выданные клиенту файлы обязаны остаться в
// том же состоянии, что и до попытки. Инъекции отказов берутся из
// runtime.Fake (Task 4): FaultResetHandshakes моделирует молчаливый сброс
// сессий на syncconf, FaultSyncErr — недоступное устройство.

// TestAddRollsBackAndLeavesNoTraceWhenPostconditionFails: неудачное
// добавление не должно оставить ни строчки в конфиге, ни записи в
// peers.json, ни файла клиентского конфига — и не должно израсходовать
// адрес: следующая попытка обязана получить тот же самый 10.0.0.4/32.
func TestAddRollsBackAndLeavesNoTraceWhenPostconditionFails(t *testing.T) {
	s, f, cfg := service(t)
	before, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	f.FaultResetHandshakes = true // syncconf молча сбрасывает сессии всех клиентов

	if _, err := s.Add("ноут"); err == nil {
		t.Fatal("ожидалась ошибка: постусловие нарушено — handshake прежних пиров обнулился")
	} else if !errors.Is(err, issuer.ErrPostcondition) {
		t.Errorf("ошибка не помечена как провал постусловия: %v", err)
	}

	after, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("конфиг не откачен к исходному состоянию")
	}
	// Было: проверка осиротевшего файла в clients/. Задача 5: .conf на диск
	// больше не пишется вовсе (ни при удаче, ни при отказе), поэтому новый
	// след неудачного Add — это приватный ключ в keys/, записываемый уже
	// ПОСЛЕ Apply (см. комментарий над Add). Постусловие здесь нарушается
	// внутри Apply, то есть до keys.Put, — каталог обязан остаться пустым.
	if entries, err := os.ReadDir(cfg.Interfaces[0].Storage.Keys); err == nil && len(entries) != 0 {
		t.Errorf("после неудачного добавления остался приватный ключ пира: %d файлов", len(entries))
	}
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Errorf("пиров в состоянии %d, ожидалось 2 — неудачное добавление попало в метаданные", len(peers))
	}

	f.FaultResetHandshakes = false
	retry, err := s.Add("ноут")
	if err != nil {
		t.Fatalf("повторное добавление после отката: %v", err)
	}
	if retry.Address != "10.0.0.4/32" {
		t.Errorf("адрес после повторной попытки = %q, ожидался 10.0.0.4/32 — "+
			"неудачная попытка израсходовала адрес", retry.Address)
	}
}

// TestAddLeavesPeerUntrackedWhenKeyWriteFails проверяет размен, описанный в
// комментарии над Add (находка ревью задачи 5, было неверно: комментарий
// утверждал, что при отказе записи ключа «пир хотя бы виден в панели», хотя
// keys.Put стоит МЕЖДУ Apply и st.Upsert/st.Save — отказ здесь означает, что
// st.Upsert/st.Save не выполнятся вовсе). Пир обязан остаться на устройстве
// (Apply уже прошёл), но БЕЗ новой записи в peers.json — метаданные, каким
// они были до вызова, не тронуты.
//
// Отказ инъецируется структурным трюком, а не chmod: подмена Storage.Keys
// файлом заставляет os.MkdirAll внутри KeyStore.Put отказать с ENOTDIR.
// chmod каталога здесь не работает — эмпирически проверено при разработке
// задачи 5: атрибут «только чтение» у КАТАЛОГА на Windows не блокирует
// создание файлов внутри (в отличие от переименования поверх уже
// существующего файла, на чём и держатся chmod-тесты состояния, например
// TestListSurvivesStateWriteFailure, — там подмена другая: под запись
// подставлен уже существующий файл, а не пустой каталог). Структурный
// трюк вдобавок uid-независим: ENOTDIR не игнорируется даже под
// root/Administrator, поэтому, в отличие от chmod-тестов по соседству,
// этому не нужен Skip.
func TestAddLeavesPeerUntrackedWhenKeyWriteFails(t *testing.T) {
	s, f, cfg := service(t)
	stateBefore, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		// Бутстрап peers.json ещё не случался — первый List()/Add() создаст
		// файл сам, отсутствие на этом шаге не ошибка фикстуры.
		stateBefore = nil
	}

	if err := os.WriteFile(cfg.Interfaces[0].Storage.Keys, []byte("занято"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, addErr := s.Add("телефон")
	if addErr == nil {
		t.Fatal("ожидалась ошибка: Storage.Keys занят файлом, писать ключ некуда")
	}

	// Устройство пира получило: Apply отработал раньше keys.Put.
	dc, err := wgconf.Parse(f.Conf)
	if err != nil {
		t.Fatal(err)
	}
	if len(dc.Peers) != 3 {
		t.Errorf("пир обязан остаться на устройстве несмотря на отказ записи ключа: "+
			"пиров у устройства %d, ожидалось 3", len(dc.Peers))
	}

	// А peers.json — нет: st.Upsert/st.Save до этой ошибки не дошли.
	stateAfter, err := os.ReadFile(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	if stateBefore != nil && string(stateAfter) != string(stateBefore) {
		t.Errorf("peers.json изменился, хотя keys.Put отказал ДО st.Upsert/st.Save:\n"+
			"было:  %s\nстало: %s", stateBefore, stateAfter)
	}
	var st store.State
	if err := json.Unmarshal(stateAfter, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Peers) != 2 {
		t.Errorf("пиров в peers.json %d, ожидалось 2 — новая запись не должна была появиться", len(st.Peers))
	}
}

// TestRemoveKeepsPeerWhenApplyFails: если применение не удалось, пир обязан
// остаться и в конфиге, и в метаданных, и его клиентский конфиг — на диске.
// Удалить его из peers.json «на всякий случай» значит потерять живого пира
// из панели, оставив его на устройстве.
func TestRemoveKeepsPeerWhenApplyFails(t *testing.T) {
	s, f, cfg := service(t)
	issued, err := s.Add("временный")
	if err != nil {
		t.Fatal(err)
	}
	f.FaultSyncErr = errors.New("устройство недоступно")

	if err := s.Remove(issued.ID); err == nil {
		t.Fatal("ожидалась ошибка: syncconf не удался")
	}

	b, _ := os.ReadFile(cfg.Interfaces[0].Config)
	if !strings.Contains(string(b), issued.Address) {
		t.Error("пир исчез из конфига, хотя применение не удалось")
	}
	peers, _ := s.List()
	var found bool
	for _, p := range peers {
		if p.ID == issued.ID {
			found = true
		}
	}
	if !found {
		t.Error("пир исчез из метаданных, хотя применение не удалось")
	}
	if _, _, err := s.ConfigFor(issued.ID); err != nil {
		t.Errorf("клиентский конфиг удалён при неудачном удалении: %v", err)
	}
}

// TestDisableKeepsPeerEnabledWhenApplyFails: неудачное отключение не должно
// пометить пира выключенным — иначе панель показывает «выключен» для пира,
// который на устройстве живёт и работает.
func TestDisableKeepsPeerEnabledWhenApplyFails(t *testing.T) {
	s, f, cfg := service(t)
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	f.FaultSyncErr = errors.New("устройство недоступно")

	if err := s.Disable(issued.ID); err == nil {
		t.Fatal("ожидалась ошибка: syncconf не удался")
	}

	b, _ := os.ReadFile(cfg.Interfaces[0].Config)
	if !strings.Contains(string(b), issued.Address) {
		t.Fatal("пир вырезан из конфига, хотя применение не удалось")
	}
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	// Флаг found (находка Important 4 финального ревью: у соседа
	// TestRemoveKeepsPeerWhenApplyFails он был, здесь — нет). Пустой список
	// проходил этот цикл молча, не проверив ничего.
	var found bool
	for _, p := range peers {
		if p.ID != issued.ID {
			continue
		}
		found = true
		if !p.Enabled {
			t.Error("пир помечен выключенным, хотя на устройстве он остался включённым")
		}
	}
	if !found {
		t.Error("пир исчез из метаданных, хотя применение не удалось и на устройстве он жив")
	}
	// Одного флага для заявленной регрессии МАЛО, и это выяснено мутацией, а
	// не рассуждением: если бы Disable на пути отказа делал st.Delete+Save,
	// пир всё равно вернулся бы в список — при неудачном Apply его блок
	// остаётся в awg3.conf, а store.Reconcile подхватывает любого пира из
	// конфига обратно, с тем же id (id — хеш публичного ключа). Восстановить
	// Reconcile не может лишь то, чего в конфиге нет: Slug, то есть ссылку на
	// выданный клиенту .conf. Поэтому настоящий детектор потери метаданных —
	// проверка ниже, ровно как у соседа.
	if _, _, err := s.ConfigFor(issued.ID); err != nil {
		t.Errorf("клиентский конфиг стал недоступен при неудачном отключении — "+
			"метаданные пира потеряны: %v", err)
	}

	// Контроль от переусердствовавшей защиты: исправное отключение обязано
	// работать после неудачной попытки.
	f.FaultSyncErr = nil
	if err := s.Disable(issued.ID); err != nil {
		t.Fatalf("повторное отключение после устранения отказа: %v", err)
	}
}

// TestEnableRefusesWhenAddressTakenMeanwhile — Important 3 финального ревью.
//
// Пока пир отключён, его адрес зарезервирован только в peers.json —
// в серверном конфиге блока [Peer] нет. Занять этот адрес за это время может
// кто угодно мимо панели: пир, заведённый руками, или второй процесс (CLI
// против демона — остаточная гонка, оставленная незакрытой сознательно).
// Ни один рубеж этого не ловил: wgconf.AppendPeer сверяет только повтор
// PublicKey, а checkPostcondition выводит exp.Added из-под ВСЕХ
// проверок пиров. Enable молча создавал двух пиров на одном IP — а это
// перекрёстная маршрутизация трафика двух разных клиентов.
func TestEnableRefusesWhenAddressTakenMeanwhile(t *testing.T) {
	s, f, cfg := service(t)
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Disable(issued.ID); err != nil {
		t.Fatal(err)
	}

	// Адрес отключённого пира занимает кто-то другой — мимо панели, сразу и
	// в файле, и на устройстве (иначе отказал бы не тот рубеж: расхождение
	// файла с устройством поймало бы постусловие, а не проверка адреса).
	const squatterKey = "c3F1YXR0ZXItcHVibGljLWtleS1mYWtlLTAwMDAwMDAwPQ=="
	current, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	squatted := string(current) + `
[Peer]
# awg3panel: заведён руками
PublicKey = ` + squatterKey + `
PresharedKey = c3F1YXR0ZXItcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMD0=
AllowedIPs = ` + issued.Address + `
`
	if err := os.WriteFile(cfg.Interfaces[0].Config, []byte(squatted), 0o600); err != nil {
		t.Fatal(err)
	}
	f.Conf = squatted

	err = s.Enable(issued.ID)
	if err == nil {
		t.Fatal("ожидался отказ: адрес отключённого пира занят другим пиром, " +
			"включение создало бы двух пиров на одном IP")
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не помечена как ошибка ввода (%v) — оператор увидит "+
			"«внутренняя ошибка» вместо причины", err)
	}
	if !strings.Contains(err.Error(), issued.Address) {
		t.Errorf("ошибка не называет спорный адрес: %v", err)
	}

	after, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	ac, err := wgconf.Parse(string(after))
	if err != nil {
		t.Fatal(err)
	}
	var onAddr int
	for _, p := range ac.Peers {
		if p.Get("AllowedIPs") == issued.Address {
			onAddr++
		}
	}
	if onAddr != 1 {
		t.Errorf("пиров на адресе %s в конфиге: %d, ожидался ровно 1 (захватчик) — "+
			"панель развела двух клиентов на одном IP", issued.Address, onAddr)
	}
	// PSK обязан уцелеть: отказ на пути включения не должен стирать
	// единственную копию — иначе пира не вернуть уже никогда.
	st, err := store.Load(cfg.Interfaces[0].Storage.State)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := st.Get(issued.ID)
	if !ok {
		t.Fatal("пир исчез из метаданных при отказе включения")
	}
	if p.PresharedKey == "" {
		t.Error("PSK стёрт на пути отказа — выданный клиенту конфиг больше не оживить")
	}
}

// TestEnableStillWorksWhenAddressFree — контроль от переусердствовавшей
// проверки адреса: обычное включение обязано работать, и адрес пира,
// которого в конфиге нет, не должен считаться занятым им самим.
func TestEnableStillWorksWhenAddressFree(t *testing.T) {
	s, _, cfg := service(t)
	issued, err := s.Add("телефон")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Disable(issued.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(issued.ID); err != nil {
		t.Fatalf("включение при свободном адресе отказало: %v", err)
	}
	b, err := os.ReadFile(cfg.Interfaces[0].Config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), issued.Address) {
		t.Error("пир не вернулся в конфиг")
	}
}

// TestEnableKeepsPSKWhenApplyFails — самое дорогое расхождение этой задачи.
// PSK отключённого пира живёт ТОЛЬКО в peers.json (в конфиге блока [Peer]
// уже нет). Если неудачное включение сотрёт его — в конфиге пира по-прежнему
// нет, а взять PSK больше неоткуда: клиент с выданным .conf мёртв навсегда.
func TestEnableKeepsPSKWhenApplyFails(t *testing.T) {
	s, f, cfg := service(t)
	issued, err := s.Add("часы")
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(cfg.Interfaces[0].Config)
	beforeC, _ := wgconf.Parse(string(before))
	var origPSK string
	for _, p := range beforeC.Peers {
		if p.Get("AllowedIPs") == issued.Address {
			origPSK = p.Get("PresharedKey")
		}
	}
	if origPSK == "" {
		t.Fatal("фикстура сломана: у выпущенного пира нет PSK в конфиге")
	}
	if err := s.Disable(issued.ID); err != nil {
		t.Fatal(err)
	}

	f.FaultSyncErr = errors.New("устройство недоступно")
	if err := s.Enable(issued.ID); err == nil {
		t.Fatal("ожидалась ошибка: syncconf не удался")
	}
	f.FaultSyncErr = nil

	if err := s.Enable(issued.ID); err != nil {
		t.Fatalf("повторное включение после неудачной попытки: %v — PSK потерян, "+
			"выданный клиенту конфиг больше не оживить", err)
	}
	after, _ := os.ReadFile(cfg.Interfaces[0].Config)
	afterC, _ := wgconf.Parse(string(after))
	var gotPSK string
	for _, p := range afterC.Peers {
		if p.Get("AllowedIPs") == issued.Address {
			gotPSK = p.Get("PresharedKey")
		}
	}
	if gotPSK != origPSK {
		t.Error("после восстановления у пира другой PSK — старый конфиг клиента мёртв")
	}
}

// TestAddRejectsNamesThatWouldBreakConfig закрывает ветки validateName,
// которых не достаёт TestAddRejectsBadNames: перевод строки и заголовок
// секции ВНУТРИ имени. Имя уезжает в конфиг комментарием
// «# awg3panel: <имя>», и непроверенные \n или [ ] там — инъекция
// произвольных секций в серверный конфиг.
//
// Класс ошибки проверяется отдельно: те же символы отвергает и
// wgconf.PeerSpec.validate, но уже внутри Apply — то есть без ErrInvalidInput
// пользователь получил бы 500 «внутренняя ошибка» вместо причины (см.
// web.statusFor и разведение кодов из ревью Task 11).
func TestAddRejectsNamesThatWouldBreakConfig(t *testing.T) {
	s, _, cfg := service(t)
	before, _ := os.ReadFile(cfg.Interfaces[0].Config)
	for _, bad := range []string{
		"ноут\nPublicKey = cG9kc3Rhdmxlbm55eS1rbHl1Y2gtMDAwMDAwMDAwMDAwMD0=",
		"ноут\n[Peer]",
		"ноут [дом]",
	} {
		_, err := s.Add(bad)
		if err == nil {
			t.Errorf("имя %q: ожидалась ошибка", bad)
			continue
		}
		if !errors.Is(err, issuer.ErrInvalidInput) {
			t.Errorf("имя %q: ошибка не помечена как ошибка ввода (%v) — "+
				"пользователь получит «внутренняя ошибка» вместо причины", bad, err)
		}
	}
	after, _ := os.ReadFile(cfg.Interfaces[0].Config)
	if string(after) != string(before) {
		t.Error("конфиг изменён отклонённым именем")
	}
}

// TestConcurrentAddsDoNotShareAddress: мьютекса внутри Applier мало —
// он держится только на участке «снимок → запись → syncconf → постусловие»,
// а выбор свободного адреса происходит ДО него. Без сериализации мутации
// целиком два одновременных запроса (достаточно двойного клика по кнопке)
// читают конфиг без нового пира, оба выбирают один и тот же первый
// свободный адрес и оба его применяют: повтор публичного ключа AppendPeer
// поймает, повтор AllowedIPs — нет. Плюс каждый сохраняет СВОЮ копию
// peers.json, и вторая запись стирает пира первой.
func TestConcurrentAddsDoNotShareAddress(t *testing.T) {
	s, _, cfg := service(t)
	const n = 6
	issued := make([]*issuer.Issued, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			issued[i], errs[i] = s.Add(fmt.Sprintf("пир-%d", i))
		}(i)
	}
	wg.Wait()

	seen := map[string]int{}
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("Add %d: %v", i, errs[i])
		}
		if prev, dup := seen[issued[i].Address]; dup {
			t.Errorf("адрес %s выдан дважды (пирам %d и %d)", issued[i].Address, prev, i)
		}
		seen[issued[i].Address] = i
	}

	b, _ := os.ReadFile(cfg.Interfaces[0].Config)
	sc, _ := wgconf.Parse(string(b))
	if len(sc.Peers) != n+2 {
		t.Errorf("пиров в конфиге %d, ожидалось %d", len(sc.Peers), n+2)
	}
	peers, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != n+2 {
		t.Errorf("пиров в метаданных %d, ожидалось %d — параллельные записи peers.json "+
			"затёрли друг друга", len(peers), n+2)
	}
}
