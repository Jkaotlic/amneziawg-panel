package issuer_test

import (
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

const liveConf = serverConf + `
[Peer]
# awg3panel: me
PublicKey = bWUtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMDAwMD0=
PresharedKey = bWUtcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.0.0.2/32

[Peer]
# awg3panel: papa
PublicKey = cGFwYS1wdWJsaWMta2V5LWZha2UtMDAwMDAwMDAwMDAwMD0=
PresharedKey = cGFwYS1wc2stZmFrZS0wMDAwMDAwMDAwMDAwMDAwMDAwPQ==
AllowedIPs = 10.0.0.3/32
`

const (
	meKey   = "bWUtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMDAwMD0="
	papaKey = "cGFwYS1wdWJsaWMta2V5LWZha2UtMDAwMDAwMDAwMDAwMD0="
	addKey  = "bmV3LXB1YmxpYy1rZXktZmFrZS0wMDAwMDAwMDAwMDAwMD0="
	// mePSK — PresharedKey пира meKey в liveConf. Нужен тестам задачи 7,
	// которые заменяют блок meKey через ReplacePeerBlock: PSK в замене
	// обязан остаться тем же, иначе сработает собственная проверка
	// постусловия «изменился PresharedKey», не имеющая отношения к тесту.
	mePSK = "bWUtcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD0="
	// rotatedKey/rotatedPSK — вторая пара ключей для теста ротации: смена
	// PublicKey пира выражается парой Removed(старый ключ)+Added(новый).
	rotatedKey = "cm90YXRlZC1wdWJsaWMta2V5LWZha2UtMDAwMDAwMDAwMD0="
	rotatedPSK = "cm90YXRlZC1wc2stZmFrZS0wMDAwMDAwMDAwMDAwMDAwMDA9"
)

// harness готовит конфиг на диске, фейковое устройство и Applier.
func harness(t *testing.T) (*issuer.Applier, *runtime.Fake, string, string) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(liveConf), 0o600); err != nil {
		t.Fatal(err)
	}
	backups := filepath.Join(dir, "backups")
	f := runtime.NewFake(liveConf)
	f.ConfPath = confPath // strip обязан читать файл, как настоящий awg-quick
	return issuer.NewApplier(f, "awg3", confPath, backups), f, confPath, backups
}

func addPeer(text string) (string, error) {
	return wgconf.AppendPeer(text, wgconf.PeerSpec{
		Name: "новый", PublicKey: addKey,
		PresharedKey: "bmV3LXBzay1mYWtlLTAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=",
		AllowedIPs:   "10.0.0.4/32",
	})
}

func readConf(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApplyAddsPeerAndUsesSyncConf(t *testing.T) {
	a, f, confPath, _ := harness(t)
	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err != nil {
		t.Fatalf("Apply вернул ошибку: %v", err)
	}
	if !strings.Contains(readConf(t, confPath), addKey) {
		t.Error("новый пир не попал в конфиг на диске")
	}
	var sync, set int
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			sync++
		}
		if strings.Contains(c, "setconf") {
			set++
		}
	}
	if sync == 0 {
		t.Errorf("syncconf не вызывался: %v", f.Calls)
	}
	if set != 0 {
		t.Errorf("вызван setconf — он рвёт живые сессии: %v", f.Calls)
	}
}

func TestApplyRemovesPeer(t *testing.T) {
	a, _, confPath, _ := harness(t)
	mutate := func(text string) (string, error) {
		return wgconf.RemovePeerByPublicKey(text, meKey)
	}
	if err := a.Apply(mutate, issuer.Expect{Removed: []string{meKey}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	out := readConf(t, confPath)
	if strings.Contains(out, meKey) {
		t.Error("пир остался в конфиге")
	}
	if !strings.Contains(out, papaKey) {
		t.Error("удалён не тот пир")
	}
}

func TestApplyMakesBackupBeforeWriting(t *testing.T) {
	a, _, _, backups := harness(t)
	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(backups)
	if err != nil {
		t.Fatalf("каталог бэкапов не создан: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("бэкапов %d, ожидался 1", len(entries))
	}
	b, _ := os.ReadFile(filepath.Join(backups, entries[0].Name()))
	if string(b) != liveConf {
		t.Error("бэкап содержит не исходное состояние конфига")
	}
}

func TestApplyKeepsOnly20Backups(t *testing.T) {
	a, _, confPath, backups := harness(t)
	for i := 0; i < 25; i++ {
		// мутация-пустышка: конфиг не меняется, но бэкап делается
		if err := a.Apply(func(s string) (string, error) { return s, nil }, issuer.Expect{}); err != nil {
			t.Fatalf("итерация %d: %v", i, err)
		}
	}
	entries, _ := os.ReadDir(backups)
	if len(entries) > 20 {
		t.Errorf("бэкапов %d, ожидалось не больше 20", len(entries))
	}
	if readConf(t, confPath) != liveConf {
		t.Error("пустая мутация изменила конфиг")
	}
}

// --- Постусловие: каждый вид расхождения из раздела 6 спеки ---

func TestApplyRollsBackWhenDeviceParamDisappears(t *testing.T) {
	a, f, confPath, _ := harness(t)
	f.FaultDropDeviceKey = "HeaderProtectionKey" // молчаливая потеря обфускации
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидалась ошибка: device-параметр исчез с живого устройства")
	}
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Errorf("ошибка не помечена как провал постусловия: %v", err)
	}
	if !strings.Contains(err.Error(), "HeaderProtectionKey") {
		t.Errorf("ошибка не называет разошедшийся параметр: %v", err)
	}
	if readConf(t, confPath) != liveConf {
		t.Error("файл не откачен к исходному состоянию")
	}
	// Critical 1 (случай a) ревью Task 8: FaultDropDeviceKey срабатывает на
	// КАЖДОМ вызове syncconf, включая тот, что делает rollback. Значит
	// повторная синхронизация из того же откаченного файла воспроизводит то
	// же самое расхождение — устройство НЕ возвращается в исходное состояние,
	// хотя файл откачен. Ошибка обязана честно сказать об этом (ErrRollbackFailed
	// + явное указание, что нужно ручное вмешательство), а не заявить об
	// успешном откате.
	if !errors.Is(err, issuer.ErrRollbackFailed) {
		t.Errorf("ошибка не помечена как провал отката, хотя устройство не могло вернуть параметр: %v", err)
	}
	if !strings.Contains(err.Error(), "ручное вмешательство") {
		t.Errorf("ошибка не требует явно ручного вмешательства: %v", err)
	}
}

// Important 4 ревью Task 8: до этой правки все три исхода отката оборачивали
// причину только через %w(cause), так что errors.Is(err, ErrPostcondition)
// был истинен и в ветке, где откат НЕ удался — а на диске или устройстве в
// этот момент лежит плохое состояние. Тест проверяет, что вызывающий может
// различить «откатили» и «откат не удался» без парсинга текста на русском.
func TestApplyDistinguishesRollbackOutcomes(t *testing.T) {
	// Откат УДАЛСЯ по всем фронтам: ErrPostcondition есть, ErrRollbackFailed — нет.
	a, f, _, _ := harness(t)
	f.FaultResetHandshakes = true
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Fatalf("ожидался ErrPostcondition: %v", err)
	}
	if errors.Is(err, issuer.ErrRollbackFailed) {
		t.Errorf("откат файла и устройства удался, но ошибка помечена как ErrRollbackFailed: %v", err)
	}

	// Откат НЕ удался: повторный syncconf при откате отказывает совсем —
	// на устройстве в этот момент действующий (не откаченный) конфиг.
	a2, f2, confPath2, _ := harness(t)
	f2.FaultSyncErr = errors.New("устройство недоступно")
	err2 := a2.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err2 == nil {
		t.Fatal("ожидалась ошибка")
	}
	if !errors.Is(err2, issuer.ErrRollbackFailed) {
		t.Errorf("откат устройства не удался, но ошибка не помечена ErrRollbackFailed: %v", err2)
	}
	if readConf(t, confPath2) != liveConf {
		t.Error("файл всё равно обязан быть восстановлен, даже если синхронизация устройства не удалась")
	}
}

// Critical 1 (случай b) ревью Task 8: файл на диске правили руками мимо
// живого устройства (реальный случай — не гипотеза). before.Device (снимок с
// УСТРОЙСТВА) содержит S1=17, orig (файл) — S1=8. assertInterfaceUntouched
// сравнивает orig с next и не видит проблемы (оба говорят «8»): расхождение
// не в мутации, а в исходном файле. Без предварительной сверки Applier
// применил бы S1=8 к устройству, разошедшемуся по обфускации со всеми
// клиентами, — и это тот же необратимый сценарий, что и Critical 1(a), только
// без даже видимости отката.
func TestApplyRejectsWhenFileDisagreesWithDeviceBeforeWrite(t *testing.T) {
	a, f, confPath, backups := harness(t)
	diverged := strings.Replace(liveConf, "S1 = 17", "S1 = 8", 1)
	if err := os.WriteFile(confPath, []byte(diverged), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидался отказ: файл и устройство разошлись по S1 ещё до мутации")
	}
	if !strings.Contains(err.Error(), "S1") {
		t.Errorf("ошибка не называет разошедшийся параметр: %v", err)
	}
	if readConf(t, confPath) != diverged {
		t.Error("отказ обязан произойти до записи — файл не должен был измениться")
	}
	if entries, _ := os.ReadDir(backups); len(entries) != 0 {
		t.Error("бэкап не должен создаваться при отказе до записи")
	}
	var syncs int
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			syncs++
		}
	}
	if syncs != 0 {
		t.Errorf("syncconf не должен вызываться при отказе до записи: %v", f.Calls)
	}
}

// TestPreflightErrorNamesParamWithoutEchoingSecrets — Critical 1 финального
// ревью. Предварительная сверка покрывает и privatekey, и
// headerprotectionkey (см. requiredDeviceKeys), а её сообщение печатало ОБЕ
// версии расходящегося значения через %q. Срабатывает это ровно в том
// сценарии, ради которого проверка написана — файл правили руками или
// восстановили старый бэкап, — и текст уезжает в лог: web.writeError пишет
// log.Printf("ошибка %d: %v"), CLI — fmt.Fprintln(os.Stderr), то есть в тот
// же journal. CLAUDE.md, незыблемое правило 4 («приватные ключи и PSK не
// пишутся в логи») сформулировано без исключений.
//
// Имя параметра остаётся: без него оператор не поймёт, что чинить, а имя
// секретом не является.
func TestPreflightErrorNamesParamWithoutEchoingSecrets(t *testing.T) {
	const (
		devicePriv = "c2VydmVyLXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9"
		filePriv   = "cG9kbWVuZW5ueXktcHJpdmF0ZS1rZXktZmFrZS0wMDAwMD0="
		deviceHPK  = "aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0="
		fileHPK    = "cG9kbWVuZW5ueXktaHBrLWZha2UtMDAwMDAwMDAwMDAwMDA9"
	)
	for _, tc := range []struct {
		name           string
		param          string
		from, to       string
		deviceV, fileV string
	}{
		{"PrivateKey", "PrivateKey", devicePriv, filePriv, devicePriv, filePriv},
		{"HeaderProtectionKey", "HeaderProtectionKey", deviceHPK, fileHPK, deviceHPK, fileHPK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, confPath, _ := harness(t)
			diverged := strings.Replace(liveConf, tc.from, tc.to, 1)
			if diverged == liveConf {
				t.Fatalf("тестовая правка не сработала — %q не найдено в liveConf", tc.from)
			}
			if err := os.WriteFile(confPath, []byte(diverged), 0o600); err != nil {
				t.Fatal(err)
			}
			err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
			if err == nil {
				t.Fatalf("ожидался отказ: файл и устройство разошлись по %s", tc.param)
			}
			msg := err.Error()
			if !strings.Contains(msg, tc.param) {
				t.Errorf("ошибка не называет разошедшийся параметр %s: %v", tc.param, err)
			}
			if strings.Contains(msg, tc.deviceV) {
				t.Errorf("в тексте ошибки секретное значение %s С УСТРОЙСТВА — оно уедет в "+
					"journal через web.writeError и CLI: %v", tc.param, err)
			}
			if strings.Contains(msg, tc.fileV) {
				t.Errorf("в тексте ошибки секретное значение %s ИЗ ФАЙЛА — оно уедет в "+
					"journal через web.writeError и CLI: %v", tc.param, err)
			}
		})
	}
}

// Critical 1: подтверждение, что предварительная сверка НЕ даёт ложных
// отказов на совершенно нормальном конфиге. Address и MTU в файле умышленно
// отличаются от того, что «было бы» на устройстве — но awg showconf их не
// публикует вовсе (см. Fake.stripped), сравнивать их не с чем, и это не
// расхождение.
func TestApplyPreflightIgnoresFieldsShowConfDoesNotPublish(t *testing.T) {
	a, _, confPath, _ := harness(t)
	edited := strings.Replace(liveConf, "Address = 10.0.0.1/24", "Address = 10.0.0.9/24", 1)
	edited = strings.Replace(edited, "MTU = 1280", "MTU = 1420", 1)
	if err := os.WriteFile(confPath, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err != nil {
		t.Fatalf("предварительная сверка ложно отказала на нормальном конфиге: %v", err)
	}
}

// Открытая находка 2 (ре-ревью Task 8): предыдущая версия предварительной
// сверки смотрела только на ключи, ПРИСУТСТВУЮЩИЕ в файле, — ключ, которого в
// файле нет вовсе (а не просто расходится значением), проходил молча.
// Пошагово: снимок с устройства содержит H4; файл его не содержит;
// assertInterfaceUntouched видит, что orig и next одинаково лишены H4, и не
// возражает; запись и syncconf проходят; клиенты отваливаются РЕАЛЬНО, и
// только тогда постусловие ловит расхождение и зовёт откат. Обязательный
// список device-ключей (requiredDeviceKeys) закрывает это: отсутствие H4 в
// файле при его наличии на устройстве — отказ ДО какой-либо записи.
func TestApplyRejectsWhenFileOmitsRequiredDeviceKey(t *testing.T) {
	a, f, confPath, backups := harness(t)
	withoutH4 := strings.Replace(liveConf, "H4 = 1955441\n", "", 1)
	if withoutH4 == liveConf {
		t.Fatal("тестовая правка не сработала — строка H4 не найдена в liveConf")
	}
	if err := os.WriteFile(confPath, []byte(withoutH4), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидался отказ: обязательный device-параметр H4 есть на устройстве, но отсутствует в файле")
	}
	if !strings.Contains(err.Error(), "H4") {
		t.Errorf("ошибка не называет отсутствующий параметр: %v", err)
	}
	if readConf(t, confPath) != withoutH4 {
		t.Error("отказ обязан произойти до записи — файл не должен был измениться")
	}
	if entries, _ := os.ReadDir(backups); len(entries) != 0 {
		t.Error("бэкап не должен создаваться при отказе до записи")
	}
	var syncs int
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			syncs++
		}
	}
	if syncs != 0 {
		t.Errorf("syncconf не должен вызываться при отказе до записи: %v", f.Calls)
	}
}

// TestApplyRejectsWhenDeviceHasFieldAbsentFromFile — находка 3 живого выката.
//
// Прежняя редакция этого теста (TestApplyIgnoresDeviceOnlyFwMarkKey) требовала
// ОБРАТНОГО: что device-only ключ FwMark, которого нет в файле, — нормальное
// состояние, и Apply обязан пройти. Свойство держалось на допущении Task 8,
// будто syncconf не трогает поля, отсутствующие во входном конфиге, и на
// mergeInterface в фейке, который это допущение воспроизводил. Живой
// эксперимент на AmneziaWG v3.0.20260730 допущение опроверг:
//
//	awg set awg3 fwmark 42     -> awg show awg3 fwmark = 0x2a
//	awg syncconf awg3 <strip>  -> rc=0
//	awg show awg3 fwmark       -> off
//
// Теперь тест утверждает ИЗМЕРЕННОЕ: раз syncconf такое поле сбрасывает,
// применять файл в этом состоянии небезопасно, и отказ обязан случиться ДО
// первой побочки. Без рубежа в предварительной сверке (направление 3)
// последовательность на таком хосте была бы: запись → syncconf → FwMark снесён
// с устройства → постусловие ловит «исчез с устройства» → откат из того же
// файла воспроизводит ту же потерю → ErrRollbackFailed «требуется ручное
// вмешательство». То есть расхождение ловилось бы уже после невосполнимой
// потери. Здесь же не создаётся ни бэкапа, ни записи, ни вызова syncconf.
func TestApplyRejectsWhenDeviceHasFieldAbsentFromFile(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(liveConf), 0o600); err != nil {
		t.Fatal(err)
	}
	backups := filepath.Join(dir, "backups")
	deviceConf := strings.Replace(liveConf, "MTU = 1280", "MTU = 1280\nFwMark = 0xca6c", 1)
	if deviceConf == liveConf {
		t.Fatal("тестовая правка не сработала — строка MTU не найдена в liveConf")
	}
	f := runtime.NewFake(deviceConf)
	f.ConfPath = confPath
	a := issuer.NewApplier(f, "awg3", confPath, backups)

	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидался отказ: FwMark есть на устройстве, но отсутствует в файле — syncconf его сбросит")
	}
	if !strings.Contains(err.Error(), "FwMark") {
		t.Errorf("ошибка не называет расходящийся параметр: %v", err)
	}
	if strings.Contains(err.Error(), "0xca6c") {
		t.Errorf("в тексте ошибки значение device-параметра, а не только имя: %v", err)
	}
	if readConf(t, confPath) != liveConf {
		t.Error("отказ обязан произойти до записи — файл не должен был измениться")
	}
	if entries, _ := os.ReadDir(backups); len(entries) != 0 {
		t.Error("бэкап не должен создаваться при отказе до записи")
	}
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			t.Errorf("syncconf не должен вызываться при отказе до записи: %v", f.Calls)
			break
		}
	}
	// И главное — устройство не тронуто: FwMark на месте.
	if !strings.Contains(f.Conf, "FwMark") {
		t.Error("отказ обязан оставить устройство нетронутым, а FwMark на нём исчез")
	}
}

func TestApplyRollsBackWhenHandshakeReset(t *testing.T) {
	a, f, confPath, _ := harness(t)
	f.FaultResetHandshakes = true // сессии сброшены — именно то, чего избегаем
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидалась ошибка: handshake прежних пиров обнулился")
	}
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Errorf("ошибка не помечена как провал постусловия: %v", err)
	}
	if readConf(t, confPath) != liveConf {
		t.Error("файл не откачен")
	}
}

func TestApplyRollsBackWhenExistingPeerDisappears(t *testing.T) {
	a, f, confPath, _ := harness(t)
	f.FaultDropPeer = papaKey
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидалась ошибка: прежний пир пропал с устройства")
	}
	// Important 3 ревью Task 8: раньше тест проверял только err != nil и откат
	// файла, и это ловилось побочным эффектом соседней проверки allowed-ips
	// (nil против непустого списка), а не собственной защитой на присутствие
	// пира. Явная проверка errors.Is и характерного текста гарантирует, что
	// падает именно из-за пропажи пира, а не из-за чего-то ещё в цикле.
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Errorf("ошибка не помечена как провал постусловия: %v", err)
	}
	if !strings.Contains(err.Error(), "пропал с устройства") {
		t.Errorf("ошибка не называет причину — пропажу пира: %v", err)
	}
	if readConf(t, confPath) != liveConf {
		t.Error("файл не откачен")
	}
	// Открытая находка 1 (ре-ревью Task 8): FaultDropPeer перманентен и
	// срабатывает на КАЖДОМ syncconf, включая тот, что делает rollback —
	// значит откат восстановил файл, но не пира на устройстве. Без сверки
	// состава пиров в rollback это осталось бы за обычным ErrPostcondition,
	// то есть той же ложью «изменения откачены», что и CRITICAL 1 для
	// device-параметров, только классом пиров.
	if !errors.Is(err, issuer.ErrRollbackFailed) {
		t.Errorf("ошибка не помечена как провал отката, хотя пир не мог вернуться на устройство: %v", err)
	}
}

// Critical 2 ревью Task 8: PresharedKey прежнего пира разбирается и лежит в
// обоих снимках, но раньше ничем не сравнивался. Пир с изменившимся PSK
// проходил все проверки (ключ на месте, allowed-ips те же, handshake
// активной сессии ненулевой) и умирал только на следующем rekey — молча и с
// задержкой, ровно та подпись отказа, ради ловли которой писалось
// постусловие.
func TestApplyRollsBackWhenPeerPresharedKeyChanges(t *testing.T) {
	a, f, confPath, _ := harness(t)
	f.FaultChangePeerPSK = papaKey // существующий пир молча получает новый PSK
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидалась ошибка: PresharedKey прежнего пира изменился")
	}
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Errorf("ошибка не помечена как провал постусловия: %v", err)
	}
	if !strings.Contains(err.Error(), "PresharedKey") {
		t.Errorf("ошибка не называет причину — смену PresharedKey: %v", err)
	}
	if readConf(t, confPath) != liveConf {
		t.Error("файл не откачен")
	}
	// Открытая находка 1 (ре-ревью Task 8): FaultChangePeerPSK тоже
	// перманентен — рандомизирует PSK заново и на откатном syncconf, поэтому
	// устройство остаётся с PSK, не совпадающим ни с одним снимком.
	if !errors.Is(err, issuer.ErrRollbackFailed) {
		t.Errorf("ошибка не помечена как провал отката, хотя PSK не мог вернуться на устройство: %v", err)
	}
}

// Important 5 ревью Task 8: раньше пиры сверялись только в одну сторону
// (before → after, плюс exp.Added). Пир, присутствующий в файле на
// диске, но отсутствующий и на устройстве «до», и в exp.Added,
// проходил молча — достижимо через дрейф файла и устройства, предшествующий
// этому конкретному Apply (например, ранее провалившийся откат).
func TestApplyRollsBackWhenUnexpectedPeerAppears(t *testing.T) {
	a, _, confPath, _ := harness(t)
	const driftKey = "ZHJpZnQtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMD0="
	drifted := liveConf + `
[Peer]
# awg3panel: drift
PublicKey = ` + driftKey + `
PresharedKey = ZHJpZnQtcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.0.0.5/32
`
	// Файл на диске уже содержит пира, которого нет на живом устройстве —
	// дрейф, предшествующий этому запуску Apply. Секция [Interface] при этом
	// не меняется, так что предварительная сверка (CRITICAL 1) её пропускает.
	if err := os.WriteFile(confPath, []byte(drifted), 0o600); err != nil {
		t.Fatal(err)
	}
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидалась ошибка: на устройстве появился пир, не запрошенный этим применением")
	}
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Errorf("ошибка не помечена как провал постусловия: %v", err)
	}
	if !strings.Contains(err.Error(), "неожиданно появился") {
		t.Errorf("ошибка не называет причину — неожиданное появление пира: %v", err)
	}
	// Откатываться нужно к состоянию файла НА МОМЕНТ ЭТОГО запуска (drifted),
	// а не к liveConf — drift-пир был в файле ещё до этого Apply.
	if readConf(t, confPath) != drifted {
		t.Error("файл откачен не к тому состоянию, с которого начался этот запуск")
	}
	// Открытая находка 1 (ре-ревью Task 8): drift-пир — часть ФАЙЛА, а не
	// результат мутации, так что откат (restore файла + повторный syncconf)
	// не может убрать его с устройства — он там просто потому, что он есть в
	// восстанавливаемом файле. Откат обязан честно сказать, что состав пиров
	// не совпал со снимком до этого запуска, а не заявить об успехе.
	if !errors.Is(err, issuer.ErrRollbackFailed) {
		t.Errorf("ошибка не помечена как провал отката, хотя drift-пир не мог уйти с устройства: %v", err)
	}
}

func TestApplyRollsBackWhenExpectedChangeDidNotHappen(t *testing.T) {
	a, f, confPath, _ := harness(t)
	f.FaultDropPeer = addKey // добавляемый пир не применился
	err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	if err == nil {
		t.Fatal("ожидалась ошибка: ожидаемое изменение не произошло")
	}
	if readConf(t, confPath) != liveConf {
		t.Error("файл не откачен")
	}
}

func TestApplyRestoresDeviceStateOnRollback(t *testing.T) {
	a, f, _, _ := harness(t)
	f.FaultResetHandshakes = true
	_ = a.Apply(addPeer, issuer.Expect{Added: []string{addKey}})
	// После отката устройство должно быть синхронизировано с исходным файлом:
	// syncconf вызывается повторно, добавленного пира на устройстве нет.
	if strings.Contains(f.Conf, addKey) {
		t.Error("на устройстве остался пир, которого больше нет в файле")
	}
	var syncs int
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") {
			syncs++
		}
	}
	if syncs < 2 {
		t.Errorf("syncconf вызван %d раз — откат не применён к устройству", syncs)
	}
}

func TestApplyReturnsErrorWhenSyncConfFails(t *testing.T) {
	a, f, confPath, _ := harness(t)
	f.FaultSyncErr = errors.New("устройство недоступно")
	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err == nil {
		t.Fatal("ожидалась ошибка")
	}
	if readConf(t, confPath) != liveConf {
		t.Error("файл не откачен после провала syncconf")
	}
}

func TestApplyRejectsMutationBreakingInterface(t *testing.T) {
	a, _, confPath, _ := harness(t)
	// Мутация, которая портит [Interface] — Applier обязан отказаться
	// применять её ещё до записи на диск.
	bad := func(text string) (string, error) {
		return strings.Replace(text, "S1 = 17", "S1 = 8", 1), nil
	}
	err := a.Apply(bad, issuer.Expect{})
	if err == nil {
		t.Fatal("ожидался отказ: мутация изменила [Interface]")
	}
	if readConf(t, confPath) != liveConf {
		t.Error("испорченный конфиг попал на диск")
	}
}

func TestApplyWritesConfigWithRestrictivePermissions(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("unix-права не проверяются на Windows")
	}
	a, _, confPath, _ := harness(t)
	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(confPath)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("права конфига = %v, ожидалось 0600", fi.Mode().Perm())
	}
}

// TestSyncWritesStrippedConfToPrivateTempFile — Important 5 финального
// ревью. Комментарий в sync() обещал «временный файл 0600 внутри
// PrivateTmp», хотя PrivateTmp=yes появится только в systemd-юните задачи 12
// (каталога deploy/ в ветке ещё нет), а os.CreateTemp("", ...) пишет в
// общий /tmp. Комментарий ослаблен до того, что код гарантирует сам, — и
// ровно это здесь и пришпилено, чтобы ослабленное утверждение не оказалось
// таким же необеспеченным, как прежнее.
//
// Файл несёт вывод awg-quick strip, то есть ПриватКлюч сервера и PSK всех
// пиров: без прав 0600 их прочитал бы любой пользователь хоста.
func TestSyncWritesStrippedConfToPrivateTempFile(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("unix-права не проверяются на Windows")
	}
	var hook *syncPathRunner
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(liveConf), 0o600); err != nil {
		t.Fatal(err)
	}
	f := runtime.NewFake(liveConf)
	f.ConfPath = confPath
	hook = &syncPathRunner{Fake: f}
	a := issuer.NewApplier(hook, "awg3", confPath, filepath.Join(dir, "backups"))

	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err != nil {
		t.Fatal(err)
	}
	if hook.path == "" {
		t.Fatal("syncconf не вызывался — тест ничего не проверил")
	}
	if hook.mode.Perm() != 0o600 {
		t.Errorf("права временного файла = %v, ожидалось 0600: в нём лежит вывод "+
			"awg-quick strip, то есть приватный ключ сервера и PSK всех пиров", hook.mode.Perm())
	}
	if !hook.hadSecret {
		t.Error("во временном файле не оказалось приватного ключа сервера — проверка прав " +
			"бессодержательна, если охранять нечего")
	}
	if _, err := os.Stat(hook.path); !os.IsNotExist(err) {
		t.Errorf("временный файл с ключами не удалён после syncconf: stat = %v", err)
	}
}

// syncPathRunner запоминает путь, права и признак наличия секрета у файла,
// который Applier.sync() передаёт в syncconf, — единственный момент, когда
// этот файл ещё существует (дальше его убирает defer в sync()).
type syncPathRunner struct {
	*runtime.Fake
	path      string
	mode      os.FileMode
	hadSecret bool
}

func (s *syncPathRunner) SyncConf(iface, path string) error {
	if s.path == "" {
		s.path = path
		if fi, err := os.Stat(path); err == nil {
			s.mode = fi.Mode()
		}
		if b, err := os.ReadFile(path); err == nil {
			s.hadSecret = strings.Contains(string(b), "PrivateKey")
		}
	}
	return s.Fake.SyncConf(iface, path)
}

func TestApplyLeavesNoTempFiles(t *testing.T) {
	a, _, confPath, _ := harness(t)
	if err := a.Apply(addPeer, issuer.Expect{Added: []string{addKey}}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(filepath.Dir(confPath))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") || strings.HasPrefix(e.Name(), ".awg3") {
			t.Errorf("остался временный файл %s", e.Name())
		}
	}
}

// --- Задача 7: Expect списками, постусловие понимает заявленное изменение пира ---
//
// replaceMe — мутация, общая для трёх тестов ниже: меняет AllowedIPs пира
// meKey через ReplacePeerBlock, оставляя PublicKey и PresharedKey теми же
// (это не ротация — адрес меняется, ключ и PSK нет).
func replaceMeAllowedIPs(newIPs string) func(string) (string, error) {
	return func(text string) (string, error) {
		return wgconf.ReplacePeerBlock(text, meKey, wgconf.PeerSpec{
			PublicKey: meKey, PresharedKey: mePSK, AllowedIPs: newIPs,
		})
	}
}

func TestPostconditionAcceptsDeclaredAddressChange(t *testing.T) {
	a, _, _, _ := harness(t)
	err := a.Apply(replaceMeAllowedIPs("10.0.0.9/32"), issuer.Expect{Modified: []issuer.ExpectedPeerChange{
		{PublicKey: meKey, AllowedIPs: "10.0.0.9/32", HandshakeMayReset: true},
	}})
	if err != nil {
		t.Fatalf("заявленная смена адреса обязана проходить: %v", err)
	}
}

func TestPostconditionRejectsUndeclaredAddressChange(t *testing.T) {
	a, _, confPath, _ := harness(t)
	before := readConf(t, confPath)
	err := a.Apply(replaceMeAllowedIPs("10.0.0.9/32"), issuer.Expect{}) // ничего не заявлено
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Fatalf("незаявленная смена allowed-ips обязана валить постусловие, получено: %v", err)
	}
	if readConf(t, confPath) != before {
		t.Fatal("файл обязан быть откачен из бэкапа")
	}
}

func TestPostconditionRejectsHandshakeResetOfBystander(t *testing.T) {
	a, f, _, _ := harness(t)
	f.FaultResetHandshakes = true
	err := a.Apply(replaceMeAllowedIPs("10.0.0.9/32"), issuer.Expect{Modified: []issuer.ExpectedPeerChange{
		{PublicKey: meKey, AllowedIPs: "10.0.0.9/32", HandshakeMayReset: true},
	}})
	if !errors.Is(err, issuer.ErrPostcondition) {
		t.Fatal("обнуление handshake у НЕзатронутого пира обязано валить постусловие: " +
			"послабление выдаётся поимённо, а не всему устройству")
	}
}

func TestExpectListsSupportRotation(t *testing.T) {
	a, _, _, _ := harness(t)
	mutate := func(text string) (string, error) {
		return wgconf.ReplacePeerBlock(text, meKey, wgconf.PeerSpec{
			PublicKey: rotatedKey, PresharedKey: rotatedPSK, AllowedIPs: "10.0.0.2/32",
		})
	}
	err := a.Apply(mutate, issuer.Expect{Added: []string{rotatedKey}, Removed: []string{meKey}})
	if err != nil {
		t.Fatalf("ротация ключей обязана проходить как Removed+Added: %v", err)
	}
}
