package runtime_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// Раздел 6.1 спеки: awg setconf рвёт живые сессии, поэтому вызвать его
// должно быть неоткуда. Проверяем структурно, а не на доверии.
func TestRunnerHasNoSetConf(t *testing.T) {
	rt := reflect.TypeOf((*runtime.Runner)(nil)).Elem()
	for i := 0; i < rt.NumMethod(); i++ {
		name := rt.Method(i).Name
		if strings.Contains(strings.ToLower(name), "setconf") {
			t.Fatalf("в интерфейсе Runner есть метод %q — setconf запрещён", name)
		}
	}
}

const fakeBase = "[Interface]\nPrivateKey = c2VydmVyLXByaXY=\nListenPort = 51820\nS1 = 17\n"

func TestFakeSyncConfRecordsCallAndAppliesFile(t *testing.T) {
	f := runtime.NewFake(fakeBase)
	path := filepath.Join(t.TempDir(), "stripped.conf")
	body := fakeBase + "\n[Peer]\nPublicKey = cA==\nAllowedIPs = 10.0.0.2/32\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.SyncConf("awg3", path); err != nil {
		t.Fatal(err)
	}
	last := f.Calls[len(f.Calls)-1]
	if !strings.HasPrefix(last, "syncconf") {
		t.Fatalf("последний вызов = %q, ожидался syncconf", last)
	}
	out, err := f.Show("awg3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "cA==\t") {
		t.Errorf("после syncconf пир не появился в dump:\n%s", out)
	}
}

// TestFakeSyncConfResetsDeviceOnlyFieldsAbsentFromPushedConf закрепляет
// ИЗМЕРЕННУЮ семантику syncconf. Живой эксперимент на полигоне nl2,
// AmneziaWG v3.0.20260730 (находка 3 выката; допущение Task 8 опровергнуто):
//
//	awg set awg3 fwmark 42     -> awg show awg3 fwmark = 0x2a
//	awg-quick strip awg3 > tmp -> в strip 10 полей обфускации, 0 wg-quick-директив
//	awg syncconf awg3 tmp      -> rc=0
//	awg show awg3 fwmark       -> off
//
// То есть device-поле, отсутствующее в пушимом конфиге, syncconf СБРАСЫВАЕТ,
// а не сохраняет. Прежний mergeInterface моделировал обратное — по пониманию
// протокола IPC, а не по измерению, — и потому маскировал в тестах реальное
// расхождение вместо того, чтобы его показывать.
func TestFakeSyncConfResetsDeviceOnlyFieldsAbsentFromPushedConf(t *testing.T) {
	deviceConf := fakeBase + "FwMark = 0x2a\n"
	f := runtime.NewFake(deviceConf)
	path := filepath.Join(t.TempDir(), "stripped.conf")
	// Пушим ровно то, что даёт strip: FwMark в файле нет и никогда не было.
	if err := os.WriteFile(path, []byte(fakeBase), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.SyncConf("awg3", path); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.Conf, "FwMark") {
		t.Errorf("фейк сохранил device-поле, которого нет в пушимом конфиге, — "+
			"на живом awg оно сбрасывается (измерено на nl2):\n%s", f.Conf)
	}
	out, err := f.ShowConf("awg3")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "FwMark") {
		t.Errorf("showconf после syncconf всё ещё показывает FwMark:\n%s", out)
	}
	// Поля, которые в пушимом конфиге ЕСТЬ, обязаны остаться на устройстве:
	// сбрасывается только отсутствующее, иначе тест был бы доволен и фейком,
	// который стирает вообще всё.
	if !strings.Contains(f.Conf, "S1 = 17") || !strings.Contains(f.Conf, "ListenPort = 51820") {
		t.Errorf("syncconf потерял поля, присутствующие в пушимом конфиге:\n%s", f.Conf)
	}
}

// Фейк обязан вести себя как awg-quick strip: убирать Address/MTU/PostUp,
// но СОХРАНЯТЬ v3-поля — именно поэтому syncconf способен их применить.
func TestFakeStripKeepsObfuscationFields(t *testing.T) {
	conf := "[Interface]\nAddress = 10.0.0.1/24\nMTU = 1280\nPrivateKey = k\n" +
		"S1 = 17\nHeaderProtectionKey = hpk\nPostUp = iptables -A FORWARD -j ACCEPT\n"
	out, err := runtime.NewFake(conf).Strip("awg3")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "Address") || strings.Contains(out, "MTU") || strings.Contains(out, "PostUp") {
		t.Errorf("strip не убрал wg-quick-поля:\n%s", out)
	}
	if !strings.Contains(out, "S1 = 17") || !strings.Contains(out, "HeaderProtectionKey") {
		t.Errorf("strip выбросил v3-поля — фейк не отражает реальность:\n%s", out)
	}
}

// Fix round 1, находка 1: Strip обязан читать ИМЕННО ФАЙЛ конфига, а не
// состояние устройства. Задаём Conf и ConfPath заведомо разным содержимым
// (в каждом свой уникальный пир) и проверяем, что в выводе Strip есть пир
// из файла и нет пира из состояния устройства. Без такого теста регрессия,
// вернувшая Strip к чтению f.Conf, прошла бы весь остальной набор незамеченной.
func TestFakeStripReadsFileNotDevice(t *testing.T) {
	deviceConf := "[Interface]\nPrivateKey = k\n" +
		"[Peer]\nPublicKey = device-only-peer\nAllowedIPs = 10.0.0.9/32\n"
	fileConf := "[Interface]\nAddress = 10.0.0.1/24\nPrivateKey = k\nS1 = 17\n" +
		"[Peer]\nPublicKey = file-only-peer\nAllowedIPs = 10.0.0.5/32\n"

	f := runtime.NewFake(deviceConf)
	path := filepath.Join(t.TempDir(), "file.conf")
	if err := os.WriteFile(path, []byte(fileConf), 0o600); err != nil {
		t.Fatal(err)
	}
	f.ConfPath = path

	out, err := f.Strip("awg3")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "file-only-peer") {
		t.Errorf("Strip не прочитал файл: пир из файла отсутствует в выводе:\n%s", out)
	}
	if strings.Contains(out, "device-only-peer") {
		t.Errorf("Strip вернул состояние устройства вместо файла:\n%s", out)
	}
	if strings.Contains(out, "Address") {
		t.Errorf("Strip не убрал Address из файла:\n%s", out)
	}
	if !strings.Contains(out, "S1 = 17") {
		t.Errorf("Strip не сохранил v3-поле из файла:\n%s", out)
	}
}

// Fix round 1, находка 2: если FaultDropPeer задан ключом, которого в
// применяемом файле нет, инъекция отказа не должна молча провалиться —
// SyncConf обязан вернуть ошибку, а не притвориться успехом.
func TestFakeSyncConfFaultDropPeerMissingKeyErrors(t *testing.T) {
	f := runtime.NewFake(fakeBase)
	f.FaultDropPeer = "no-such-key"
	path := filepath.Join(t.TempDir(), "conf.conf")
	body := fakeBase + "\n[Peer]\nPublicKey = cA==\nAllowedIPs = 10.0.0.2/32\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.SyncConf("awg3", path); err == nil {
		t.Fatal("ожидалась ошибка: FaultDropPeer задан несуществующим ключом, инъекция отказа должна провалиться громко")
	}
}

// Fix round 1, находка 4: PubKey — часть контракта интерфейса Runner и обязан
// возвращать ошибку, как это делает execRunner, а не паниковать.
func TestFakePubKeyRejectsShortKeyInsteadOfPanicking(t *testing.T) {
	f := runtime.NewFake(fakeBase)
	if _, err := f.PubKey("short"); err == nil {
		t.Fatal("ожидалась ошибка на приватный ключ короче 8 символов")
	}
}
