package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// listFixtureConf — серверный конфиг с ОДНИМ блоком [Peer]. Второй, ВЫКЛЮЧЕННЫЙ
// пир заводится не здесь, а в peers.json (см. listPeersServiceFixture), и это
// не небрежность фикстуры, а контракт disable: у отключённого пира блока в
// awg3.conf нет по определению — он живёт только в метаданных вместе с
// сохранённым PSK (см. store.Reconcile).
//
// Прежняя редакция обещала в комментарии «двух пиров, один включён, один
// выключен», а давала одного, которому store.Reconcile принудительно ставит
// Enabled=true. Из трёх искомых подстрок "СОСТОЯНИЕ" была статической шапкой,
// а "включён" — литералом ветки по умолчанию: удаление
// `+"`if !p.Enabled { state = \"выключен\" }`"+` оставляло тест зелёным, то есть
// фикс Important 1 предыдущего раунда не был пришпилен вообще (находка
// Important 4 финального ревью).
const listFixtureConf = `[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9
MTU = 1280
S1 = 17
S2 = 21
S3 = 16
S4 = 12
H1 = 1633177
H2 = 2114993
H3 = 1287653
H4 = 1955441
HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0=
ContentPaddingAddition = 0-96

[Peer]
PublicKey = bWUtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMDAwMD0=
PresharedKey = bWUtcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.0.0.2/32
`

// tmpInterfaceStorage строит Storage.* для интерфейса внутри t.TempDir() —
// путём с ПРЯМЫМ слэшем. config.Interface.DefaultsPath (задача 5,
// Service.Defaults) вычисляет каталог состояния через path.Dir (путь на
// целевом Linux-хосте, см. комментарий у Interface.StateDir), а
// filepath.Join на Windows даёт обратный слэш, в котором path.Dir не
// находит разделителя и тихо возвращает "." — Storage.Keys без этой правки
// вообще оставался бы на дефолтном "/var/lib/awg3panel/keys" из
// config.Default(), а это на Windows означает корень ТЕКУЩЕГО диска
// (проверено эмпирически: go test буквально создал и записал в
// G:\var\lib\awg3panel\keys при разработке задачи 5). os.* работает
// одинаково успешно что с прямым, что с обратным слэшем на Windows, поэтому
// подмена безопасна и для обычных файловых операций.
//
// Живёт в этом файле (без build-тега) намеренно: нужна и cli_test.go (тег
// "!readonly"), и cli_readonly_test.go (тег "readonly") — общий хелпер
// обязан быть виден в обеих сборках (находка ревью задачи 5: до этой
// правки Storage.Keys был исправлен только в файлах с тегом "!readonly", и
// тот же пробел, что уже один раз посадил тестовые ключи на корень диска
// G:\, оставался в cli_list_test.go/cli_readonly_test.go нетронутым).
func tmpInterfaceStorage(dir string) config.Storage {
	base := filepath.ToSlash(dir)
	return config.Storage{
		State:         base + "/peers.json",
		Backups:       base + "/backups",
		Keys:          base + "/keys",
		ClientConfigs: base + "/clients",
	}
}

// listPeersServiceFixture строит Service, у которого РОВНО ОДИН пир включён
// (он в конфиге) и РОВНО ОДИН выключен (он только в peers.json) — то есть обе
// ветки колонки СОСТОЯНИЕ достижимы одним вызовом. Не переиспользует
// cliService (cli_test.go): та фикстура тегирована "!readonly" и в read-only
// сборке не существует, а listPeers обязана быть проверена в ОБЕИХ.
func listPeersServiceFixture(t *testing.T) *issuer.Service {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(listFixtureConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)

	// Отключённый пир: в конфиге его нет, в метаданных есть, PSK сохранён —
	// ровно то состояние, которое оставляет после себя disable.
	//
	// Имя выбрано так, чтобы НЕ содержать ни "включён", ни "выключен":
	// первая редакция этой фикстуры звала пира «выключенный», и проверка
	// strings.Contains(s, "выключен") радостно находила его ИМЯ, а не колонку
	// состояния — тест снова проходил при удалённой проверке p.Enabled,
	// ровно та же ошибка, которую он и призван закрыть (поймано мутацией).
	st := &store.State{Version: 1, Peers: []store.Peer{{
		ID: "off000000001", Name: "планшет", PublicKey: offPeerKey,
		Address: "10.0.0.8/32", Enabled: false, PresharedKey: "b2ZmLXBzay1mYWtlLTAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=",
		CreatedAt: "2026-01-01T00:00:00Z",
	}}}
	if err := st.Save(cfg.Interfaces[0].Storage.State); err != nil {
		t.Fatal(err)
	}

	f := runtime.NewFake(listFixtureConf)
	f.ConfPath = confPath
	return issuer.New(cfg.Interfaces[0], cfg.Listen, f)
}

const offPeerKey = "b2ZmLXB1YmxpYy1rZXktZmFrZS0wMDAwMDAwMDAwMDAwMD0="

// TestListPeersShowsState — Important 1 фикс-раунда 1: read-only сборка
// раньше печатала список БЕЗ состояния пира (включён/выключен), хотя это
// единственная команда, доступная администратору в этой сборке. listPeers
// без build-тега — общая для обеих сборок, и этот тест сам без тега:
// доказывает, что состояние есть независимо от того, с каким тегом собран
// пакет.
func TestListPeersShowsState(t *testing.T) {
	svc := listPeersServiceFixture(t)
	var out bytes.Buffer
	if err := listPeers(svc, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	// "выключен" — единственная подстрока, которую нельзя получить ни из
	// статической шапки, ни из литерала ветки по умолчанию: она печатается
	// ТОЛЬКО когда код действительно посмотрел на p.Enabled.
	for _, want := range []string{"СОСТОЯНИЕ", "включён", "выключен", "10.0.0.2/32", "10.0.0.8/32"} {
		if !strings.Contains(s, want) {
			t.Errorf("в выводе listPeers нет %q:\n%s", want, s)
		}
	}
	// Обе колонки состояния обязаны быть у РАЗНЫХ пиров, а не у одного:
	// без этого "включён" и "выключен" могли бы оказаться в одной строке.
	var on, off int
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "ID") || strings.TrimSpace(line) == "" {
			continue
		}
		switch {
		case strings.Contains(line, "выключен"):
			off++
		case strings.Contains(line, "включён"):
			on++
		default:
			t.Errorf("строка пира без состояния: %q", line)
		}
	}
	if on != 1 || off != 1 {
		t.Errorf("включённых строк %d, выключенных %d, ожидалось по одной:\n%s", on, off, s)
	}
}
