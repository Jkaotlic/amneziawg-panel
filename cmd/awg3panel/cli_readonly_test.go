//go:build readonly

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/web"
)

// Этап A (раздел 12.1 спеки, повторено для CLI по образцу
// internal/web/readonly_test.go): read-only сборка физически не умеет
// мутировать через CLI, а не молча отклоняет мутацию в рантайме поверх той
// же кодовой базы. Гарантия — в самом устройстве build-тегов: runCLI из
// cli.go (единственное место в CLI-слое, где вызываются svc.Add/Remove/
// Disable/Enable) несёт тег "!readonly" и в этой сборке НЕ КОМПИЛИРУЕТСЯ —
// единственный runCLI, который здесь существует, это cli_readonly.go, и его
// код (см. файл) не содержит ни одного обращения к этим методам.
//
// Тест ниже проверяет то, что рантайм МОЖЕТ показать: попытка любой из
// четырёх мутирующих команд не вызывает НИ ОДНОГО побочного эффекта —
// ни обращения к устройству (Fake.Calls), ни изменения файла конфига на
// диске, ни изменения состава пиров. Тест, который лишь проверял бы текст
// ошибки, прошёл бы и при рантайм-заглушке "if readonly { return err }"
// поверх полного кода — здесь же дополнительно проверяется, что до самого
// Service мутация вообще не дошла: без этого текстовая проверка ничего не
// доказывает (см. предупреждение задачи "тест, который прошёл бы и без
// тега").
func TestReadonlyRunCLIRefusesMutationsWithoutSideEffects(t *testing.T) {
	// Пробник тега: если он когда-нибудь перестанет пробрасываться в
	// internal/web тем же -tags readonly, тест обязан упасть здесь, а не
	// создать ложное впечатление покрытия.
	if !web.ReadOnlyBuild {
		t.Fatal("сборка с тегом readonly не помечена как read-only (web.ReadOnlyBuild = false)")
	}

	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(testConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)
	f := runtime.NewFake(testConf)
	f.ConfPath = confPath
	svc := issuer.New(cfg.Interfaces[0], cfg.Listen, f)

	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	peersBefore, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ cmd, arg string }{
		{"add", "новый"},
		{"rm", "любой-id"},
		{"disable", "любой-id"},
		{"enable", "любой-id"},
	} {
		var out bytes.Buffer
		err := runCLI(tc.cmd, []string{tc.arg}, svc, &out)
		if err == nil {
			t.Errorf("%s: read-only сборка обязана отказать", tc.cmd)
			continue
		}
		if !strings.Contains(err.Error(), "только чтения") {
			t.Errorf("%s: текст ошибки не объясняет причину: %q", tc.cmd, err.Error())
		}
		if !errors.Is(err, issuer.ErrInvalidInput) {
			t.Errorf("%s: ошибка не классифицирована для кода возврата: %v", tc.cmd, err)
		}
		if out.Len() != 0 {
			t.Errorf("%s: в out при отказе ничего не должно попасть: %q", tc.cmd, out.String())
		}
	}

	for _, c := range f.Calls {
		if strings.HasPrefix(c, "syncconf") || strings.HasPrefix(c, "strip") {
			t.Errorf("read-only сборка обратилась к устройству: %v", f.Calls)
			break
		}
	}
	after, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Error("файл конфига изменился в read-only сборке")
	}
	peersAfter, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peersAfter) != len(peersBefore) {
		t.Errorf("состав пиров изменился в read-only сборке: было %d, стало %d",
			len(peersBefore), len(peersAfter))
	}
}

func TestReadonlyRunCLIListStillWorks(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(testConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)
	f := runtime.NewFake(testConf)
	f.ConfPath = confPath
	svc := issuer.New(cfg.Interfaces[0], cfg.Listen, f)

	var out bytes.Buffer
	if err := runCLI("list", nil, svc, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "10.0.0.2/32") {
		t.Errorf("вывод не содержит адреса пира:\n%s", out.String())
	}
}

// TestReadonlyRunCLIListShowsState — Important 1 фикс-раунда 1: в read-only
// сборке list — ЕДИНСТВЕННАЯ доступная администратору команда, и до той
// правки её вывод не содержал состояния пира (включён/выключен), хотя поле
// p.Enabled уже читаемое и полная сборка его показывает.
//
// Фикстура берётся из listPeersServiceFixture (cli_list_test.go — файл без
// build-тега, то есть существует и в этой сборке): там ОДИН пир включён и
// ОДИН выключен. Прежняя, локальная фикстура несла один-единственный пир из
// testConf, которому store.Reconcile принудительно ставит Enabled=true, —
// искомое "включён" было литералом ветки по умолчанию, и тест оставался
// зелёным при полностью удалённой проверке p.Enabled (находка Important 4
// финального ревью). Проход через runCLI сохранён: он проверяет ещё и то,
// что read-only диспетчер вообще маршрутизирует "list" в общую listPeers.
func TestReadonlyRunCLIListShowsState(t *testing.T) {
	svc := listPeersServiceFixture(t)

	var out bytes.Buffer
	if err := runCLI("list", nil, svc, &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"СОСТОЯНИЕ", "включён", "выключен"} {
		if !strings.Contains(s, want) {
			t.Errorf("read-only список не показывает состояние пира — нет %q:\n%s", want, s)
		}
	}
}

// TestReadonlyDistinguishesUnknownFromDisabled — fix round 1, minor 3:
// опечатка в имени команды не должна выглядеть как осознанно отключённая
// возможность. "add"/"rm"/"disable"/"enable" существуют в полной сборке и
// здесь честно отвечают "недоступна... только чтения"; всё остальное —
// "неизвестная команда", тем же текстом, что и в полной сборке.
func TestReadonlyDistinguishesUnknownFromDisabled(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(testConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)
	f := runtime.NewFake(testConf)
	f.ConfPath = confPath
	svc := issuer.New(cfg.Interfaces[0], cfg.Listen, f)

	for _, tc := range []struct {
		cmd        string
		wantSubstr string
		rejectSub  string
	}{
		{"add", "только чтения", "неизвестная команда"},
		{"rm", "только чтения", "неизвестная команда"},
		{"disable", "только чтения", "неизвестная команда"},
		{"enable", "только чтения", "неизвестная команда"},
		{"плясать", "неизвестная команда", "только чтения"},
	} {
		var out bytes.Buffer
		err := runCLI(tc.cmd, []string{"x"}, svc, &out)
		if err == nil {
			t.Errorf("%s: ожидалась ошибка", tc.cmd)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSubstr) {
			t.Errorf("%s: текст = %q, ожидалась подстрока %q", tc.cmd, err.Error(), tc.wantSubstr)
		}
		if strings.Contains(err.Error(), tc.rejectSub) {
			t.Errorf("%s: текст = %q, НЕ ожидалась подстрока %q", tc.cmd, err.Error(), tc.rejectSub)
		}
	}
}

// testConf в read-only сборке не существует отдельно (cli_test.go несёт тег
// "!readonly" — весь брифовый файл вместе с этой константой физически не
// компилируется здесь), поэтому та же фикстура конфига объявлена локально.
const testConf = `[Interface]
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
