//go:build !readonly

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
)

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

// tmpInterfaceStorage живёт в cli_list_test.go (файл без build-тега): она
// нужна и здесь, и в cli_readonly_test.go (тег "readonly"), а этот файл
// несёт тег "!readonly" — общий хелпер обязан лежать в файле, который
// компилируется в ОБЕИХ сборках, иначе одна из них его не увидит.

func cliService(t *testing.T) *issuer.Service {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(testConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	// cfg.Listen НЕ оставлен дефолтным "10.0.0.1:8081" (fix round 1, minor
	// 1): refuseIfDaemonRunning реально стучится в сеть на этот адрес
	// (cli.go, daemonIsListening), и на хосте, где пакеты в такие сети
	// дропаются, а не отвечают отказом сразу, каждый вызов add/rm/disable/
	// enable тормозил бы на полный daemonCheckTimeout. freeAddr(t)
	// (cli_concurrency_test.go) даёт заведомо свободный локальный адрес —
	// проверка получает быстрый и детерминированный ECONNREFUSED.
	cfg.Listen = freeAddr(t)
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)
	f := runtime.NewFake(testConf)
	f.ConfPath = confPath // strip обязан читать файл, как настоящий awg-quick (см. apply_test.go)
	return issuer.New(cfg.Interfaces[0], cfg.Listen, f)
}

func TestCLIList(t *testing.T) {
	var out bytes.Buffer
	if err := runCLI("list", nil, cliService(t), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "10.0.0.2/32") {
		t.Errorf("вывод не содержит адреса пира:\n%s", out.String())
	}
}

func TestCLIAddPrintsConfig(t *testing.T) {
	var out bytes.Buffer
	if err := runCLI("add", []string{"ноутбук"}, cliService(t), &out); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	for _, want := range []string{"[Interface]", "PrivateKey", "S1 = 17", "10.0.0.3/32"} {
		if !strings.Contains(s, want) {
			t.Errorf("в выводе нет %q:\n%s", want, s)
		}
	}
}

func TestCLIAddRequiresName(t *testing.T) {
	var out bytes.Buffer
	if err := runCLI("add", nil, cliService(t), &out); err == nil {
		t.Fatal("ожидалась ошибка: имя не передано")
	}
}

func TestCLIRemoveThenList(t *testing.T) {
	svc := cliService(t)
	var out bytes.Buffer
	if err := runCLI("add", []string{"временный"}, svc, &out); err != nil {
		t.Fatal(err)
	}
	peers, _ := svc.List()
	var id string
	for _, p := range peers {
		if p.Name == "временный" {
			id = p.ID
		}
	}
	if id == "" {
		t.Fatal("пир не найден после добавления")
	}
	out.Reset()
	if err := runCLI("rm", []string{id}, svc, &out); err != nil {
		t.Fatal(err)
	}
	after, _ := svc.List()
	if len(after) != 1 {
		t.Errorf("пиров после удаления %d, ожидался 1", len(after))
	}
}

func TestCLIUnknownCommand(t *testing.T) {
	var out bytes.Buffer
	if err := runCLI("плясать", nil, cliService(t), &out); err == nil {
		t.Fatal("ожидалась ошибка на неизвестную команду")
	}
}

func TestCLIHashPasswordNeedsNoConfig(t *testing.T) {
	var out bytes.Buffer
	// Ключевое свойство: команда обязана работать ДО того, как есть config.yaml —
	// иначе установить пароль будет нечем. Реализована в Task 11, здесь
	// проверяется, что она не потерялась при разрастании CLI.
	if err := hashPasswordCmd([]string{"пароль"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "$2") {
		t.Errorf("вывод не похож на bcrypt-хеш: %q", out.String())
	}
}
