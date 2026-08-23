//go:build !readonly

package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// cliServiceListen — то же, что cliService в cli_test.go, но с управляемым
// cfg.Listen: тестам ниже нужно и занять этот адрес настоящим слушателем
// (изобразить работающий демон), и гарантированно освободить его — чего
// нельзя добиться, когда Listen всегда "10.0.0.1:8081" (адрес туннеля,
// которого на машине с go test нет физически, см. TestDaemonIsListening*).
func cliServiceListen(t *testing.T, listen string) (*issuer.Service, *runtime.Fake) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(testConf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Listen = listen
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)
	f := runtime.NewFake(testConf)
	f.ConfPath = confPath
	return issuer.New(cfg.Interfaces[0], cfg.Listen, f), f
}

// freeAddr выдаёт адрес заведомо свободного порта: слушает на 127.0.0.1:0,
// сразу закрывает — следующий bind на тот же номер порта пройдёт, пока его
// кто-то снова не займёт.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// TestDaemonIsListeningDetectsRealListener — модельный тест самой функции
// определения: живой слушатель на адресе даёт true, тот же адрес после
// Close — false. Без реального демона и без сети шире loopback.
func TestDaemonIsListeningDetectsRealListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if !daemonIsListening(addr) {
		t.Error("daemonIsListening() = false при работающем слушателе")
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	if daemonIsListening(addr) {
		t.Error("daemonIsListening() = true после закрытия слушателя")
	}
}

// TestRefuseMutationsWhenDaemonListening — сердце риска: демон (изображён
// настоящим net.Listener) слушает cfg.Listen, CLI пытается мутировать —
// обязан отказать до касания Service, а не гоняться с демоном за одним и тем
// же peers.json/awg3.conf. Проверяются все четыре мутирующие команды.
func TestRefuseMutationsWhenDaemonListening(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	svc, f := cliServiceListen(t, addr)
	before, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	beforeCalls := len(f.Calls)

	for _, tc := range []struct{ cmd, arg string }{
		{"add", "новый"},
		{"rm", "любой-id"},
		{"disable", "любой-id"},
		{"enable", "любой-id"},
	} {
		var out bytes.Buffer
		err := runCLI(tc.cmd, []string{tc.arg}, svc, &out)
		if err == nil {
			t.Errorf("%s: ожидался отказ, пока демон слушает %s", tc.cmd, addr)
			continue
		}
		if !errors.Is(err, errDaemonRunning) {
			t.Errorf("%s: ошибка не классифицирована как errDaemonRunning: %v", tc.cmd, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, addr) {
			t.Errorf("%s: текст отказа не называет адрес панели %q: %q", tc.cmd, addr, msg)
		}
		if !strings.Contains(msg, "панел") {
			t.Errorf("%s: текст отказа не отсылает к панели как основному пути: %q", tc.cmd, msg)
		}
		// fix round 1, minor 2: errDaemonRunning оборачивается через %w в
		// сообщение, начинающееся теми же словами, — администратор не должен
		// видеть "похоже, панель уже запущена" дважды подряд.
		if n := strings.Count(msg, "панель уже запущена"); n != 1 {
			t.Errorf("%s: фраза \"панель уже запущена\" встречается %d раз(а), ожидался 1: %q",
				tc.cmd, n, msg)
		}
		if out.Len() != 0 {
			t.Errorf("%s: при отказе в out ничего не должно попасть, получено: %q", tc.cmd, out.String())
		}
	}

	// Проверка "устройство не тронуто" — ДО следующего свободного вызова
	// svc.List() ниже: он сам легитимно добавит в f.Calls ещё один "show",
	// и это не мутация, а обычное чтение живого статуса, которое не должно
	// портить сравнение.
	if len(f.Calls) != beforeCalls {
		t.Errorf("отказ обязан произойти ДО обращения к устройству, а вызовы были: %v", f.Calls[beforeCalls:])
	}

	after, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Errorf("состав пиров изменился при отказе: было %d, стало %d", len(before), len(after))
	}
}

// TestMutationsProceedWhenDaemonNotListening — симметричный случай: адрес
// освобождён (freeAddr сама открыла и закрыла слушатель), проверка не
// должна ложно блокировать нормальную работу CLI как основного инструмента
// восстановления, когда демон не поднят.
func TestMutationsProceedWhenDaemonNotListening(t *testing.T) {
	svc, _ := cliServiceListen(t, freeAddr(t))
	var out bytes.Buffer
	if err := runCLI("add", []string{"ноутбук"}, svc, &out); err != nil {
		t.Fatalf("неожиданный отказ при незанятом cfg.Listen: %v", err)
	}
	if !strings.Contains(out.String(), "[Interface]") {
		t.Errorf("add не выпустил конфиг: %s", out.String())
	}
}

// TestRefuseIfDaemonRunningMissesAddressMismatch — fix round 1, Important 2:
// исполняемая фиксация остаточного пробела, честно названного в комментарии
// над refuseIfDaemonRunning. Демон реально работает (настоящий net.Listener
// на daemonAddr), но CLI сконфигурирован ДРУГИМ -config, где cfg.Listen
// указывает на другой, свободный адрес — ровно сценарий "запустили
// восстановительную команду не с тем -config" или "listen: в config.yaml
// поправили уже после старта демона". Проверка бьёт по адресу ИЗ СВОЕГО
// конфига, а не спрашивает демона напрямую, поэтому мутация проходит, хотя
// демон в это время жив и работает на daemonAddr.
//
// Это не баг-репорт "почини" — это фиксация ИЗВЕСТНОГО и ОПИСАННОГО в
// комментарии поведения: если тест однажды начнёт падать, значит защита
// изменилась, и комментарий над refuseIfDaemonRunning обязан обновиться
// вместе с ним, а не разойтись с кодом, как это уже случилось в Task 13
// (Critical: комментарий обещал больше, чем код на самом деле проверял).
func TestRefuseIfDaemonRunningMissesAddressMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	daemonAddr := ln.Addr().String()

	// CLI запущен с ДРУГИМ -config: cfg.Listen указывает не на daemonAddr,
	// а на заведомо свободный адрес.
	svc, _ := cliServiceListen(t, freeAddr(t))

	var out bytes.Buffer
	if err := runCLI("add", []string{"восстановительный"}, svc, &out); err != nil {
		t.Fatalf("ожидался успех несмотря на живой демон на %s: проверка бьёт по "+
			"cfg.Listen СВОЕГО -config, а не по адресу демона — см. комментарий "+
			"над refuseIfDaemonRunning; получена ошибка: %v", daemonAddr, err)
	}
}

// TestCLIUnknownCommandAndMissingArgsAreInvalidInput — "укажите имя",
// "укажите id" и "неизвестная команда" из cli.go — такая же ошибка ВВОДА,
// как пустое имя пира внутри Service.Add, и обязана давать тот же код
// возврата процесса (см. cli_errors_test.go, TestExitCodeForDistinguishesCategories).
func TestCLIUnknownCommandAndMissingArgsAreInvalidInput(t *testing.T) {
	svc := cliService(t)
	var out bytes.Buffer
	for _, tc := range []struct {
		cmd  string
		args []string
	}{
		{"add", nil},
		{"rm", nil},
		{"disable", nil},
		{"enable", nil},
		{"плясать", nil},
	} {
		out.Reset()
		err := runCLI(tc.cmd, tc.args, svc, &out)
		if err == nil {
			t.Errorf("%s: ожидалась ошибка", tc.cmd)
			continue
		}
		if !errors.Is(err, issuer.ErrInvalidInput) {
			t.Errorf("%s: ошибка не классифицирована как issuer.ErrInvalidInput: %v", tc.cmd, err)
		}
	}
}

// confWithoutPSK — сервер с пиром без PresharedKey: закрытая Critical Task 13
// (см. Service.Disable). Проверяем, что через CLI отказ виден так же ясно,
// как из панели, — внятный текст и отличимый код возврата, а не голый стек.
const confWithoutPSK = `[Interface]
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
# awg3panel: заведён вручную
PublicKey = bWUtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMDAwMD0=
AllowedIPs = 10.0.0.2/32
`

func TestCLIDisableWithoutPSKIsClearAndDistinguishable(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "awg3.conf")
	if err := os.WriteFile(confPath, []byte(confWithoutPSK), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Listen = freeAddr(t) // см. комментарий в cliService, cli_test.go — та же причина
	cfg.Interfaces[0].Config = confPath
	cfg.Interfaces[0].Storage = tmpInterfaceStorage(dir)
	fk := runtime.NewFake(confWithoutPSK)
	fk.ConfPath = confPath
	svc := issuer.New(cfg.Interfaces[0], cfg.Listen, fk)

	peers, err := svc.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("ожидался ровно один пир, получено %d", len(peers))
	}
	id := peers[0].ID

	var out bytes.Buffer
	err = runCLI("disable", []string{id}, svc, &out)
	if err == nil {
		t.Fatal("ожидался отказ: у пира нет PresharedKey")
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не классифицирована как issuer.ErrInvalidInput: %v", err)
	}
	if !strings.Contains(err.Error(), "PresharedKey") {
		t.Errorf("текст ошибки не объясняет причину администратору: %q", err.Error())
	}
	if exitCodeFor(err) == exitCodeFor(issuer.ErrNotFound) || exitCodeFor(err) == exitCodeFor(errDaemonRunning) {
		t.Errorf("отказ Disable без PSK получил код возврата, неотличимый от других категорий: %d", exitCodeFor(err))
	}
}
