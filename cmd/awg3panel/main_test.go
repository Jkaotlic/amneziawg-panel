package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"golang.org/x/crypto/bcrypt"
)

// TestHashPasswordCmdFromArgument покрывает ветку "пароль пришёл аргументом":
// хеш должен реально соответствовать паролю через bcrypt, а не просто быть
// непустой строкой.
func TestHashPasswordCmdFromArgument(t *testing.T) {
	var out bytes.Buffer
	if err := hashPasswordCmd([]string{"мой-пароль"}, &out); err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	hash := strings.TrimSpace(out.String())
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("мой-пароль")); err != nil {
		t.Errorf("хеш не соответствует паролю %q: %v", "мой-пароль", err)
	}
}

// TestHashPasswordCmdEmptyPasswordFails покрывает ветку отказа на пустом пароле —
// пустой аргумент не должен молча превратиться в пустой валидный хеш.
func TestHashPasswordCmdEmptyPasswordFails(t *testing.T) {
	var out bytes.Buffer
	if err := hashPasswordCmd([]string{""}, &out); err == nil {
		t.Fatal("ожидалась ошибка на пустом пароле")
	}
	if out.Len() != 0 {
		t.Errorf("на ошибке в вывод не должно ничего попасть, получено: %q", out.String())
	}
}

// TestHashPasswordCmdEmptyPasswordIsInvalidInput — fix round 1, minor 4:
// main() раньше гасил ошибку hash-password через log.Fatal (код возврата
// всегда 1, метка времени в выводе — не как у остальных команд CLI), хотя
// "пустой пароль" — самая обычная ошибка ВВОДА и по контракту exitCodeFor
// обязана давать exitInvalidInput (2), как и любая другая. Здесь проверяется
// именно классификация — то, что main.go передаёт в exitCodeFor().
func TestHashPasswordCmdEmptyPasswordIsInvalidInput(t *testing.T) {
	var out bytes.Buffer
	err := hashPasswordCmd([]string{""}, &out)
	if err == nil {
		t.Fatal("ожидалась ошибка на пустом пароле")
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не классифицирована как issuer.ErrInvalidInput: %v", err)
	}
	if got := exitCodeFor(err); got != exitInvalidInput {
		t.Errorf("exitCodeFor(err) = %d, ожидался exitInvalidInput = %d", got, exitInvalidInput)
	}
}

// TestHashPasswordCmdFromStdinTrimsNewline покрывает ветку чтения со stdin и
// обрезку \r\n. hashPasswordCmd не принимает io.Reader — он читает os.Stdin
// напрямую (сигнатура намеренно взята из брифа как есть: единственный
// параметр под подмену в тестах — вывод, io.Writer). Подменить os.Stdin
// временно можно и без изменения сигнатуры функции: os.Stdin — обычная
// экспортируемая переменная пакета os, её можно переставить на конец
// os.Pipe() на время теста и вернуть обратно через defer. Так проверяется
// реальное поведение программы (включая os.Stdin), а не рефакторинг ради
// тестируемости, который бы расширил изменяемую поверхность main.go сверх
// того, что попросил бриф.
func TestHashPasswordCmdFromStdinTrimsNewline(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdin := os.Stdin
	os.Stdin = r
	defer func() { os.Stdin = origStdin }()

	go func() {
		io.WriteString(w, "пароль-из-стдина\r\n")
		w.Close()
	}()

	var out bytes.Buffer
	if err := hashPasswordCmd(nil, &out); err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	hash := strings.TrimSpace(out.String())
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("пароль-из-стдина")); err != nil {
		t.Errorf("хеш из stdin не совпал с паролем (не обрезался \\r\\n?): %v", err)
	}
}

// --- Задача 5: реестр интерфейсов, флаг --iface, команда ifaces. ---
//
// printIfaces и resolveIface вынесены из main() именно затем, чтобы их
// можно было проверить тестом отдельно от os.Args/os.Exit/flag.Parse,
// которые в самом main() не изолировать (тот же приём, что уже применён к
// hashPasswordCmd/runCLI/listPeers в этом пакете). Ни один из тестов ниже не
// касается диска: NewRegistry на этапе конструирования Service не читает и
// не пишет файлы (см. issuer.New), а печать/выбор интерфейса тем более.
func twoMinimalIfaceConfig() *config.Config {
	cfg := config.Default()
	second := cfg.Interfaces[0]
	second.ID, second.Title, second.Interface = "awg4", "Второй", "awg4"
	second.Config = "/nonexistent/awg4.conf"
	second.Storage = config.Storage{
		State: "/nonexistent/awg4/peers.json", Backups: "/nonexistent/awg4/backups",
		Keys: "/nonexistent/awg4/keys", ClientConfigs: "/nonexistent/awg4/clients",
	}
	cfg.Interfaces = append(cfg.Interfaces, second)
	return cfg
}

func fakeRegistry(cfg *config.Config) *issuer.Registry {
	return issuer.NewRegistry(cfg, func(binDir string) runtime.Runner { return runtime.NewFake("") })
}

func TestPrintIfacesFormatsEditFlag(t *testing.T) {
	var out bytes.Buffer
	printIfaces(&out, []issuer.IfaceMeta{
		{ID: "awg3", Title: "Первый", Interface: "awg3", InterfaceEdit: false},
		{ID: "awg4", Title: "Второй", Interface: "awg4", InterfaceEdit: true},
	})
	s := out.String()
	for _, want := range []string{
		"awg3", "Первый", "устройство awg3", "правка [Interface]: нет",
		"awg4", "Второй", "устройство awg4", "правка [Interface]: да",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("в выводе ifaces нет %q:\n%s", want, s)
		}
	}
}

func TestResolveIfaceDefaultsToFirst(t *testing.T) {
	cfg := twoMinimalIfaceConfig()
	reg := fakeRegistry(cfg)
	svc, iface, err := resolveIface(cfg, reg, "")
	if err != nil {
		t.Fatal(err)
	}
	if iface.ID != cfg.Interfaces[0].ID {
		t.Errorf("iface.ID = %q, ожидался первый %q", iface.ID, cfg.Interfaces[0].ID)
	}
	if want := reg.Default(); svc != want {
		t.Error("пустой --iface обязан выбрать Registry.Default()")
	}
}

func TestResolveIfaceSelectsByID(t *testing.T) {
	cfg := twoMinimalIfaceConfig()
	reg := fakeRegistry(cfg)
	svc, iface, err := resolveIface(cfg, reg, cfg.Interfaces[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if iface.ID != cfg.Interfaces[1].ID {
		t.Errorf("iface.ID = %q, ожидался %q", iface.ID, cfg.Interfaces[1].ID)
	}
	want, ok := reg.Mutator(cfg.Interfaces[1].ID)
	if !ok || svc != want {
		t.Error("--iface обязан выбрать соответствующий Service из реестра")
	}
}

func TestResolveIfaceUnknownListsAvailable(t *testing.T) {
	cfg := twoMinimalIfaceConfig()
	reg := fakeRegistry(cfg)
	_, _, err := resolveIface(cfg, reg, "нет-такого")
	if err == nil {
		t.Fatal("ожидалась ошибка на неизвестный --iface")
	}
	for _, id := range []string{cfg.Interfaces[0].ID, cfg.Interfaces[1].ID} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("текст ошибки не называет доступный интерфейс %q: %v", id, err)
		}
	}
}
