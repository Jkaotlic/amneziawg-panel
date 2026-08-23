package runtime

import (
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

// Important 1 финального ревью: stderr внешнего `awg` вкладывался в текст
// ошибки как есть. Ревьюер проверил боевой бинарь /opt/awg3/bin/awg — он
// содержит форматные строки "Line unrecognized: `%s'" и "Key is not the
// correct length or format: `%s'", то есть при повреждённой строке
// PrivateKey/PresharedKey в применяемом конфиге сам awg печатает СЕКРЕТ в
// stderr. Дальше он становился телом нашей ошибки и уезжал в journal тем же
// путём, что и C1: web.writeError → log.Printf, CLI → os.Stderr.
//
// Ключ ниже — настоящей длины (44 символа base64, 32 байта Curve25519):
// порог вырезания рассчитан именно на неё.
const keyLike = "cHJpdmF0ZS1rZXktb2YtYS1yZWFsLWxlbmd0aC0wMDA9"

func TestCommandErrorRedactsKeyLikeValuesFromStderr(t *testing.T) {
	if len(keyLike) != 44 {
		t.Fatalf("фикстура сломана: длина ключа %d, у настоящего ключа WireGuard/AWG — 44", len(keyLike))
	}
	for _, stderr := range []string{
		"Key is not the correct length or format: `" + keyLike + "'",
		"Line unrecognized: `PrivateKey = " + keyLike + "'",
		"Line unrecognized: `PresharedKey=" + keyLike + "'",
	} {
		err := commandError("awg", []string{"syncconf", "awg3", "/tmp/x.conf"},
			errors.New("exit status 1"), stderr)
		if strings.Contains(err.Error(), keyLike) {
			t.Errorf("секрет из stderr попал в текст ошибки:\nstderr: %s\nошибка: %v", stderr, err)
		}
	}
}

// Диагностика обязана пережить фильтр: без неё администратор не отличит
// «конфиг битый» от «интерфейса нет» и полезет отлаживать вслепую.
func TestCommandErrorKeepsDiagnosticText(t *testing.T) {
	err := commandError("awg", []string{"syncconf", "awg3", "/tmp/x.conf"},
		errors.New("exit status 1"),
		"Key is not the correct length or format: `"+keyLike+"'")
	for _, want := range []string{"Key is not the correct length or format", "syncconf", "awg3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("из ошибки пропала диагностика %q: %v", want, err)
		}
	}
}

// Имена параметров конфига короче порога и вырезаться не должны: самое
// длинное реальное имя — ContentPaddingAddition, 22 символа.
func TestCommandErrorKeepsShortTokens(t *testing.T) {
	err := commandError("awg", []string{"syncconf", "awg3", "/tmp/x.conf"},
		errors.New("exit status 1"),
		"Line unrecognized: `ContentPaddingAddition = 0-96'")
	if !strings.Contains(err.Error(), "ContentPaddingAddition") {
		t.Errorf("вырезано имя параметра, которое секретом не является: %v", err)
	}
}

// syncconf ругается на КАЖДУЮ негодную строку конфига: при массовом
// повреждении файла (обрыв записи, испорченный бэкап) в лог уехал бы весь
// набор ключей разом. Причина отказа читается и по первой строке.
func TestCommandErrorKeepsOnlyFirstStderrLine(t *testing.T) {
	const second = "bmV4dC1saW5lLXNlY3JldC1rZXktMDAwMDAwMDAwMDAwMD0="
	err := commandError("awg", []string{"syncconf", "awg3", "/tmp/x.conf"},
		errors.New("exit status 1"),
		"Line unrecognized: `PrivateKey = "+keyLike+"'\n"+
			"Line unrecognized: `PresharedKey = "+second+"'\n")
	if strings.Contains(err.Error(), second) {
		t.Errorf("в ошибку попала вторая строка stderr с ещё одним секретом: %v", err)
	}
	if strings.Contains(err.Error(), "PresharedKey") {
		t.Errorf("в ошибку попала вторая строка stderr: %v", err)
	}
}

// Обёртка обязана оставаться разворачиваемой: вызывающие различают причины
// через errors.Is/errors.As, а не по тексту.
func TestCommandErrorWrapsCause(t *testing.T) {
	cause := errors.New("устройство недоступно")
	err := commandError("awg", []string{"syncconf", "awg3", "/tmp/x.conf"}, cause, "")
	if !errors.Is(err, cause) {
		t.Errorf("причина не разворачивается через errors.Is: %v", err)
	}
	// Пустой stderr не должен давать висящее двоеточие в конце строки.
	if strings.HasSuffix(err.Error(), ": ") || strings.HasSuffix(err.Error(), ":") {
		t.Errorf("при пустом stderr ошибка заканчивается пустым двоеточием: %q", err.Error())
	}
}

// TestExecRunnerErrorDoesNotLeakStderrSecrets — проверка ПРОВОДКИ, а не
// одной функции: настоящий execRunner.run обязан пропускать stderr через
// фильтр. Unit-тесты выше упали бы и при полностью отключённой проводке.
//
// Требует исполняемого файла без расширения по пути binDir/awg — на Windows
// CreateProcess такой файл не запустит, поэтому там честный Skip, а не
// ложный PASS. В контейнере golang:1.26 (где прогоняется -race) тест
// работает.
func TestExecRunnerErrorDoesNotLeakStderrSecrets(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("на Windows нельзя запустить скрипт без расширения по пути binDir/awg")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo \"Key is not the correct length or format: \\`" + keyLike + "'\" >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "awg"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	err := NewExec(dir).SyncConf("awg3", filepath.Join(dir, "stripped.conf"))
	if err == nil {
		t.Fatal("ожидалась ошибка: подставной awg завершается кодом 1")
	}
	if strings.Contains(err.Error(), keyLike) {
		t.Errorf("execRunner вложил секрет из stderr в ошибку: %v", err)
	}
	if !strings.Contains(err.Error(), "Key is not the correct length or format") {
		t.Errorf("execRunner потерял диагностику целиком: %v", err)
	}
}

// PubKey строит ошибку отдельно от run (приватный ключ идёт через stdin) —
// значит фильтр обязан стоять и там, иначе `awg pubkey` на повреждённом
// ключе напечатает его же в stderr и утечка вернётся другой дверью.
func TestPubKeyErrorAlsoFiltersStderr(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("на Windows нельзя запустить скрипт без расширения по пути binDir/awg")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"echo \"Key is not the correct length or format: \\`" + keyLike + "'\" >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "awg"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := NewExec(dir).PubKey(keyLike)
	if err == nil {
		t.Fatal("ожидалась ошибка: подставной awg завершается кодом 1")
	}
	if strings.Contains(err.Error(), keyLike) {
		t.Errorf("PubKey вложил секрет из stderr в ошибку: %v", err)
	}
}
