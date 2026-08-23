package main

import (
	"errors"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// errDaemonRunning помечает отказ мутирующей CLI-команды из-за того, что
// что-то (предположительно `awg3panel serve`) уже слушает cfg.Listen. См.
// refuseIfDaemonRunning в cli.go (полная сборка) — решение по риску
// межпроцессной конкуренции подробно разобрано в task-14-report.md.
//
// Файл БЕЗ build-тега: errDaemonRunning и exitCodeFor обязаны существовать в
// обеих сборках (main.go вызывает exitCodeFor независимо от тега), хотя
// производит эту ошибку только полная сборка — в read-only её просто
// никогда не покажут errors.Is.
var errDaemonRunning = errors.New("похоже, панель уже запущена")

// cliInputError — обёртка ошибок ВВОДА CLI (нехватка обязательного
// аргумента, неизвестная команда, недоступность команды в read-only сборке),
// которые заданы дословным текстом (бриф Task 14, Step 3) и НЕ должны
// обрасти префиксом от fmt.Errorf("%w: ...", issuer.ErrInvalidInput) — он
// изменил бы видимый текст. Error() отдаёт msg как есть, Unwrap() открывает
// errors.Is(err, issuer.ErrInvalidInput) для exitCodeFor: с точки зрения
// администратора нехватка id — такая же ошибка ввода, как пустое имя пира
// внутри Service.Add, и обязана получать тот же код возврата.
type cliInputError struct{ msg string }

func (e cliInputError) Error() string { return e.msg }
func (e cliInputError) Unwrap() error { return issuer.ErrInvalidInput }

// mutatingCommands перечисляет имена команд, существующих только в полной
// сборке (cli.go, тег "!readonly"). Используется cli_readonly.go, чтобы
// отличить "команда существует, но выключена этой сборкой" от "такой
// команды нет вообще" — иначе опечатка в имени команды выглядела бы как
// осознанно отключённая возможность (fix round 1, minor 3). Список
// поддерживается вручную в паре со switch в cli.go: там же, где меняется
// набор мутирующих команд, обязана поменяться и эта карта.
var mutatingCommands = map[string]bool{
	"add": true, "rm": true, "disable": true, "enable": true,
}

// Коды возврата процесса. 0 занят успехом рантаймом Go. Дальше — коды,
// которые скрипт вокруг CLI обязан различать не читая stderr (требование
// ревью): несуществующий id, отказ из-за уже работающей панели и ошибка
// ввода — разные ситуации для оператора, и не должны схлопываться в одну
// и ту же "1", которая была раньше единственным кодом отказа.
const (
	exitInternal      = 1 // непредвиденный сбой — свойство по умолчанию, как было до Task 14
	exitInvalidInput  = 2 // issuer.ErrInvalidInput: неверный ввод, включая нехватку аргумента
	exitNotFound      = 3 // issuer.ErrNotFound: такого id нет
	exitDaemonRunning = 4 // errDaemonRunning: похоже, панель уже запущена
)

// exitCodeFor классифицирует ошибку runCLI в код возврата процесса.
// Порядок проверок важен только там, где категории могли бы пересечься —
// здесь этого нет: три sentinel-ошибки взаимоисключающи по построению.
func exitCodeFor(err error) int {
	switch {
	case errors.Is(err, errDaemonRunning):
		return exitDaemonRunning
	case errors.Is(err, issuer.ErrNotFound):
		return exitNotFound
	case errors.Is(err, issuer.ErrInvalidInput):
		return exitInvalidInput
	default:
		return exitInternal
	}
}
