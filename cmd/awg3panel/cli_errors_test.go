package main

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// TestExitCodeForDistinguishesCategories покрывает раздел "Коды возврата"
// решения по межпроцессной конкуренции (task-14-report.md): несуществующий
// id, отказ из-за уже запущенной панели, ошибка ввода и непредвиденный сбой
// обязаны получать РАЗНЫЕ коды возврата процесса — иначе скрипт вокруг CLI
// не может отличить "сам виноват" от "попробуй через панель" от "чинить бота".
func TestExitCodeForDistinguishesCategories(t *testing.T) {
	notFound := fmt.Errorf("%w: xyz", issuer.ErrNotFound)
	invalidInput := fmt.Errorf("%w: пустое имя", issuer.ErrInvalidInput)
	daemonRunning := fmt.Errorf("%w: слушает 10.0.0.1:8081", errDaemonRunning)
	internal := errors.New("awg show: exit status 1")

	got := map[string]int{
		"not-found":      exitCodeFor(notFound),
		"invalid-input":  exitCodeFor(invalidInput),
		"daemon-running": exitCodeFor(daemonRunning),
		"internal":       exitCodeFor(internal),
	}
	seen := map[int]string{}
	for name, code := range got {
		if code == 0 {
			t.Errorf("%s: код возврата 0 зарезервирован за успехом", name)
		}
		if other, dup := seen[code]; dup {
			t.Errorf("%s и %s получили один и тот же код %d — они обязаны различаться", name, other, code)
		}
		seen[code] = name
	}
}

// TestCLIInputErrorPreservesExactText: обёртка не должна ничего добавлять к
// тексту, заданному брифом дословно (%w у fmt.Errorf приписал бы префикс
// issuer.ErrInvalidInput.Error()) — только классифицировать её через
// errors.Is.
func TestCLIInputErrorPreservesExactText(t *testing.T) {
	const msg = "укажите имя: awg3panel add <имя>"
	err := cliInputError{msg}
	if err.Error() != msg {
		t.Errorf("Error() = %q, ожидалось дословно %q", err.Error(), msg)
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Error("cliInputError обязана классифицироваться как issuer.ErrInvalidInput")
	}
}
