//go:build readonly

package main

import (
	"fmt"
	"io"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// В read-only сборке доступна только команда list, вывод которой формирует
// listPeers (cli_list.go, без build-тега) — общая с полной сборкой функция,
// а не собственная копия форматирования (fix round 1, Important 1): раньше
// этот файл нёс свой цикл печати, и он молча не показывал СОСТОЯНИЕ пира.
//
// Мутирующие ветки cli.go (svc.Add/Remove/Disable/Enable) сюда не попадают
// физически — этот файл несёт тег "readonly", cli.go несёт "!readonly", и
// это единственный runCLI, который компилируется в такой сборке (см.
// TestReadonlyRunCLIRefusesMutationsWithoutSideEffects в cli_readonly_test.go).
func runCLI(cmd string, args []string, svc *issuer.Service, out io.Writer) error {
	if cmd == "list" {
		return listPeers(svc, out)
	}
	// mutatingCommands (cli_errors.go) отличает "команда существует, но
	// выключена этой сборкой" от "такой команды нет вообще" (fix round 1,
	// minor 3): раньше awg3panel плясать отвечал тем же текстом, что и
	// awg3panel add, — опечатка выглядела как осознанно отключённая
	// возможность, хотя полная сборка на том же вводе честно говорит
	// "неизвестная команда".
	if mutatingCommands[cmd] {
		return cliInputError{fmt.Sprintf("команда %q недоступна: бинарь собран в режиме только чтения", cmd)}
	}
	return cliInputError{fmt.Sprintf("неизвестная команда %q", cmd)}
}
