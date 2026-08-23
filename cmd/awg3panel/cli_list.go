package main

import (
	"fmt"
	"io"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
)

// listPeers печатает список пиров в out. Без build-тега и общая для обеих
// сборок (fix round 1, Important 1): до этого cli.go и cli_readonly.go несли
// почти дословные копии одного и того же цикла форматирования за тегом, и
// read-only версия при этом печатала на одну колонку меньше — без
// СОСТОЯНИЯ пира, хотя это единственная команда, доступная в той сборке, и
// поле p.Enabled уже читаемое. Теперь за тегом остаются только мутации, а
// read-only сборка не хранит собственную копию форматирования, которая
// могла бы разъехаться с полной при любой правке.
func listPeers(svc *issuer.Service, out io.Writer) error {
	peers, err := svc.List()
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "%-12s  %-20s  %-16s  %-9s  %s\n",
		"ID", "ИМЯ", "АДРЕС", "СОСТОЯНИЕ", "ПОСЛЕДНИЙ HANDSHAKE")
	for _, p := range peers {
		state := "включён"
		if !p.Enabled {
			state = "выключен"
		}
		hs := "никогда"
		if p.LastHandshake > 0 {
			hs = time.Unix(p.LastHandshake, 0).UTC().Format("2006-01-02 15:04:05 UTC")
		}
		fmt.Fprintf(out, "%-12s  %-20s  %-16s  %-9s  %s\n",
			p.ID, p.Name, p.Address, state, hs)
	}
	return nil
}
