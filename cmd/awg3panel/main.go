// Command awg3panel — веб-панель выпуска клиентских конфигов AmneziaWG 3.0.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/web"
)

// version подставляется линкером: -ldflags "-X main.version=..."
var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	configPath := flag.String("config", "/etc/awg3panel/config.yaml", "путь к config.yaml")
	ifaceID := flag.String("iface", "", "id интерфейса из config.yaml (по умолчанию первый)")
	flag.Parse()

	cmd := flag.Arg(0)
	// version и hash-password обрабатываются ДО загрузки конфига:
	// хеш пароля нужен как раз для того, чтобы конфиг стало возможно заполнить.
	switch cmd {
	case "version":
		build := "полная"
		if web.ReadOnlyBuild {
			build = "только чтение"
		}
		fmt.Printf("awg3panel %s (сборка: %s)\n", version, build)
		return
	case "hash-password":
		// Тот же путь, что и у мутирующих команд ниже (fix round 1,
		// minor 4): раньше здесь стоял log.Fatal — код возврата всегда 1
		// независимо от причины, и в stderr уходила строка с меткой
		// времени от log, не как у остальных ошибок CLI.
		if err := hashPasswordCmd(flag.Args()[1:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCodeFor(err))
		}
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("конфигурация: %v", err)
	}
	// Реестр строит по Service на КАЖДЫЙ интерфейс из config.yaml (задача 5)
	// — конструктор Service не трогает диск (см. issuer.New), так что это
	// дёшево независимо от того, какой интерфейс дальше будет выбран.
	reg := issuer.NewRegistry(cfg, func(binDir string) runtime.Runner { return runtime.NewExec(binDir) })

	// ifaces — читающая команда и обязана работать в read-only сборке тоже,
	// поэтому обрабатывается здесь, а не в mutatingCommands/runCLI
	// (cli_errors.go): та карта перечисляет команды, которых в read-only
	// бинаре нет физически, а ifaces есть в обеих сборках.
	if cmd == "ifaces" {
		printIfaces(os.Stdout, reg.Metas())
		return
	}

	// serve обслуживает ВЕСЬ реестр разом (задача 10: маршруты несут префикс
	// /api/ifaces/{iface}/...), поэтому --iface здесь ни на что не влияет —
	// в отличие от CLI-команд ниже, которым он и нужен: выбрать ОДИН
	// интерфейс, над которым выполнить разовую мутацию (add/rm/disable/enable)
	// или прочитать список (list).
	switch cmd {
	case "", "serve":
		if err := newServer(cfg, reg).ListenAndServe(); err != nil {
			log.Fatalf("сервер: %v", err)
		}
	default:
		svc, _, err := resolveIface(cfg, reg, *ifaceID)
		if err != nil {
			log.Fatal(err)
		}
		if err := runCLI(cmd, flag.Args()[1:], svc, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitCodeFor(err))
		}
	}
}

// printIfaces печатает таблицу интерфейсов для команды "ifaces". Вынесена
// из main(), чтобы формат вывода можно было проверить тестом отдельно от
// os.Args/os.Exit, которые в main() не изолировать.
func printIfaces(w io.Writer, metas []issuer.IfaceMeta) {
	for _, m := range metas {
		edit := "нет"
		if m.InterfaceEdit {
			edit = "да"
		}
		fmt.Fprintf(w, "%s\t%s\tустройство %s\tправка [Interface]: %s\n",
			m.ID, m.Title, m.Interface, edit)
	}
}

// resolveIface выбирает интерфейс для CLI-команд по флагу --iface: пустое
// значение — тот же интерфейс, что Registry.Default() (первый по порядку в
// config.yaml), непустое — точное совпадение id, иначе отказ со списком
// доступных id. serve эту функцию больше не зовёт (задача 10 перевела
// web.Server на весь реестр — маршруты сами выбирают интерфейс по пути
// запроса), возврат config.Interface в main() тоже больше не используется
// (только *issuer.Service идёт в runCLI) — сигнатура оставлена как есть,
// чтобы не трогать её тесты (TestResolveIface*, main_test.go), которые
// проверяют оба значения по отдельности.
func resolveIface(cfg *config.Config, reg *issuer.Registry, ifaceID string) (*issuer.Service, config.Interface, error) {
	if ifaceID == "" {
		return reg.Default(), cfg.Interfaces[0], nil
	}
	svc, ok := reg.Mutator(ifaceID)
	if !ok {
		ids := make([]string, 0, len(reg.Metas()))
		for _, m := range reg.Metas() {
			ids = append(ids, m.ID)
		}
		return nil, config.Interface{}, fmt.Errorf("интерфейс %q не найден; доступны: %s",
			ifaceID, strings.Join(ids, ", "))
	}
	for _, i := range cfg.Interfaces {
		if i.ID == ifaceID {
			return svc, i, nil
		}
	}
	// Недостижимо: Registry строится из cfg.Interfaces тем же перебором
	// (см. issuer.NewRegistry), так что успешный Mutator(ifaceID) гарантирует
	// совпадение и здесь.
	return nil, config.Interface{}, fmt.Errorf("интерфейс %q найден в реестре, но не в конфиге", ifaceID)
}

// hashPasswordCmd печатает bcrypt-хеш для config.yaml. Пароль берётся
// из аргумента либо со стандартного ввода — второе предпочтительнее,
// потому что аргумент остаётся в истории команд:
//
//	printf '%s' 'мой-пароль' | awg3panel hash-password
//
// Скрытие ввода с терминала намеренно не делается: это потребовало бы
// четвёртой зависимости ради разовой операции установки.
func hashPasswordCmd(args []string, out io.Writer) error {
	var plain string
	if len(args) > 0 {
		plain = args[0]
	} else {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		plain = strings.TrimRight(string(b), "\r\n")
	}
	if plain == "" {
		// cliInputError, а не fmt.Errorf (fix round 1, minor 4): "пустой
		// пароль" — обычная ошибка ВВОДА и обязана классифицироваться так
		// же, как остальные, для exitCodeFor в main().
		return cliInputError{"пустой пароль"}
	}
	h, err := web.HashPassword(plain)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, h)
	return nil
}
