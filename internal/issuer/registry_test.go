package issuer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// twoIfaceConfig строит config.Config с двумя интерфейсами: каждый со
// своими путями внутри t.TempDir() (раздел 5.1 спеки — интерфейсы не делят
// ни файла, ни каталога, иначе Reconcile одного вычищал бы пиров другого).
// InterfaceEdit различается между ними намеренно: TestRegistryOrderAndLookup
// проверяет, что Registry.Metas() довозит этот флаг до UI как есть, а не
// теряет его на константе.
func twoIfaceConfig(t *testing.T) *config.Config {
	t.Helper()
	root := t.TempDir()
	mk := func(id, title string, edit bool) config.Interface {
		dir := filepath.Join(root, id)
		confPath := filepath.Join(dir, "awg3.conf")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(confPath, []byte(serverConf), 0o600); err != nil {
			t.Fatal(err)
		}
		return config.Interface{
			ID: id, Title: title, Interface: id, Config: confPath,
			BinDir: dir, InterfaceEdit: edit,
			Client:  config.Client{Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0"},
			Storage: slashStorage(dir),
		}
	}
	cfg := config.Default()
	cfg.Interfaces = []config.Interface{
		mk("awg3", "Первый", false),
		mk("awg4", "Второй", true),
	}
	return cfg
}

func TestRegistryOrderAndLookup(t *testing.T) {
	cfg := twoIfaceConfig(t)
	reg := issuer.NewRegistry(cfg, func(binDir string) runtime.Runner { return runtime.NewFake(serverConf) })
	metas := reg.Metas()
	if len(metas) != 2 || metas[0].ID != cfg.Interfaces[0].ID {
		t.Fatalf("порядок интерфейсов обязан совпадать с конфигом: %+v", metas)
	}
	if _, ok := reg.Lister("нет-такого"); ok {
		t.Fatal("неизвестный интерфейс не должен находиться")
	}
	if reg.Default() == nil {
		t.Fatal("Default обязан вернуть первый интерфейс")
	}
	if metas[1].InterfaceEdit != cfg.Interfaces[1].InterfaceEdit {
		t.Fatal("флаг interface_edit обязан доезжать до UI как есть")
	}
}

// TestRegistryListerAndMutatorReturnSameService — Lister и Mutator не два
// независимых объекта на интерфейс: web зависит от узких интерфейсов, а в
// read-only сборке Mutator не вызывается ниоткуда вовсе, но обязан отдавать
// ТОТ ЖЕ *Service, что и Lister, — иначе мутация через один был бы не виден
// через другой. All() обязан отдавать все сервисы в порядке конфига.
func TestRegistryListerAndMutatorReturnSameService(t *testing.T) {
	cfg := twoIfaceConfig(t)
	reg := issuer.NewRegistry(cfg, func(binDir string) runtime.Runner { return runtime.NewFake(serverConf) })
	l, ok := reg.Lister(cfg.Interfaces[0].ID)
	if !ok {
		t.Fatal("Lister не нашёл известный интерфейс")
	}
	m, ok := reg.Mutator(cfg.Interfaces[0].ID)
	if !ok {
		t.Fatal("Mutator не нашёл известный интерфейс")
	}
	if l != m {
		t.Error("Lister и Mutator обязаны возвращать один и тот же *Service")
	}
	all := reg.All()
	if len(all) != 2 || all[0] != l {
		t.Errorf("All() обязан вернуть все сервисы в порядке конфига: %+v", all)
	}
}
