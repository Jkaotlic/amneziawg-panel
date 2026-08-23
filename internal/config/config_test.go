package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
)

func sampleYAML(listen string) string {
	return `listen: "` + listen + `"
auth:
  user: "admin"
  bcrypt: "$2a$12$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR"
awg:
  interface: "awg3"
  config: "/etc/amnezia/amneziawg/awg3.conf"
  bin_dir: "/opt/awg3/bin"
client:
  endpoint: "203.0.113.10:51820"
  allowed_ips: "0.0.0.0/0"
  persistent_keepalive: "22-30"
  dns: ""
  jc: 0
storage:
  state: "/var/lib/awg3panel/peers.json"
  backups: "/var/lib/awg3panel/backups"
  client_configs: "/var/lib/awg3panel/clients"
`
}

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadValid грузит конфиг легаси-формы (awg:/client:/storage: на
// верхнем уровне) — миграция в Interfaces проверяется здесь заодно с
// разбором, отдельно она покрыта TestLoadMigratesLegacySingleInterface.
func TestLoadValid(t *testing.T) {
	cfg, err := config.Load(write(t, sampleYAML("10.0.0.1:8081")))
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if cfg.Listen != "10.0.0.1:8081" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if len(cfg.Interfaces) != 1 {
		t.Fatalf("интерфейсов %d, ожидался 1", len(cfg.Interfaces))
	}
	if cfg.Interfaces[0].Interface != "awg3" {
		t.Errorf("Interfaces[0].Interface = %q", cfg.Interfaces[0].Interface)
	}
	if cfg.Interfaces[0].Client.PersistentKeepalive != "22-30" {
		t.Errorf("PersistentKeepalive = %q", cfg.Interfaces[0].Client.PersistentKeepalive)
	}
}

func TestLoadRejectsWildcardBind(t *testing.T) {
	for _, listen := range []string{"0.0.0.0:8081", ":8081", "[::]:8081"} {
		if _, err := config.Load(write(t, sampleYAML(listen))); err == nil {
			t.Errorf("listen %q: ожидалась ошибка, получено nil", listen)
		} else if !strings.Contains(err.Error(), "listen") {
			t.Errorf("listen %q: ошибка без упоминания listen: %v", listen, err)
		}
	}
}

func TestLoadRejectsMissingBcrypt(t *testing.T) {
	body := strings.Replace(sampleYAML("10.0.0.1:8081"),
		`bcrypt: "$2a$12$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR"`,
		`bcrypt: ""`, 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("ожидалась ошибка на пустой bcrypt")
	}
}

func TestLoadRejectsRelativePaths(t *testing.T) {
	body := strings.Replace(sampleYAML("10.0.0.1:8081"),
		`config: "/etc/amnezia/amneziawg/awg3.conf"`,
		`config: "awg3.conf"`, 1)
	if _, err := config.Load(write(t, body)); err == nil {
		t.Fatal("ожидалась ошибка на относительный путь до конфига AWG")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := config.Load(filepath.Join(t.TempDir(), "нет.yaml")); err == nil {
		t.Fatal("ожидалась ошибка на отсутствующий файл")
	}
}

func TestLoadInterfacesList(t *testing.T) {
	path := write(t, `
listen: "10.0.0.1:8081"
auth: { user: "admin", bcrypt: "$2a$12$xxxxxxxxxxxxxxxxxxxxxx" }
interfaces:
  - id: awg3
    title: "awg3 (боевой)"
    interface: awg3
    config: /etc/amnezia/amneziawg/awg3.conf
    bin_dir: /opt/awg3/bin
    interface_edit: false
    client: { endpoint: "1.2.3.4:51820", allowed_ips: "0.0.0.0/0" }
    storage:
      state: /var/lib/awg3panel/awg3/peers.json
      backups: /var/lib/awg3panel/awg3/backups
      keys: /var/lib/awg3panel/awg3/keys
  - id: awg31
    interface: awg3.1
    config: /etc/amnezia/amneziawg/awg3.1.conf
    bin_dir: /opt/awg3.1/bin
    interface_edit: true
    client: { endpoint: "1.2.3.4:51773", allowed_ips: "0.0.0.0/0" }
    storage:
      state: /var/lib/awg3panel/awg31/peers.json
      backups: /var/lib/awg3panel/awg31/backups
      keys: /var/lib/awg3panel/awg31/keys
`)
	c, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Interfaces) != 2 {
		t.Fatalf("интерфейсов %d, ожидалось 2", len(c.Interfaces))
	}
	if c.Interfaces[0].ID != "awg3" || c.Interfaces[1].ID != "awg31" {
		t.Fatalf("порядок интерфейсов не сохранён: %q, %q", c.Interfaces[0].ID, c.Interfaces[1].ID)
	}
	if c.Interfaces[1].InterfaceEdit != true {
		t.Fatal("interface_edit у awg31 должен быть true")
	}
	// Заголовок не задан — подставляется id, чтобы UI не показывал пустую вкладку.
	if c.Interfaces[1].Title != "awg31" {
		t.Fatalf("Title = %q, ожидалось %q", c.Interfaces[1].Title, "awg31")
	}
	// Пути состояния, которых нет в конфиге, выводятся из state.
	if got := c.Interfaces[0].DefaultsPath(); got != "/var/lib/awg3panel/awg3/defaults.json" {
		t.Fatalf("DefaultsPath = %q", got)
	}
	if got := c.Interfaces[0].PendingPath(); got != "/var/lib/awg3panel/awg3/pending-interface.json" {
		t.Fatalf("PendingPath = %q", got)
	}
}

// TestDefault сверяет config.Default() с литералами раздела 11 спеки.
// Тест фиксирует значения буквально, чтобы правка, случайно меняющая
// один из умолчательных литералов, ломала сборку тестов, а не проходила
// незамеченной.
func TestDefault(t *testing.T) {
	d := config.Default()

	if d.Listen != "10.0.0.1:8081" {
		t.Errorf("Listen = %q, хотим %q", d.Listen, "10.0.0.1:8081")
	}
	if d.Auth.User != "admin" {
		t.Errorf("Auth.User = %q, хотим %q", d.Auth.User, "admin")
	}
	if len(d.Interfaces) != 1 {
		t.Fatalf("интерфейсов %d, хотим 1", len(d.Interfaces))
	}
	iface := d.Interfaces[0]
	if iface.ID != "awg3" {
		t.Errorf("Interfaces[0].ID = %q, хотим %q", iface.ID, "awg3")
	}
	if iface.Interface != "awg3" {
		t.Errorf("Interfaces[0].Interface = %q, хотим %q", iface.Interface, "awg3")
	}
	if iface.Config != "/etc/amnezia/amneziawg/awg3.conf" {
		t.Errorf("Interfaces[0].Config = %q, хотим %q", iface.Config, "/etc/amnezia/amneziawg/awg3.conf")
	}
	if iface.BinDir != "/opt/awg3/bin" {
		t.Errorf("Interfaces[0].BinDir = %q, хотим %q", iface.BinDir, "/opt/awg3/bin")
	}
	if iface.Client.Endpoint != "203.0.113.10:51820" {
		t.Errorf("Client.Endpoint = %q, хотим %q", iface.Client.Endpoint, "203.0.113.10:51820")
	}
	if iface.Client.AllowedIPs != "0.0.0.0/0" {
		t.Errorf("Client.AllowedIPs = %q, хотим %q", iface.Client.AllowedIPs, "0.0.0.0/0")
	}
	if iface.Client.PersistentKeepalive != "22-30" {
		t.Errorf("Client.PersistentKeepalive = %q, хотим %q", iface.Client.PersistentKeepalive, "22-30")
	}
	// DNS сознательно пуст: свой резолвер конфликтует с AdGuard Home
	// в домашней сети. Это НЕ недоделка — не заполнять реальным DNS.
	if iface.Client.DNS != "" {
		t.Errorf("Client.DNS = %q, хотим пустую строку (свой DNS конфликтует с AdGuard Home)", iface.Client.DNS)
	}
	// Jc = 0 в умолчаниях сознательно (jitter отключён по умолчанию,
	// включается явно при необходимости) — утверждаем нулевое значение явно.
	if iface.Client.Jc != 0 {
		t.Errorf("Client.Jc = %d, хотим 0 (по умолчанию джиттер выключен)", iface.Client.Jc)
	}
	if iface.Storage.State != "/var/lib/awg3panel/peers.json" {
		t.Errorf("Storage.State = %q, хотим %q", iface.Storage.State, "/var/lib/awg3panel/peers.json")
	}
	if iface.Storage.Backups != "/var/lib/awg3panel/backups" {
		t.Errorf("Storage.Backups = %q, хотим %q", iface.Storage.Backups, "/var/lib/awg3panel/backups")
	}
	if iface.Storage.Keys != "/var/lib/awg3panel/keys" {
		t.Errorf("Storage.Keys = %q, хотим %q", iface.Storage.Keys, "/var/lib/awg3panel/keys")
	}
	if iface.Storage.ClientConfigs != "/var/lib/awg3panel/clients" {
		t.Errorf("Storage.ClientConfigs = %q, хотим %q", iface.Storage.ClientConfigs, "/var/lib/awg3panel/clients")
	}

	// Умолчания обязаны проходить Validate() после заполнения auth.bcrypt —
	// ловит рассогласование между Default() и правилами валидации.
	d.Auth.Bcrypt = "$2a$12$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR"
	if err := d.Validate(); err != nil {
		t.Errorf("Default() с заполненным bcrypt не проходит Validate(): %v", err)
	}
}

func TestLoadMigratesLegacySingleInterface(t *testing.T) {
	path := write(t, `
listen: "10.0.0.1:8081"
auth: { user: "admin", bcrypt: "$2a$12$xxxxxxxxxxxxxxxxxxxxxx" }
awg:
  interface: "awg3"
  config: "/etc/amnezia/amneziawg/awg3.conf"
  bin_dir: "/opt/awg3/bin"
client:
  endpoint: "1.2.3.4:51820"
  allowed_ips: "0.0.0.0/0"
  persistent_keepalive: "22-30"
storage:
  state: "/var/lib/awg3panel/peers.json"
  backups: "/var/lib/awg3panel/backups"
  client_configs: "/var/lib/awg3panel/clients"
`)
	c, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Interfaces) != 1 {
		t.Fatalf("интерфейсов %d, ожидался 1", len(c.Interfaces))
	}
	got := c.Interfaces[0]
	if got.ID != "default" || got.Interface != "awg3" {
		t.Fatalf("ID=%q Interface=%q", got.ID, got.Interface)
	}
	if got.InterfaceEdit {
		t.Fatal("легаси-конфиг обязан получить interface_edit=false")
	}
	if got.Storage.ClientConfigs != "/var/lib/awg3panel/clients" {
		t.Fatalf("легаси client_configs потерян: %q", got.Storage.ClientConfigs)
	}
	// keys в старом конфиге нет — выводится рядом с peers.json. Проверяем
	// обычной строкой, а не filepath.FromSlash: путь целевого Linux-хоста
	// строится через path, а не через filepath хостовой ОС (см. Interface.StateDir).
	if got.Storage.Keys != "/var/lib/awg3panel/keys" {
		t.Fatalf("Storage.Keys = %q", got.Storage.Keys)
	}
	if c.LegacyAWG != nil || c.LegacyClient != nil || c.LegacyStorage != nil {
		t.Fatal("легаси-поля обязаны быть очищены после миграции")
	}
}

// TestLoadRejectsMixedForms задаёт ПОЛНУЮ легаси-форму (awg:+client:+storage:
// со всеми обязательными полями) рядом с interfaces:, а не обрывок. Если бы
// легаси-секции были неполны, отказ пришёл бы от проверки полноты в
// migrateLegacy (LegacyAWG == nil || LegacyStorage == nil), и тест остался бы
// зелёным даже без проверки смешения форм — ложно-позитивная защита. Полная
// форма гарантирует, что единственная причина отказа — само смешение.
func TestLoadRejectsMixedForms(t *testing.T) {
	path := write(t, `
listen: "10.0.0.1:8081"
auth: { user: "admin", bcrypt: "$2a$12$xxxxxxxxxxxxxxxxxxxxxx" }
awg: { interface: "awg3", config: "/etc/a.conf", bin_dir: "/opt/awg3/bin" }
client: { endpoint: "1.2.3.4:51820", allowed_ips: "0.0.0.0/0" }
storage: { state: /var/lib/awg3panel/peers.json, backups: /var/lib/awg3panel/backups, keys: /var/lib/awg3panel/keys }
interfaces:
  - id: awg31
    interface: awg3.1
    config: /etc/b.conf
    bin_dir: /opt/awg3.1/bin
    client: { endpoint: "1.2.3.4:51773", allowed_ips: "0.0.0.0/0" }
    storage: { state: /var/lib/x/peers.json, backups: /var/lib/x/backups, keys: /var/lib/x/keys }
`)
	if _, err := config.Load(path); err == nil {
		t.Fatal("смешение старой и новой формы обязано быть ошибкой старта")
	}
}

func TestValidateRejectsDuplicates(t *testing.T) {
	base := func(mod func(*config.Config)) *config.Config {
		c := &config.Config{
			Listen: "10.0.0.1:8081",
			Auth:   config.Auth{User: "admin", Bcrypt: "$2a$12$x"},
			Interfaces: []config.Interface{
				{ID: "a", Interface: "awg3", Config: "/etc/a.conf", BinDir: "/opt/a",
					Client:  config.Client{Endpoint: "1.2.3.4:1", AllowedIPs: "0.0.0.0/0"},
					Storage: config.Storage{State: "/v/a/p.json", Backups: "/v/a/b", Keys: "/v/a/k"}},
				{ID: "b", Interface: "awg3.1", Config: "/etc/b.conf", BinDir: "/opt/b",
					Client:  config.Client{Endpoint: "1.2.3.4:2", AllowedIPs: "0.0.0.0/0"},
					Storage: config.Storage{State: "/v/b/p.json", Backups: "/v/b/b", Keys: "/v/b/k"}},
			},
		}
		mod(c)
		return c
	}
	cases := map[string]func(*config.Config){
		"одинаковый id":         func(c *config.Config) { c.Interfaces[1].ID = "a" },
		"одно устройство":       func(c *config.Config) { c.Interfaces[1].Interface = "awg3" },
		"общий peers.json":      func(c *config.Config) { c.Interfaces[1].Storage.State = "/v/a/p.json" },
		"общий каталог бэкапов": func(c *config.Config) { c.Interfaces[1].Storage.Backups = "/v/a/b" },
		"общий каталог ключей":  func(c *config.Config) { c.Interfaces[1].Storage.Keys = "/v/a/k" },
		"общий конфиг AWG":      func(c *config.Config) { c.Interfaces[1].Config = "/etc/a.conf" },
		"пустой список":         func(c *config.Config) { c.Interfaces = nil },
		"id не slug":            func(c *config.Config) { c.Interfaces[1].ID = "AWG 3.1" },
		// Находка финального ревью I3: state.json у интерфейсов РАЗНЫЙ
		// ("/v/a/p.json" vs "/v/a/other.json"), поэтому проверка storage.state
		// её не ловит, — но каталог один и тот же ("/v/a"), а именно от
		// каталога (path.Dir(state)) считаются DefaultsPath()/PendingPath().
		"общий каталог state (иначе называется файл)": func(c *config.Config) {
			c.Interfaces[1].Storage.State = "/v/a/other.json"
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			if err := base(mod).Validate(); err == nil {
				t.Fatalf("%s: ожидалась ошибка валидации", name)
			}
		})
	}
}

// TestValidateRejectsSharedDefaultsDirectory — находка финального ревью I3,
// воспроизведённая буквально сценарием из брифа: легаси-раскладка кладёт
// peers.json прямо в /var/lib/awg3panel, а второй интерфейс дописывают рядом
// с ДРУГИМ именем файла состояния (например, peers-awg31.json — по
// привычке, не подозревая о проблеме). Storage.State у них при этом разные
// строки, и проверка пересечений путей (только config/state/backups/keys) их
// не ловит, — но DefaultsPath()/PendingPath() считаются от path.Dir(state)
// (см. Interface.StateDir), а каталог здесь ОДИН И ТОТ ЖЕ:
// /var/lib/awg3panel. Правка умолчаний одного интерфейса молча меняла бы
// умолчания другого — ровно то, что README прямо обещает как невозможное
// ("Несколько интерфейсов": "правка одного не может задеть другой ни при
// каких обстоятельствах").
func TestValidateRejectsSharedDefaultsDirectory(t *testing.T) {
	c := &config.Config{
		Listen: "10.0.0.1:8081",
		Auth:   config.Auth{User: "admin", Bcrypt: "$2a$12$x"},
		Interfaces: []config.Interface{
			{ID: "awg3", Interface: "awg3", Config: "/etc/amnezia/amneziawg/awg3.conf", BinDir: "/opt/awg3/bin",
				Client: config.Client{Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0"},
				Storage: config.Storage{
					State:   "/var/lib/awg3panel/peers.json",
					Backups: "/var/lib/awg3panel/backups",
					Keys:    "/var/lib/awg3panel/keys",
				}},
			{ID: "awg31", Interface: "awg3.1", Config: "/etc/amnezia/amneziawg/awg3.1.conf", BinDir: "/opt/awg3.1/bin",
				Client: config.Client{Endpoint: "1.2.3.4:51773", AllowedIPs: "0.0.0.0/0"},
				Storage: config.Storage{
					// Другое ИМЯ файла — буквальное сравнение storage.state эту
					// пару пропускает, хотя каталог общий.
					State:   "/var/lib/awg3panel/peers-awg31.json",
					Backups: "/var/lib/awg3panel/backups-awg31",
					Keys:    "/var/lib/awg3panel/keys-awg31",
				}},
		},
	}
	// Сверка предпосылки: если DefaultsPath() тут вдруг не совпадёт (правка
	// StateDir/DefaultsPath где-то ещё изменила их поведение), тест обязан
	// сказать об этом прямо, а не молча проверить нерелевантный сценарий.
	if got0, got1 := c.Interfaces[0].DefaultsPath(), c.Interfaces[1].DefaultsPath(); got0 != got1 {
		t.Fatalf("подготовка теста сломана: DefaultsPath у интерфейсов обязаны совпасть, чтобы "+
			"тест проверял находку I3: %q vs %q", got0, got1)
	}
	if err := c.Validate(); err == nil {
		t.Fatal("два интерфейса с общим каталогом defaults.json/pending-interface.json обязаны " +
			"быть отвергнуты валидацией — иначе правка умолчаний одного интерфейса молча меняет " +
			"умолчания другого")
	}
}
