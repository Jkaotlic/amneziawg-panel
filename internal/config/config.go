// Package config загружает и валидирует config.yaml панели.
//
// Валидация намеренно строгая: запуск с невалидным конфигом — отказ старта
// с внятной ошибкой, а не тихая работа на умолчаниях (раздел 11 спеки).
package config

import (
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen     string      `yaml:"listen"`
	Auth       Auth        `yaml:"auth"`
	Interfaces []Interface `yaml:"interfaces"`

	// Легаси-форма одиночного интерфейса. Разбирается только затем, чтобы
	// свернуться в Interfaces (см. migrateLegacy); после Load всегда nil.
	// Поля объявлены здесь, а не игнорируются, потому что dec.KnownFields(true)
	// иначе отверг бы существующий рабочий config.yaml на боевом хосте.
	LegacyAWG     *AWG     `yaml:"awg"`
	LegacyClient  *Client  `yaml:"client"`
	LegacyStorage *Storage `yaml:"storage"`
}

type Auth struct {
	User   string `yaml:"user"`
	Bcrypt string `yaml:"bcrypt"`
}

// AWG — легаси-секция awg: одноинтерфейсного конфига. Живёт только как тип
// поля Config.LegacyAWG; новый формат описывает то же самое через Interface.
type AWG struct {
	Interface string `yaml:"interface"`
	Config    string `yaml:"config"`
	BinDir    string `yaml:"bin_dir"`
}

// Interface — один управляемый интерфейс AWG со всем, что к нему относится.
// Самодостаточен намеренно: два интерфейса не делят ни файла, ни каталога,
// иначе Reconcile одного вычищал бы пиров другого (раздел 5.1 спеки).
type Interface struct {
	ID            string  `yaml:"id"`
	Title         string  `yaml:"title"`
	Interface     string  `yaml:"interface"`
	Config        string  `yaml:"config"`
	BinDir        string  `yaml:"bin_dir"`
	InterfaceEdit bool    `yaml:"interface_edit"`
	Client        Client  `yaml:"client"`
	Storage       Storage `yaml:"storage"`
}

type Client struct {
	Endpoint            string `yaml:"endpoint"`
	AllowedIPs          string `yaml:"allowed_ips"`
	PersistentKeepalive string `yaml:"persistent_keepalive"`
	DNS                 string `yaml:"dns"`
	Jc                  int    `yaml:"jc"`
	Jmin                int    `yaml:"jmin"`
	Jmax                int    `yaml:"jmax"`
}

type Storage struct {
	State   string `yaml:"state"`
	Backups string `yaml:"backups"`
	Keys    string `yaml:"keys"`
	// ClientConfigs — легаси-каталог выданных .conf. Нужен только миграции
	// приватных ключей (задача 4); когда каталог опустел, поле можно убрать.
	ClientConfigs string `yaml:"client_configs"`
}

// StateDir — каталог, в котором живёт состояние интерфейса. defaults.json и
// pending-interface.json своих полей в конфиге не имеют и лежат здесь: два
// файла состояния одного интерфейса, разъехавшиеся по разным каталогам из-за
// опечатки, дали бы панель, которая при старте ищет pending не там, где его
// оставила (раздел 5.5 спеки).
//
// Строится через path, а не filepath: значение — путь на целевом Linux-хосте,
// а не на машине, где выполняется код (панель разрабатывается на Windows).
func (i Interface) StateDir() string { return path.Dir(i.State()) }

func (i Interface) State() string { return i.Storage.State }

func (i Interface) DefaultsPath() string {
	return path.Join(i.StateDir(), "defaults.json")
}

func (i Interface) PendingPath() string {
	return path.Join(i.StateDir(), "pending-interface.json")
}

// interfaceIDPattern — id интерфейса становится частью пути на диске и
// сегментом URL, поэтому разрешены только slug-символы.
var interfaceIDPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Default возвращает конфиг с умолчаниями раздела 11 спеки: один интерфейс —
// боевой awg3 в его исходной, ещё не мультиинтерфейсной раскладке путей.
// Используется тестами как готовый валидный конфиг; поля auth заполняются
// отдельно.
func Default() *Config {
	return &Config{
		Listen: "10.0.0.1:8081",
		Auth:   Auth{User: "admin"},
		Interfaces: []Interface{
			{
				ID:        "awg3",
				Title:     "awg3",
				Interface: "awg3",
				Config:    "/etc/amnezia/amneziawg/awg3.conf",
				BinDir:    "/opt/awg3/bin",
				Client: Client{
					Endpoint:            "203.0.113.10:51820",
					AllowedIPs:          "0.0.0.0/0",
					PersistentKeepalive: "22-30",
				},
				Storage: Storage{
					State:         "/var/lib/awg3panel/peers.json",
					Backups:       "/var/lib/awg3panel/backups",
					Keys:          "/var/lib/awg3panel/keys",
					ClientConfigs: "/var/lib/awg3panel/clients",
				},
			},
		},
	}
}

func Load(configPath string) (*Config, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("чтение конфига %s: %w", configPath, err)
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("разбор конфига %s: %w", configPath, err)
	}
	if err := c.migrateLegacy(); err != nil {
		return nil, fmt.Errorf("конфиг %s: %w", configPath, err)
	}
	// Заголовок по умолчанию — id: иначе вкладка интерфейса в UI была бы
	// пустой. Присваивается здесь, а не в Validate(), потому что Validate
	// вызывается и на уже полностью готовых структурах (см. тесты валидации),
	// где молчаливая мутация Title была бы неожиданной.
	for i := range c.Interfaces {
		if c.Interfaces[i].Title == "" {
			c.Interfaces[i].Title = c.Interfaces[i].ID
		}
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("конфиг %s: %w", configPath, err)
	}
	return &c, nil
}

// migrateLegacy сворачивает старую одноинтерфейсную форму конфига в список
// из одного элемента. Смешение форм — ошибка, а не приоритет одной над
// другой: оператор, у которого в файле есть обе, не знает, какая действует,
// и молчаливый выбор панели сделает его правым ровно в половине случаев.
func (c *Config) migrateLegacy() error {
	hasLegacy := c.LegacyAWG != nil || c.LegacyClient != nil || c.LegacyStorage != nil
	if !hasLegacy {
		return nil
	}
	if len(c.Interfaces) > 0 {
		return fmt.Errorf("в конфиге есть и interfaces:, и старые секции awg:/client:/storage: — " +
			"оставьте одну форму")
	}
	if c.LegacyAWG == nil || c.LegacyStorage == nil {
		return fmt.Errorf("старая форма конфига неполна: нужны секции awg: и storage:")
	}
	st := *c.LegacyStorage
	if st.Keys == "" && st.State != "" {
		// Путь на целевом Linux-хосте — считается через path, а не filepath
		// (см. комментарий у StateDir).
		st.Keys = path.Join(path.Dir(st.State), "keys")
	}
	var cl Client
	if c.LegacyClient != nil {
		cl = *c.LegacyClient
	}
	c.Interfaces = []Interface{{
		ID: "default", Title: c.LegacyAWG.Interface,
		Interface: c.LegacyAWG.Interface, Config: c.LegacyAWG.Config,
		BinDir: c.LegacyAWG.BinDir, InterfaceEdit: false,
		Client: cl, Storage: st,
	}}
	c.LegacyAWG, c.LegacyClient, c.LegacyStorage = nil, nil, nil
	return nil
}

func (c *Config) Validate() error {
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return fmt.Errorf("listen %q: не в формате адрес:порт: %w", c.Listen, err)
	}
	if port == "" {
		return fmt.Errorf("listen %q: пустой порт", c.Listen)
	}
	// Панель не выставляется наружу ни при каких условиях (раздел 10 спеки):
	// слушать разрешено только конкретный адрес туннеля.
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return fmt.Errorf("listen %q: слушать на всех адресах запрещено, укажите адрес туннеля", c.Listen)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("listen %q: %q не IP-адрес", c.Listen, host)
	}
	if c.Auth.User == "" {
		return fmt.Errorf("auth.user пуст")
	}
	if !strings.HasPrefix(c.Auth.Bcrypt, "$2") {
		return fmt.Errorf("auth.bcrypt пуст или не bcrypt-хеш")
	}

	if len(c.Interfaces) == 0 {
		return fmt.Errorf("не задан ни один интерфейс")
	}

	// Каждый интерфейс самодостаточен (раздел 5.1 спеки): id и управляемое
	// устройство не повторяются, а config/state/backups/keys (и производный
	// от state каталог — см. ниже) не пересекаются между интерфейсами —
	// общий файл означал бы, что Reconcile одного вычищает пиров другого.
	seenID := map[string]bool{}
	seenIface := map[string]string{}
	seenPath := map[string]string{}
	for _, iface := range c.Interfaces {
		if !interfaceIDPattern.MatchString(iface.ID) {
			return fmt.Errorf("interfaces: id %q не slug: разрешены строчные латинские буквы, цифры и дефис, 1-32 символа", iface.ID)
		}
		if seenID[iface.ID] {
			return fmt.Errorf("interfaces: id %q повторяется", iface.ID)
		}
		seenID[iface.ID] = true

		if iface.Interface == "" {
			return fmt.Errorf("interfaces[%s].interface пуст", iface.ID)
		}
		if owner, ok := seenIface[iface.Interface]; ok {
			return fmt.Errorf("interfaces[%s]: устройство %q уже управляется интерфейсом %q — два интерфейса не могут делить одно устройство",
				iface.ID, iface.Interface, owner)
		}
		seenIface[iface.Interface] = iface.ID

		if iface.BinDir == "" {
			return fmt.Errorf("interfaces[%s].bin_dir пуст", iface.ID)
		}
		if !filepath.IsAbs(iface.BinDir) && !strings.HasPrefix(iface.BinDir, "/") {
			return fmt.Errorf("interfaces[%s].bin_dir = %q: требуется абсолютный путь", iface.ID, iface.BinDir)
		}

		for _, field := range []struct{ name, value string }{
			{"config", iface.Config},
			{"storage.state", iface.Storage.State},
			{"storage.backups", iface.Storage.Backups},
			{"storage.keys", iface.Storage.Keys},
			// Не буквальное поле конфига, а производный каталог
			// (path.Dir от storage.state, см. Interface.StateDir) — в нём
			// лежат defaults.json и pending-interface.json. Без этой строки
			// (находка финального ревью, I3) два интерфейса, чьи state
			// проходят проверку выше как РАЗНЫЕ строки (например,
			// "/var/lib/awg3panel/peers.json" и
			// "/var/lib/awg3panel/peers-awg31.json" — разные имена файлов),
			// но лежат В ОДНОМ каталоге, проходили валидацию, хотя
			// DefaultsPath()/PendingPath() у них совпадали: правка умолчаний
			// одного интерфейса молча меняла умолчания другого.
			{"storage.state (каталог defaults.json/pending-interface.json)", iface.StateDir()},
		} {
			if field.value == "" {
				return fmt.Errorf("interfaces[%s].%s пуст", iface.ID, field.name)
			}
			if !filepath.IsAbs(field.value) && !strings.HasPrefix(field.value, "/") {
				return fmt.Errorf("interfaces[%s].%s = %q: требуется абсолютный путь", iface.ID, field.name, field.value)
			}
			if owner, ok := seenPath[field.value]; ok {
				return fmt.Errorf("interfaces[%s].%s = %q: путь уже используется интерфейсом %q",
					iface.ID, field.name, field.value, owner)
			}
			seenPath[field.value] = iface.ID
		}

		if _, _, err := net.SplitHostPort(iface.Client.Endpoint); err != nil {
			return fmt.Errorf("interfaces[%s].client.endpoint %q: не в формате адрес:порт: %w", iface.ID, iface.Client.Endpoint, err)
		}
		if iface.Client.AllowedIPs == "" {
			return fmt.Errorf("interfaces[%s].client.allowed_ips пуст", iface.ID)
		}
	}

	return nil
}
