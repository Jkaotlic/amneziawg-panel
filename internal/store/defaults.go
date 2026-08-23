package store

import (
	"encoding/json"
	"fmt"
	"os"
)

// Defaults — умолчания клиентских параметров одного интерфейса. Живут в
// /var/lib, а не в config.yaml: config.yaml — файл развёртывания, его правит
// install.sh и root, а сервис, переписывающий собственный файл развёртывания,
// теряет комментарии YAML и конфликтует с идемпотентностью установщика
// (раздел 5.6 спеки).
type Defaults struct {
	Version    int               `json:"version"`
	Endpoint   string            `json:"endpoint"`
	AllowedIPs string            `json:"allowed_ips"`
	Keepalive  string            `json:"keepalive"`
	DNS        string            `json:"dns"`
	Jc         int               `json:"jc"`
	Jmin       int               `json:"jmin"`
	Jmax       int               `json:"jmax"`
	Extra      map[string]string `json:"extra,omitempty"`
}

const DefaultsVersion = 1

// LoadDefaults читает defaults.json. Если файла нет — возвращает копию сида
// и created=true; записывать её на диск обязан вызывающий, чтобы сбой записи
// не ронял путь чтения.
func LoadDefaults(path string, seed Defaults) (*Defaults, bool, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		d := seed
		d.Version = DefaultsVersion
		// Extra — ссылочный тип: d := seed копирует структуру, но не саму
		// карту, и без явного клонирования d.Extra и seed.Extra указывали бы
		// на одну и ту же карту — правка одной была бы видна в другой ещё до
		// какой-либо записи на диск (находка ревью задачи 5).
		d.Extra = cloneExtra(seed.Extra)
		return &d, true, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("чтение %s: %w", path, err)
	}
	var d Defaults
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, false, fmt.Errorf("разбор %s: %w", path, err)
	}
	if d.Version == 0 {
		d.Version = DefaultsVersion
	}
	if d.Version > DefaultsVersion {
		return nil, false, fmt.Errorf("%s: версия формата %d новее панели (%d)", path, d.Version, DefaultsVersion)
	}
	return &d, false, nil
}

// Save пишет умолчания атомарно — см. writeAtomicJSON в store.go.
func (d *Defaults) Save(path string) error {
	d.Version = DefaultsVersion
	return writeAtomicJSON(path, d)
}

// cloneExtra возвращает независимую копию карты дополнительных client-side
// полей — см. комментарий в ветке "файла ещё нет" функции LoadDefaults.
func cloneExtra(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
