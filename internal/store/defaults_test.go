package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

func TestLoadDefaultsSeedsOnFirstRun(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defaults.json")
	seed := store.Defaults{Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Keepalive: "22-30"}
	d, created, err := store.LoadDefaults(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("первый вызов обязан сообщить, что файла не было")
	}
	if d.Endpoint != seed.Endpoint {
		t.Fatalf("Endpoint = %q, ожидался сид %q", d.Endpoint, seed.Endpoint)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("LoadDefaults не должна писать на диск сама: запись — дело вызывающего")
	}

	d.DNS = "10.0.0.1"
	if err := d.Save(path); err != nil {
		t.Fatal(err)
	}
	again, created, err := store.LoadDefaults(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if created {
		t.Fatal("файл уже есть — created обязан быть false")
	}
	if again.DNS != "10.0.0.1" {
		t.Fatalf("DNS = %q: сид не должен перебивать сохранённое значение", again.DNS)
	}
}

// TestLoadDefaultsSeedDoesNotShareExtraMap — находка ревью задачи 5:
// на ветке "файла ещё нет" LoadDefaults копирует seed СТРУКТУРОЙ
// (d := seed), а Defaults.Extra — карта, ссылочный тип. Копирование
// структуры не копирует саму карту: d.Extra и seed.Extra остаются
// указывающими на ОДНУ И ТУ ЖЕ карту, и правка карты у одного вызывающего
// LoadDefaults была бы видна другому ещё ДО какой-либо записи на диск —
// без всякой конкуренции, просто по факту общего указателя.
//
// Ветка "файл существует" (json.Unmarshal в свежую var d Defaults) от этого
// бага не страдает: декодер JSON всегда аллоцирует новую карту. Поэтому сид
// здесь обязан нести НЕПУСТУЮ Extra, а путь — заведомо не существовать:
// это единственная комбинация, которая реально проходит через уязвимую
// ветку и может отличить починку от её отсутствия.
func TestLoadDefaultsSeedDoesNotShareExtraMap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defaults.json")
	seed := store.Defaults{
		Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0",
		Extra: map[string]string{"I1": "исходное"},
	}
	d, created, err := store.LoadDefaults(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if !created {
		t.Fatal("файла нет — created обязан быть true")
	}

	d.Extra["I1"] = "испорчено-снаружи"

	if seed.Extra["I1"] != "исходное" {
		t.Errorf("LoadDefaults отдала карту Extra, общую с сидом вызывающего: seed.Extra[%q] = %q, "+
			"а обязано было остаться %q", "I1", seed.Extra["I1"], "исходное")
	}
}
