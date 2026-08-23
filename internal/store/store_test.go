package store_test

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

func TestPeerIDIsStableAndURLSafe(t *testing.T) {
	// Сырой base64-ключ содержит / и + и в пути URL непригоден.
	pub := "bWUvcHVibGljK2tleT0="
	id := store.PeerID(pub)
	if len(id) != 12 {
		t.Fatalf("длина id = %d, ожидалось 12", len(id))
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("id %q содержит небезопасный символ %q", id, r)
		}
	}
	if store.PeerID(pub) != id {
		t.Error("id не стабилен между вызовами")
	}
	if store.PeerID(pub+"x") == id {
		t.Error("разные ключи дали одинаковый id")
	}
}

func TestLoadMissingFileGivesEmptyState(t *testing.T) {
	st, err := store.Load(filepath.Join(t.TempDir(), "peers.json"))
	if err != nil {
		t.Fatalf("отсутствие файла — не ошибка: %v", err)
	}
	if st.Version != 1 || len(st.Peers) != 0 {
		t.Errorf("состояние = %+v, ожидалось пустое версии 1", st)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "peers.json")
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{
		ID: store.PeerID("k"), Name: "папа-телефон", PublicKey: "k",
		Address: "10.0.0.4/32", CreatedAt: "2026-08-01T12:00:00Z", Enabled: true,
	})
	// Отключённый пир с PSK — единственное место, где этот секрет вообще
	// существует: в awg3.conf блока [Peer] у него уже нет. Прежняя версия
	// теста утверждала «PSK включённого пира не должен сохраняться» на
	// фикстуре, где PresharedKey не задан вовсе, — тавтология, проходившая
	// при любом поведении Save/Load (находка Important 4 финального ревью).
	// Инвариант «у включённого пира PSK не хранится» принадлежит не Save, а
	// Reconcile, и проверяется в TestReconcileClearsPSKOfPeerPresentInConf;
	// здесь проверяется то, за что отвечает круг Save→Load: секрет обязан
	// пережить его без потерь.
	st.Upsert(store.Peer{
		ID: store.PeerID("off"), Name: "выключенный", PublicKey: "off",
		Address: "10.0.0.5/32", CreatedAt: "2026-08-01T12:00:00Z", Enabled: false,
		PresharedKey: "psk-vyklyuchennogo",
	})
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Peers) != 2 || got.Peers[0].Name != "папа-телефон" {
		t.Fatalf("после перечитывания: %+v", got.Peers)
	}
	if got.Peers[1].PresharedKey != "psk-vyklyuchennogo" {
		t.Errorf("PSK отключённого пира не пережил круг Save→Load: %q — "+
			"выданный клиенту конфиг стало бы нечем оживить", got.Peers[1].PresharedKey)
	}
	if got.Peers[1].Enabled {
		t.Error("флаг «выключен» не пережил круг Save→Load")
	}
}

func TestSaveIsAtomicAndPrivate(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("unix-права не проверяются на Windows")
	}
	p := filepath.Join(t.TempDir(), "peers.json")
	st := &store.State{Version: 1}
	if err := st.Save(p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("права = %v, ожидалось 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Errorf("в каталоге остались временные файлы: %d записей", len(entries))
	}
}

func TestUpsertReplacesByID(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: "a", Name: "первое"})
	st.Upsert(store.Peer{ID: "a", Name: "второе"})
	if len(st.Peers) != 1 || st.Peers[0].Name != "второе" {
		t.Fatalf("Upsert не заменил запись: %+v", st.Peers)
	}
}

func TestReconcileAdoptsUnknownPeers(t *testing.T) {
	st := &store.State{Version: 1}
	st.Reconcile([]string{"keyA", "keyB"}, func(pub string) string { return "10.0.0.2/32" })
	if len(st.Peers) != 2 {
		t.Fatalf("подхвачено %d пиров, ожидалось 2", len(st.Peers))
	}
	p, ok := st.ByPublicKey("keyA")
	if !ok {
		t.Fatal("пир keyA не подхвачен")
	}
	if want := "peer-" + store.PeerID("keyA"); p.Name != want {
		t.Errorf("имя по умолчанию = %q, ожидалось %q", p.Name, want)
	}
	if !p.Enabled {
		t.Error("подхваченный пир должен быть включён")
	}
}

func TestReconcileKeepsDisabledPeersAbsentFromConf(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: store.PeerID("off"), PublicKey: "off", Name: "выключенный",
		Address: "10.0.0.9/32", Enabled: false, PresharedKey: "psk"})
	st.Reconcile([]string{"keyA"}, func(string) string { return "10.0.0.2/32" })
	p, ok := st.ByPublicKey("off")
	if !ok {
		t.Fatal("отключённый пир пропал — его PSK и адрес потеряны навсегда")
	}
	if p.PresharedKey != "psk" {
		t.Error("PSK отключённого пира потерян")
	}
}

func TestReconcileDropsEnabledPeersRemovedOutside(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: store.PeerID("gone"), PublicKey: "gone", Enabled: true})
	st.Reconcile([]string{"keyA"}, func(string) string { return "10.0.0.2/32" })
	if _, ok := st.ByPublicKey("gone"); ok {
		t.Error("включённый пир, удалённый из конфига руками, должен исчезнуть из состояния")
	}
}

// TestReconcileKeepsEnabledPeerThatStillHoldsPSK — Important 2 финального
// ревью: окно потери PSK.
//
// Пара «Enabled=true И PresharedKey != ""» возникает ровно в одном месте —
// в Service.Disable между сохранением PSK (пир при этом ещё включён) и
// пометкой Enabled=false ПОСЛЕ успешного Apply. Если в этом промежутке
// падает запись состояния (диск полон, EIO) или умирает процесс, на диске
// остаётся Enabled=true с PSK, а блока [Peer] в конфиге уже нет. Прежний
// switch промахивался мимо обеих веток (inConf — нет, !p.Enabled — нет), и
// запись ВЫБРАСЫВАЛАСЬ вместе с единственной копией PSK, а адрес уходил
// следующему клиенту.
//
// Ветка безопасна ровно потому, что у пира, ПРИСУТСТВУЮЩЕГО в конфиге,
// первая ветка switch срабатывает раньше и PSK обнуляет (см.
// TestReconcileClearsPSKOfPeerPresentInConf) — то есть «включён и держит
// PSK» вне этого окна не встречается.
func TestReconcileKeepsEnabledPeerThatStillHoldsPSK(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: store.PeerID("half"), PublicKey: "half", Name: "на полпути",
		Address: "10.0.0.7/32", Enabled: true, PresharedKey: "psk-otklyuchaemogo"})
	st.Reconcile([]string{"keyA"}, func(string) string { return "10.0.0.2/32" })

	p, ok := st.ByPublicKey("half")
	if !ok {
		t.Fatal("пир, не дошедший до пометки «выключен», выброшен вместе с единственной копией PSK — " +
			"выданный клиенту конфиг не оживить, а его адрес уйдёт следующему")
	}
	if p.PresharedKey != "psk-otklyuchaemogo" {
		t.Errorf("PSK = %q, ожидался сохранённый — без него Enable откажет навсегда", p.PresharedKey)
	}
	if p.Enabled {
		t.Error("пира нет в конфиге, но он помечен включённым — панель врёт про состояние устройства")
	}
	if p.Address != "10.0.0.7/32" {
		t.Errorf("адрес = %q, ожидался сохранённый: он обязан остаться зарезервированным", p.Address)
	}
}

// TestReconcileClearsPSKOfPeerPresentInConf покрывает store.go: у пира,
// найденного в конфиге, PresharedKey обнуляется, потому что он живёт в самом
// конфиге и вторая копия в метаданных — лишний экземпляр секрета на диске.
// Ни один тест этого не проверял (находка Important 4 финального ревью), а
// строка при этом несущая: именно на неё ссылается порядок «сначала
// сохранить PSK, потом вырезать блок» в Service.Disable как на штатную
// уборку лишней копии, и именно она делает безопасной ветку
// TestReconcileKeepsEnabledPeerThatStillHoldsPSK.
func TestReconcileClearsPSKOfPeerPresentInConf(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: store.PeerID("live"), PublicKey: "live", Name: "живой",
		Address: "10.0.0.5/32", Enabled: false, PresharedKey: "лишняя-копия"})
	st.Reconcile([]string{"live"}, func(string) string { return "10.0.0.5/32" })

	p, ok := st.ByPublicKey("live")
	if !ok {
		t.Fatal("пир из конфига пропал из состояния")
	}
	if p.PresharedKey != "" {
		t.Errorf("PSK = %q, ожидалось пусто: у пира, присутствующего в конфиге, "+
			"вторая копия секрета в метаданных не нужна", p.PresharedKey)
	}
	if !p.Enabled {
		t.Error("пир есть в конфиге, но не помечен включённым")
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"папа-телефон": "papa-telefon",
		"My Phone!":    "my-phone",
		"  --a--  ":    "a",
		"":             "peer",
		"ЁжИк":         "yozhik",
	}
	for in, want := range cases {
		if got := store.Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

func TestUniqueSlugAddsSuffix(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: "1", Name: "телефон", Slug: "telefon"})
	if got := st.UniqueSlug("телефон"); got != "telefon-2" {
		t.Errorf("UniqueSlug = %q, ожидалось telefon-2", got)
	}
}

// Slug фиксируется при выпуске: переименование пира не должно уводить
// его конфиг из-под ссылки на скачивание.
func TestUniqueSlugIgnoresPeersWithoutSlug(t *testing.T) {
	st := &store.State{Version: 1}
	st.Upsert(store.Peer{ID: "1", Name: "телефон"}) // подхваченный пир, конфига нет
	if got := st.UniqueSlug("телефон"); got != "telefon" {
		t.Errorf("UniqueSlug = %q, ожидалось telefon", got)
	}
}

func TestOverridesRoundTripDistinguishesEmptyFromAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.json")
	empty := ""
	s := &store.State{Peers: []store.Peer{
		{ID: "aaa", Name: "с пустым DNS", PublicKey: "K1", Enabled: true,
			Overrides: &store.Overrides{DNS: &empty}},
		{ID: "bbb", Name: "без оверрайдов", PublicKey: "K2", Enabled: true},
	}}
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != store.StateVersion {
		t.Fatalf("Version = %d, ожидалось %d", got.Version, store.StateVersion)
	}
	a, _ := got.Get("aaa")
	if a.Overrides == nil || a.Overrides.DNS == nil || *a.Overrides.DNS != "" {
		t.Fatal("явно пустой DNS обязан пережить круг и остаться заданным")
	}
	b, _ := got.Get("bbb")
	if b.Overrides != nil {
		t.Fatal("отсутствующие оверрайды обязаны остаться отсутствующими")
	}
}

func TestLoadAcceptsVersion1AndRejectsFuture(t *testing.T) {
	dir := t.TempDir()
	v1 := filepath.Join(dir, "v1.json")
	os.WriteFile(v1, []byte(`{"version":1,"peers":[{"id":"aaa","public_key":"K","enabled":true}]}`), 0o600)
	if _, err := store.Load(v1); err != nil {
		t.Fatalf("файл версии 1 обязан читаться: %v", err)
	}
	v9 := filepath.Join(dir, "v9.json")
	os.WriteFile(v9, []byte(`{"version":9,"peers":[]}`), 0o600)
	if _, err := store.Load(v9); err == nil {
		t.Fatal("файл версии из будущего обязан быть ошибкой: панель не знает его семантики")
	}
}
