package issuer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// Внутренний (white-box) тест: removeLegacyFile — неэкспортируемая точка
// подмены в keys.go, и подменить её на функцию, детерминированно возвращающую
// ошибку, можно только из пакета issuer, а не issuer_test (где живут
// остальные тесты keys_test.go). Симулировать отказ удаления через реальную
// файловую систему нельзя переносимо: занятость файла, доступ только для
// чтения и гонки ломаются по-разному на Windows и Linux. Второй такой файл
// после service_internal_test.go — оба существуют по одной и той же причине
// (нужен доступ к неэкспортируемому символу пакета), см. также ревью Task 4,
// находка «Осиротевший легаси-файл».

func TestMigrateLegacyKeyKeepsKeyWhenLegacyRemovalFails(t *testing.T) {
	dir := t.TempDir()
	ks := NewKeyStore(filepath.Join(dir, "keys"))
	legacy := filepath.Join(dir, "phone.conf")
	if err := os.WriteFile(legacy,
		[]byte("[Interface]\nPrivateKey = PRIVKEY1\nAddress = 10.0.0.4/32\n\n[Peer]\nPublicKey = SRV\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	fake := runtime.NewFake("[Interface]\nPrivateKey = S\nListenPort = 1\n")
	want, _ := fake.PubKey("PRIVKEY1")

	prev := removeLegacyFile
	removeLegacyFile = func(string) error { return errors.New("симулированный отказ удаления") }
	t.Cleanup(func() { removeLegacyFile = prev })

	if err := MigrateLegacyKey(ks, fake, "9f2c1a4b8e70", legacy, want); err != nil {
		t.Fatalf("отказ удаления легаси-файла не должен отменять успех миграции: %v", err)
	}
	if got, err := ks.Get("9f2c1a4b8e70"); err != nil || got != "PRIVKEY1" {
		t.Fatalf("ключ обязан остаться в хранилище несмотря на отказ удаления: %q, %v", got, err)
	}
	// Раз removeLegacyFile смоделирован как отказавший (а не как реально
	// удаливший файл), легаси-файл обязан физически остаться на диске —
	// это и есть тот самый «осиротевший файл», который правка признаёт
	// меньшим злом, чем отказ выдать конфиг пиру с уже сохранённым ключом.
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("легаси-файл обязан остаться на диске при смоделированном отказе удаления: %v", err)
	}
}

// TestPrivateKeyTreatsLegacyRemovalFailureAsSuccess — задача 5, рулинг
// ревью задачи 4 («Осиротевший легаси-файл»): MigrateLegacyKey возвращает
// nil, если ключ сохранён, но легаси-файл удалить не удалось. Service.
// privateKey (service.go) обязан доверять этому nil как «ключ теперь в
// хранилище» и после него УСПЕШНО прочитать его через keys.Get — а не
// перепроверять факт удаления файла самостоятельно. Живёт в этом файле
// (white-box), а не в service_test.go: только пакет issuer может подменить
// removeLegacyFile на детерминированно отказывающую функцию.
func TestPrivateKeyTreatsLegacyRemovalFailureAsSuccess(t *testing.T) {
	dir := t.TempDir()
	legacyDir := filepath.Join(dir, "clients")
	if err := os.MkdirAll(legacyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(legacyDir, "phone.conf")
	if err := os.WriteFile(legacy,
		[]byte("[Interface]\nPrivateKey = PRIVKEY1\nAddress = 10.0.0.4/32\n\n[Peer]\nPublicKey = SRV\n"),
		0o600); err != nil {
		t.Fatal(err)
	}

	fake := runtime.NewFake("[Interface]\nPrivateKey = S\nListenPort = 1\n")
	wantPub, _ := fake.PubKey("PRIVKEY1")

	iface := config.Interface{
		ID: "t",
		Storage: config.Storage{
			Keys:          filepath.Join(dir, "keys"),
			ClientConfigs: legacyDir,
		},
	}
	s := New(iface, "10.0.0.1:8081", fake)

	prev := removeLegacyFile
	removeLegacyFile = func(string) error { return errors.New("симулированный отказ удаления") }
	t.Cleanup(func() { removeLegacyFile = prev })

	p := store.Peer{ID: "9f2c1a4b8e70", Slug: "phone", PublicKey: wantPub}
	priv, err := s.privateKey(nil, p)
	if err != nil {
		t.Fatalf("privateKey обязан считать миграцию успешной несмотря на отказ удаления "+
			"легаси-файла: %v", err)
	}
	if priv != "PRIVKEY1" {
		t.Fatalf("приватный ключ = %q, ожидался PRIVKEY1", priv)
	}
	if got, err := s.keys.Get(p.ID); err != nil || got != "PRIVKEY1" {
		t.Fatalf("ключ обязан быть доступен через keys.Get после миграции: %q, %v", got, err)
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatalf("легаси-файл обязан остаться (отказ удаления смоделирован): %v", err)
	}
}
