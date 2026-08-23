package issuer_test

import (
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

func TestKeyStoreRejectsUnsafeID(t *testing.T) {
	ks := issuer.NewKeyStore(t.TempDir())
	for _, bad := range []string{"", "../etc/passwd", "a/b", "AAAA", "id.key", strings.Repeat("a", 65)} {
		if err := ks.Put(bad, "cHJpdg=="); err == nil {
			t.Fatalf("id %q обязан быть отвергнут: путь к файлу строится из него, а id приходит из URL", bad)
		}
	}
}

func TestKeyStorePutGetDelete(t *testing.T) {
	dir := t.TempDir()
	ks := issuer.NewKeyStore(dir)
	if _, err := ks.Get("9f2c1a4b8e70"); !errors.Is(err, issuer.ErrNoPrivateKey) {
		t.Fatalf("ожидалась ErrNoPrivateKey, получено %v", err)
	}
	if err := ks.Put("9f2c1a4b8e70", "cHJpdmF0ZS1rZXk="); err != nil {
		t.Fatal(err)
	}
	got, err := ks.Get("9f2c1a4b8e70")
	if err != nil || got != "cHJpdmF0ZS1rZXk=" {
		t.Fatalf("Get = %q, %v", got, err)
	}
	if err := ks.Delete("9f2c1a4b8e70"); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Get("9f2c1a4b8e70"); !errors.Is(err, issuer.ErrNoPrivateKey) {
		t.Fatal("после Delete ключа быть не должно")
	}
	// Повторное удаление несуществующего — не ошибка: путь удаления пира
	// обязан быть идемпотентным, иначе наполовину удалённый пир не удаляется вовсе.
	if err := ks.Delete("9f2c1a4b8e70"); err != nil {
		t.Fatalf("повторный Delete: %v", err)
	}
}

func TestKeyStoreFileMode(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("unix-права не проверяются на Windows")
	}
	dir := t.TempDir()
	ks := issuer.NewKeyStore(dir)
	if err := ks.Put("9f2c1a4b8e70", "cHJpdg=="); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "9f2c1a4b8e70.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("права %o, ожидалось 600", fi.Mode().Perm())
	}
}

// Приватные ключи ниже — "PRIVKEY1"/"WRONGKEY" вместо "PRIV"/"WRONG" из
// брифа. Отклонение намеренное: runtime.Fake.PubKey (см.
// internal/runtime/fake.go) обязана возвращать ошибку на ключах короче 8
// байт, а не паниковать на priv[:8] — это часть контракта Runner, отдельная
// от детерминированности, которой требует этот тест, и её нельзя ослаблять
// ради теста (см. комментарий у PubKey). "PRIV"/"WRONG" (4 и 5 байт) эту
// проверку задевают ещё до сравнения публичных ключей — то есть до того,
// что тест на самом деле проверяет. Реальные приватные ключи всегда 44
// base64-байта, так что 8-байтовые заглушки ближе к жизни, чем 4-байтовые,
// и не меняют смысл ни одного из двух тестов.
func TestMigrateLegacyKeyVerifiesPublicKey(t *testing.T) {
	dir := t.TempDir()
	ks := issuer.NewKeyStore(filepath.Join(dir, "keys"))
	legacy := filepath.Join(dir, "phone.conf")
	os.WriteFile(legacy, []byte("[Interface]\nPrivateKey = PRIVKEY1\nAddress = 10.0.0.4/32\n\n[Peer]\nPublicKey = SRV\n"), 0o600)

	fake := runtime.NewFake("[Interface]\nPrivateKey = S\nListenPort = 1\n")
	// Fake.PubKey возвращает детерминированную производную от приватного ключа.
	want, _ := fake.PubKey("PRIVKEY1")

	if err := issuer.MigrateLegacyKey(ks, fake, "9f2c1a4b8e70", legacy, want); err != nil {
		t.Fatalf("миграция: %v", err)
	}
	if got, err := ks.Get("9f2c1a4b8e70"); err != nil || got != "PRIVKEY1" {
		t.Fatalf("ключ не перенесён: %q, %v", got, err)
	}
	if _, err := os.Stat(legacy); !os.IsNotExist(err) {
		t.Fatal("успешная миграция обязана удалить легаси-файл: один ключ в двух местах — " +
			"два места для утечки и два для расхождения")
	}
}

func TestMigrateLegacyKeyKeepsFileOnMismatch(t *testing.T) {
	dir := t.TempDir()
	ks := issuer.NewKeyStore(filepath.Join(dir, "keys"))
	legacy := filepath.Join(dir, "phone.conf")
	os.WriteFile(legacy, []byte("[Interface]\nPrivateKey = WRONGKEY\n\n[Peer]\nPublicKey = SRV\n"), 0o600)

	fake := runtime.NewFake("[Interface]\nPrivateKey = S\nListenPort = 1\n")
	err := issuer.MigrateLegacyKey(ks, fake, "9f2c1a4b8e70", legacy, "ЧУЖОЙ-ПУБЛИЧНЫЙ-КЛЮЧ")
	if err == nil {
		t.Fatal("расхождение публичного ключа обязано быть ошибкой")
	}
	if _, err := ks.Get("9f2c1a4b8e70"); !errors.Is(err, issuer.ErrNoPrivateKey) {
		t.Fatal("при расхождении ключ не должен попасть в хранилище")
	}
	if _, err := os.Stat(legacy); err != nil {
		t.Fatal("при расхождении легаси-файл обязан остаться нетронутым")
	}
}
