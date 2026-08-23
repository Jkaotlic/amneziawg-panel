package issuer

import (
	"os"
	"path/filepath"
)

// writeFileAtomic0600 пишет body в path через временный файл в том же
// каталоге и rename: читатель никогда не увидит частично записанный файл.
// Временный файл получает права 0600 до переименования, так что итоговый
// файл ни на мгновение не оказывается доступен шире, чем 0600 — это важно
// и для конфига (apply.go), и для приватных ключей клиентов (KeyStore).
func writeFileAtomic0600(path, body string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".awg3panel-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
