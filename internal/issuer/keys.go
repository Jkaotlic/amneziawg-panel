package issuer

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// ErrNoPrivateKey — приватный ключ пира панели неизвестен. Не ошибка
// состояния: пиры, заведённые вручную до панели, живут так всегда. Выдать им
// конфиг нельзя, всё остальное — можно, а вернуть в строй их умеет Rotate.
var ErrNoPrivateKey = fmt.Errorf("%w: приватный ключ пира панели неизвестен", ErrNotFound)

// idRe — id пира состоит из hex-символов (см. store.PeerID). Проверка
// обязательна: id приходит из пути HTTP-запроса, а из него строится путь к
// файлу. "../" в id без этой проверки читает и перезаписывает что угодно.
var idRe = regexp.MustCompile(`^[0-9a-f]{6,64}$`)

// KeyStore хранит приватные ключи клиентских пиров панели — по одному файлу
// <dir>/<id>.key на пира. Раньше приватный ключ существовал только внутри
// выданного clients/<slug>.conf; отдельное хранилище — то, что позволяет
// пересобрать клиентский конфиг заново в любой момент (задача 5).
type KeyStore struct{ dir string }

func NewKeyStore(dir string) *KeyStore { return &KeyStore{dir: dir} }

func (k *KeyStore) path(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", fmt.Errorf("%w: недопустимый id пира %q", ErrInvalidInput, id)
	}
	return filepath.Join(k.dir, id+".key"), nil
}

// Get возвращает приватный ключ пира id. Ключа нет — не паникуем и не
// возвращаем внутреннюю ошибку файловой системы, а ErrNoPrivateKey: это
// штатное состояние для пиров, заведённых до появления хранилища.
func (k *KeyStore) Get(id string) (string, error) {
	p, err := k.path(id)
	if err != nil {
		return "", err
	}
	b, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return "", ErrNoPrivateKey
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// Put сохраняет приватный ключ пира id, атомарно и с правами 0600
// (writeFileAtomic0600, см. atomic.go). Перезаписывает прежнее значение, если
// оно было — вызывающий код решает, когда это уместно (например, Rotate).
func (k *KeyStore) Put(id, priv string) error {
	p, err := k.path(id)
	if err != nil {
		return err
	}
	if strings.TrimSpace(priv) == "" {
		return fmt.Errorf("%w: пустой приватный ключ", ErrInvalidInput)
	}
	if err := os.MkdirAll(k.dir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic0600(p, strings.TrimSpace(priv)+"\n")
}

// Delete удаляет приватный ключ пира id. Идемпотентна: повторное удаление
// уже отсутствующего ключа — не ошибка, иначе путь удаления пира (который
// может вызвать Delete больше одного раза, например при повторной обработке
// отказавшего запроса) отказывал бы на втором вызове, и наполовину удалённый
// пир не удалялся бы вовсе.
func (k *KeyStore) Delete(id string) error {
	p, err := k.path(id)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// removeLegacyFile — точка подмены для теста: смоделировать отказ удаления
// переносимо между Windows и Linux иначе нечем, а ветка «ключ сохранён,
// файл удалить не удалось» — единственная, где миграция обязана считаться
// успешной вопреки ошибке.
var removeLegacyFile = os.Remove

// MigrateLegacyKey переносит приватный ключ из выданного ранее клиентского
// .conf в хранилище ключей и удаляет исходный файл.
//
// Сверка публичного ключа (шаг 3 раздела 5.2 спеки) обязательна: без неё
// испорченный или подменённый .conf тихо стал бы источником ключа, и панель
// начала бы выдавать конфиг, которым нельзя подключиться, — а обнаружилось
// бы это на телефоне у человека, а не здесь.
//
// Успех Put необратим: если последующее удаление легаси-файла отказывает
// (нет прав, гонка, ФС только для чтения), миграция всё равно считается
// успешной. Альтернатива хуже: вызывающий код (задача 5) отличает «ключа
// нет» только по ошибке миграции, и отказ здесь означал бы, что панель
// откажется выдать конфиг пиру, чей ключ уже надёжно лежит в хранилище, —
// то есть ровно тому, для кого миграция и делалась. Осиротевший легаси-файл
// под 0600 — меньшее зло (рулинг по находке ревью Task 4, «Осиротевший
// легаси-файл»).
func MigrateLegacyKey(ks *KeyStore, r runtime.Runner, id, legacyConfPath, wantPublicKey string) error {
	b, err := os.ReadFile(legacyConfPath)
	if err != nil {
		return err
	}
	c, err := wgconf.Parse(string(b))
	if err != nil {
		return fmt.Errorf("разбор легаси-конфига пира %s: %w", id, err)
	}
	priv := c.Interface.Get("PrivateKey")
	if priv == "" {
		return fmt.Errorf("в легаси-конфиге пира %s нет PrivateKey", id)
	}
	pub, err := r.PubKey(priv)
	if err != nil {
		return fmt.Errorf("вычисление публичного ключа при миграции пира %s: %w", id, err)
	}
	if pub != wantPublicKey {
		// Ни один из ключей в текст ошибки не попадает (правило 4).
		return fmt.Errorf("легаси-конфиг пира %s не соответствует его публичному ключу в awg3.conf — "+
			"файл оставлен нетронутым, ключ не перенесён", id)
	}
	if err := ks.Put(id, priv); err != nil {
		return err
	}
	if err := removeLegacyFile(legacyConfPath); err != nil && !os.IsNotExist(err) {
		// Ключ уже надёжно лежит в хранилище — миграция по существу
		// состоялась (см. комментарий над функцией). Путь пишем в лог как
		// есть: это не секрет, в отличие от ключа, и он нужен оператору,
		// чтобы убрать файл вручную.
		log.Printf("миграция пира %s: ключ перенесён в хранилище ключей, но легаси-файл %s "+
			"не удалён: %v — уберите файл вручную", id, legacyConfPath, err)
	}
	return nil
}
