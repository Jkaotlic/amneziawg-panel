// Package store хранит метаданные пиров — то, чего нет в awg3.conf:
// человеческие имена, дату выпуска, флаг «отключён» и PSK отключённых пиров.
//
// Источник правды по составу пиров и криптографии — сам awg3.conf
// (раздел 7.1 спеки). Здесь только то, что серверный конфиг не хранит.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Peer struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
	CreatedAt string `json:"created_at"`
	Enabled   bool   `json:"enabled"`
	// Slug фиксируется при выпуске и больше не пересчитывается: имя файла
	// с клиентским конфигом должно оставаться находимым даже после
	// переименования пира или появления тёзки.
	Slug string `json:"slug,omitempty"`
	// PresharedKey заполняется ТОЛЬКО для отключённых пиров: при disable блок
	// [Peer] уходит из awg3.conf, и при обратном включении PSK неоткуда взять.
	PresharedKey string `json:"preshared_key,omitempty"`
	// Overrides — персональные значения клиентских параметров этого пира,
	// перебивающие defaults.json. nil означает «оверрайдов нет вовсе», а не
	// «оверрайды пустые» — см. комментарий к типу Overrides.
	Overrides *Overrides `json:"overrides,omitempty"`
}

// Overrides — персональные значения клиентских параметров пира.
// Указатели, а не строки, потому что умолчание DNS — пустая строка: без
// различия «поля нет» и «поле = пусто» нельзя выразить «этому пиру DNS не
// нужен вопреки умолчанию» (раздел 5.3 спеки).
type Overrides struct {
	DNS        *string           `json:"dns,omitempty"`
	AllowedIPs *string           `json:"allowed_ips,omitempty"`
	Keepalive  *string           `json:"keepalive,omitempty"`
	MTU        *string           `json:"mtu,omitempty"`
	Endpoint   *string           `json:"endpoint,omitempty"`
	Jc         *int              `json:"jc,omitempty"`
	Jmin       *int              `json:"jmin,omitempty"`
	Jmax       *int              `json:"jmax,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

type State struct {
	Version int    `json:"version"`
	Peers   []Peer `json:"peers"`
}

// StateVersion — версия формата peers.json, которую пишет эта панель.
// 1 → 2: добавлены overrides, а id перестал быть производной от ТЕКУЩЕГО
// публичного ключа (после ротации он не пересчитывается — см. Service.Rotate).
const StateVersion = 2

// PeerID — первые 12 hex-символов sha256 публичного ключа.
// Стабилен и безопасен для URL, в отличие от сырого base64 с / и +.
func PeerID(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(sum[:])[:12]
}

func Load(path string) (*State, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &State{Version: 1}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("разбор %s: %w", path, err)
	}
	if s.Version == 0 {
		s.Version = 1
	}
	if s.Version > StateVersion {
		return nil, fmt.Errorf("%s: версия формата %d новее панели (%d)", path, s.Version, StateVersion)
	}
	return &s, nil
}

// Save пишет состояние атомарно: временный файл в том же каталоге,
// права 0600, затем rename.
func (s *State) Save(path string) error {
	s.Version = StateVersion
	return writeAtomicJSON(path, s)
}

// writeAtomicJSON сериализует v и пишет его по path атомарно: временный файл
// в том же каталоге, права 0600, затем rename. Общий хелпер для State.Save и
// Defaults.Save — оба хранилища требуют одной и той же гарантии «либо старый
// файл целиком, либо новый целиком», и дублировать её было незачем.
func writeAtomicJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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

// Get возвращает указатель на пира с данным id — он указывает внутрь
// слайса s.Peers, а не на копию. Указатель действителен только до
// следующего вызова Upsert, Delete или Reconcile на этом же State: любая
// из трёх может уплотнить s.Peers на месте или переаллоцировать его
// целиком, и тогда запись через устаревший указатель уйдёт мимо —
// молча, без ошибки компиляции или паники, — а настоящая (сдвинутая
// или скопированная в новый массив) запись останется нетронутой и в
// Save не попадёт. Цена ошибки конкретна: обработчик отключения пира
// берёт p := Get(id), применяет изменения к конфигу и только потом
// пишет p.PresharedKey = psk — если между этими шагами вклинится любая
// другая операция над State, PSK отключённого пира потеряется
// безвозвратно, а мёртвый конфиг на устройстве клиента будет уже нечем
// оживить. Правило: мутировать через возвращённый указатель нужно
// непосредственно перед Save, не удерживая его через другие вызовы.
func (s *State) Get(id string) (*Peer, bool) {
	for i := range s.Peers {
		if s.Peers[i].ID == id {
			return &s.Peers[i], true
		}
	}
	return nil, false
}

// ByPublicKey возвращает указатель на пира с данным публичным ключом.
// Действует тот же контракт времени жизни, что и у Get: указатель годен
// только до следующего Upsert, Delete или Reconcile — см. комментарий
// к Get за подробностями и ценой нарушения.
func (s *State) ByPublicKey(pub string) (*Peer, bool) {
	for i := range s.Peers {
		if s.Peers[i].PublicKey == pub {
			return &s.Peers[i], true
		}
	}
	return nil, false
}

// Upsert добавляет пира или заменяет существующего по ID.
// Добавление новой записи может выполнить append, который переаллоцирует
// s.Peers целиком: любые указатели, ранее полученные от Get или
// ByPublicKey, после такого вызова смотрят в старый, уже не связанный
// с State массив — записи через них не попадут в следующий Save.
func (s *State) Upsert(p Peer) {
	for i := range s.Peers {
		if s.Peers[i].ID == p.ID {
			s.Peers[i] = p
			return
		}
	}
	s.Peers = append(s.Peers, p)
}

// Delete удаляет пира по ID, уплотняя s.Peers на месте.
// Указатели, ранее полученные от Get или ByPublicKey на пиров, стоявших
// в слайсе после удалённого, после этого вызова указывают на устаревший
// слот — запись через них молча теряется.
func (s *State) Delete(id string) {
	out := s.Peers[:0]
	for _, p := range s.Peers {
		if p.ID != id {
			out = append(out, p)
		}
	}
	s.Peers = out
}

// Reconcile приводит состояние в соответствие с составом пиров в awg3.conf:
//
//	есть в конфиге, нет в состоянии → подхватить с именем peer-<id>;
//	есть в конфиге и в состоянии    → пометить включённым;
//	нет в конфиге, отключён         → сохранить (в этом и смысл disable);
//	нет в конфиге, включён, но держит PSK → сохранить, пометив выключенным;
//	нет в конфиге, включён          → удалить (убран из конфига мимо панели).
//
// Предпоследняя строка закрывает окно потери PSK (ревью финальное, I2). Пара
// «Enabled=true И PresharedKey != ""» возникает РОВНО в одном месте:
// Service.Disable сохраняет PSK, пока пир ещё включён, и помечает его
// выключенным только ПОСЛЕ успешного Apply. Если между этими шагами падает
// запись состояния (диск полон, EIO) или умирает процесс, на диске остаётся
// Enabled=true с PSK, а блока [Peer] в конфиге уже нет — и последняя ветка
// выбросила бы запись вместе с единственной копией PSK, попутно освободив
// адрес под следующего клиента. Ложных срабатываний у этой ветки нет: у
// пира, ПРИСУТСТВУЮЩЕГО в конфиге, первая ветка switch срабатывает раньше и
// PSK обнуляет, так что вне описанного окна такая пара не встречается.
//
// Пересобирает s.Peers через kept := s.Peers[:0] и append — как и Delete,
// уплотняет на месте и может переаллоцировать массив. Указатели, ранее
// полученные от Get или ByPublicKey, после этого вызова недействительны.
func (s *State) Reconcile(confPubKeys []string, addressOf func(pub string) string) {
	inConf := make(map[string]bool, len(confPubKeys))
	for _, pub := range confPubKeys {
		inConf[pub] = true
	}
	kept := s.Peers[:0]
	for _, p := range s.Peers {
		switch {
		case inConf[p.PublicKey]:
			p.Enabled = true
			if addr := addressOf(p.PublicKey); addr != "" {
				p.Address = addr
			}
			p.PresharedKey = "" // у живого пира PSK лежит в конфиге
			kept = append(kept, p)
		case !p.Enabled || p.PresharedKey != "":
			// Флаг выставляется явно, а не оставляется как есть: пира в
			// конфиге нет, значит на устройстве его тоже нет, и показывать
			// его включённым — врать про состояние устройства.
			p.Enabled = false
			kept = append(kept, p)
		}
	}
	s.Peers = kept
	for _, pub := range confPubKeys {
		if _, ok := s.ByPublicKey(pub); ok {
			continue
		}
		id := PeerID(pub)
		s.Peers = append(s.Peers, Peer{
			ID: id, Name: "peer-" + id, PublicKey: pub,
			Address: addressOf(pub), Enabled: true,
		})
	}
}

var translit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "g", 'д': "d", 'е': "e", 'ё': "yo",
	'ж': "zh", 'з': "z", 'и': "i", 'й': "y", 'к': "k", 'л': "l", 'м': "m",
	'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "h", 'ц': "c", 'ч': "ch", 'ш': "sh", 'щ': "sch",
	'ы': "y", 'э': "e", 'ю': "yu", 'я': "ya",
}

// Slug превращает имя пира в безопасное имя файла: [a-z0-9-].
func Slug(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == 'ъ' || r == 'ь':
			// мягкий и твёрдый знаки просто выпадают
		case translit[r] != "":
			b.WriteString(translit[r])
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(collapseDashes(b.String()), "-")
	if out == "" {
		return "peer"
	}
	return out
}

func collapseDashes(s string) string {
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	return s
}

// UniqueSlug возвращает slug, не совпадающий со slug'ами уже известных пиров.
func (s *State) UniqueSlug(name string) string {
	base := Slug(name)
	taken := make(map[string]bool, len(s.Peers))
	for _, p := range s.Peers {
		if p.Slug != "" {
			taken[p.Slug] = true
		}
	}
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		cand := base + "-" + strconv.Itoa(i)
		if !taken[cand] {
			return cand
		}
	}
}
