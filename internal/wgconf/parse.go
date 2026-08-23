// Package wgconf выполняет две независимые роли (раздел 5.1 спеки):
//
//  1. разбор серверного конфига AmneziaWG ДЛЯ ЧТЕНИЯ — parse.go;
//  2. хирургическое текстовое редактирование блоков [Peer] ДЛЯ ЗАПИСИ — edit.go.
//
// Обратной сериализации модели в файл здесь нет и быть не должно: потеря или
// искажение поля [Interface] при записи меняет обфускацию на живом устройстве
// и молча отключает всех клиентов (раздел 6.1 спеки).
package wgconf

import (
	"fmt"
	"strings"
)

type KV struct {
	Key   string
	Value string
}

// Section — одна секция конфига вместе с её точными границами в исходном тексте.
// Границы хранятся в байтах, чтобы редактирование могло вырезать и вставлять
// диапазоны, не пересобирая остальной файл.
type Section struct {
	Name      string // "Interface" или "Peer"
	Items     []KV
	StartByte int // включительно, указывает на "[" заголовка
	EndByte   int // исключительно, начало следующего заголовка либо конец файла
}

type Config struct {
	Raw       string
	Interface *Section
	Peers     []*Section
}

func (s *Section) Get(key string) string {
	for _, kv := range s.Items {
		if strings.EqualFold(kv.Key, key) {
			return kv.Value
		}
	}
	return ""
}

func (s *Section) GetAll(key string) []string {
	var out []string
	for _, kv := range s.Items {
		if strings.EqualFold(kv.Key, key) {
			out = append(out, kv.Value)
		}
	}
	return out
}

// Bytes возвращает исходные байты секции из текста, которым она была разобрана.
func (s *Section) Bytes(raw string) string { return raw[s.StartByte:s.EndByte] }

// maxKeyNameLen — верхняя граница длины строки, которую keyNameOnly готова
// признать именем ключа. Это не эвристика «обычно короче» — это жёсткая
// граница протокола: PrivateKey/PublicKey/PresharedKey в WireGuard и AWG —
// ровно 32-байтные значения Curve25519, что в base64 даёт МИНИМУМ 43 символа
// (44 с padding-«=»), короче они не бывают физически. Самое длинное реальное
// имя ключа в этом конфиге — "ContentPaddingAddition", 22 символа. 32 —
// комфортный запас с обеих сторон: 10 символов над самым длинным именем,
// 11 символов под самым коротким возможным секретом.
const maxKeyNameLen = 32

// looksLikeKeyName — true, если s похоже на имя ключа конфига (например,
// "PrivateKey"), а не на его значение. Строгая проверка нарочно: цена
// ложноположительного срабатывания (секрет распознан как «имя» и утёк в
// лог) намного выше цены ложноотрицательного (настоящее имя ключа не
// распознано, и сообщение чуть менее информативно, но безопасно).
//   - непустая и не длиннее maxKeyNameLen — единственная защита, которая
//     реально нужна: base64-тело ключа/PSK всегда длиннее любого имени;
//   - состоит только из ASCII-букв и цифр — ни один настоящий ключ конфига
//     не содержит "+", "/" или "=", а base64 использует именно их;
//   - начинается с буквы, а не с цифры.
func looksLikeKeyName(s string) bool {
	if s == "" || len(s) > maxKeyNameLen {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
			// буква — всегда можно
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// keyNameOnly возвращает текст слева от первого "=" — для использования в
// сообщениях об ошибках — но ТОЛЬКО если он похож на имя ключа (см.
// looksLikeKeyName). Никогда не возвращает то, что находится справа от "=":
// строка в конфиге AWG чаще всего "PrivateKey = <base64>" или "PresharedKey
// = <base64>", и правая часть — потенциальный секрет, который не должен
// попасть ни в лог, ни в текст ошибки, ни тем более в тело HTTP-ответа
// (CLAUDE.md, незыблемое правило 4).
//
// Одного правила «есть „=“ → слева имя» недостаточно: настоящие base64-ключи
// почти всегда ОКАНЧИВАЮТСЯ на "=" (padding), поэтому голое значение без
// имени ключа — то есть сам секрет — тоже успешно режется strings.Cut и без
// доп. проверки выглядело бы как «имя». looksLikeKeyName закрывает именно
// этот случай через ограничение длины и алфавита.
func keyNameOnly(line string) string {
	key, _, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	name := strings.TrimSpace(key)
	if !looksLikeKeyName(name) {
		return ""
	}
	return name
}

// EOL определяет перевод строки, преобладающий в тексте.
func EOL(text string) string {
	if strings.Count(text, "\r\n") > 0 && strings.Count(text, "\r\n")*2 >= strings.Count(text, "\n") {
		return "\r\n"
	}
	return "\n"
}

func Parse(text string) (*Config, error) {
	c := &Config{Raw: text}
	var cur *Section
	offset := 0
	for lineNo, line := range strings.SplitAfter(text, "\n") {
		if line == "" { // хвост SplitAfter после финального \n
			continue
		}
		start := offset
		offset += len(line)
		trimmed := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			continue
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if cur != nil {
				cur.EndByte = start
			}
			sec := &Section{Name: name, StartByte: start}
			switch {
			case strings.EqualFold(name, "Interface"):
				if c.Interface != nil {
					return nil, fmt.Errorf("строка %d: вторая секция [Interface]", lineNo+1)
				}
				c.Interface = sec
			case strings.EqualFold(name, "Peer"):
				c.Peers = append(c.Peers, sec)
			default:
				return nil, fmt.Errorf("строка %d: неизвестная секция [%s]", lineNo+1, name)
			}
			cur = sec
		default:
			if cur == nil {
				if name := keyNameOnly(trimmed); name != "" {
					return nil, fmt.Errorf("строка %d: значение (ключ %q) вне секции", lineNo+1, name)
				}
				return nil, fmt.Errorf("строка %d: значение вне секции", lineNo+1)
			}
			key, val, ok := strings.Cut(trimmed, "=")
			if !ok {
				return nil, fmt.Errorf("строка %d: нет знака =", lineNo+1)
			}
			cur.Items = append(cur.Items, KV{
				Key:   strings.TrimSpace(key),
				Value: strings.TrimSpace(val),
			})
		}
	}
	if cur != nil {
		cur.EndByte = len(text)
	}
	if c.Interface == nil {
		return nil, fmt.Errorf("секция [Interface] не найдена")
	}
	return c, nil
}
