package runtime

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type execRunner struct{ binDir string }

// NewExec возвращает Runner, вызывающий awg и awg-quick из binDir.
func NewExec(binDir string) Runner { return &execRunner{binDir: binDir} }

func (e *execRunner) run(bin string, args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(e.binDir, bin), args...)
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		// В аргументах ключей нет: приватный ключ передаётся только через stdin.
		return "", commandError(bin, args, err, errBuf.String())
	}
	return out.String(), nil
}

// commandError собирает ошибку внешней команды, пропуская её stderr через
// stderrSnippet. Аргументы (имя интерфейса, путь к временному файлу)
// подставляются как есть: ключей в них нет по построению — приватный ключ
// уходит только через stdin.
func commandError(bin string, args []string, err error, stderr string) error {
	snippet := stderrSnippet(stderr)
	if snippet == "" {
		// Без этой ветки при пустом stderr в конце оставалось висящее
		// двоеточие с пробелом — читается как обрезанное сообщение.
		return fmt.Errorf("%s %s: %w", bin, strings.Join(args, " "), err)
	}
	return fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, snippet)
}

// secretRunLen — длина цепочки символов base64-алфавита, начиная с которой
// stderrSnippet считает её потенциальным секретом. Это не «обычно длиннее»,
// а граница протокола: PrivateKey/PublicKey/PresharedKey в WireGuard и AWG —
// ровно 32-байтные значения Curve25519, то есть 44 символа base64 с
// padding'ом, короче они не бывают. Самое длинное реальное имя параметра
// конфига — ContentPaddingAddition, 22 символа. Порог 40 лежит между ними с
// запасом в обе стороны (та же логика и те же величины, что у
// wgconf.maxKeyNameLen, только с другой стороны границы).
const secretRunLen = 40

// stderrSnippet готовит stderr внешней команды к вставке в текст ошибки.
//
// Повод конкретный (ревью финальное, I1): боевой бинарь /opt/awg3/bin/awg
// содержит форматные строки "Line unrecognized: `%s'" и "Key is not the
// correct length or format: `%s'" — при повреждённой строке PrivateKey или
// PresharedKey в применяемом конфиге сам `awg syncconf` печатает СЕКРЕТ в
// stderr. Дальше он становился телом нашей ошибки и уезжал в journal тем же
// путём, что и утечка C1: web.writeError → log.Printf, CLI → os.Stderr.
// Поведение чужого бинаря нам не подчиняется, поэтому фильтруем на входе.
//
// Полный отказ от stderr был бы проще, но дороже: без него администратор не
// отличит «конфиг битый» от «интерфейса нет» и «нет прав» — все три
// выглядели бы как безымянный exit status 1. Поэтому режем адресно:
//
//  1. остаётся только первая непустая строка. syncconf ругается на КАЖДУЮ
//     негодную строку конфига, так что при массовом повреждении (обрыв
//     записи, испорченный бэкап) в лог уехал бы весь набор ключей разом;
//     причина отказа при этом читается и по первой строке;
//  2. любая цепочка символов base64-алфавита длиной от secretRunLen
//     заменяется на отметку с её длиной.
//
// Символ "/" входит в алфавит намеренно, хотя из-за него под вырезание
// попадёт и достаточно длинный путь: ключ, содержащий "/" в середине, при
// исключении этого символа распался бы на два куска короче порога и утёк бы
// целиком. Перерезать лишнее здесь безопаснее, чем недорезать, — тем более
// что путь мы и так печатаем отдельно, из args, где он не фильтруется.
func stderrSnippet(s string) string {
	var line string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(strings.TrimSuffix(l, "\r")); l != "" {
			line = l
			break
		}
	}
	return redactSecretLike(line)
}

func redactSecretLike(s string) string {
	var b strings.Builder
	run := 0
	// flush закрывает накопленную цепочку, окончившуюся на позиции end
	// (не включительно).
	flush := func(end int) {
		switch {
		case run == 0:
		case run >= secretRunLen:
			fmt.Fprintf(&b, "[вырезано %d символов]", run)
		default:
			b.WriteString(s[end-run : end])
		}
		run = 0
	}
	// Обход побайтовый, а не по рунам: символы base64-алфавита все
	// однобайтовые ASCII, а любой байт многобайтовой UTF-8 последовательности
	// (>= 0x80) в алфавит не попадает и переписывается как есть, поэтому
	// кириллица в сообщении не бьётся.
	for i := 0; i < len(s); i++ {
		if isBase64Byte(s[i]) {
			run++
			continue
		}
		flush(i)
		b.WriteByte(s[i])
	}
	flush(len(s))
	return b.String()
}

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
		c == '+' || c == '/' || c == '='
}

func (e *execRunner) Show(iface string) (string, error) {
	return e.run("awg", "show", iface, "dump")
}

func (e *execRunner) ShowConf(iface string) (string, error) {
	return e.run("awg", "showconf", iface)
}

func (e *execRunner) Strip(iface string) (string, error) {
	return e.run("awg-quick", "strip", iface)
}

func (e *execRunner) SyncConf(iface, path string) error {
	_, err := e.run("awg", "syncconf", iface, path)
	return err
}

func (e *execRunner) GenKey() (string, error) {
	out, err := e.run("awg", "genkey")
	return strings.TrimSpace(out), err
}

func (e *execRunner) GenPSK() (string, error) {
	out, err := e.run("awg", "genpsk")
	return strings.TrimSpace(out), err
}

// PubKey передаёт приватный ключ через stdin, а не аргументом:
// аргументы процесса видны в /proc любому, кто может читать список процессов.
func (e *execRunner) PubKey(priv string) (string, error) {
	cmd := exec.Command(filepath.Join(e.binDir, "awg"), "pubkey")
	cmd.Stdin = strings.NewReader(priv + "\n")
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		return "", commandError("awg", []string{"pubkey"}, err, errBuf.String())
	}
	return strings.TrimSpace(out.String()), nil
}
