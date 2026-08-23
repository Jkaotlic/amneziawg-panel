package wgconf_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/main.conf")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseInterface(t *testing.T) {
	c, err := wgconf.Parse(fixture(t))
	if err != nil {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	want := map[string]string{
		"Address":                "10.0.0.1/24",
		"ListenPort":             "51820",
		"MTU":                    "1280",
		"S1":                     "17",
		"S4":                     "12",
		"H1":                     "1633177",
		"H4":                     "1955441",
		"ContentPaddingAddition": "0-96",
	}
	for k, v := range want {
		if got := c.Interface.Get(k); got != v {
			t.Errorf("Interface[%s] = %q, ожидалось %q", k, got, v)
		}
	}
	if c.Interface.Get("HeaderProtectionKey") == "" {
		t.Error("HeaderProtectionKey потерян")
	}
}

func TestParseGetIsCaseInsensitive(t *testing.T) {
	c, _ := wgconf.Parse(fixture(t))
	if c.Interface.Get("listenport") != "51820" {
		t.Error("Get должен искать без учёта регистра")
	}
}

func TestParseGetAllKeepsRepeatedKeys(t *testing.T) {
	c, _ := wgconf.Parse(fixture(t))
	if got := c.Interface.GetAll("PostUp"); len(got) != 2 {
		t.Errorf("PostUp: получено %d значений, ожидалось 2", len(got))
	}
}

func TestParsePeers(t *testing.T) {
	c, _ := wgconf.Parse(fixture(t))
	if len(c.Peers) != 2 {
		t.Fatalf("пиров %d, ожидалось 2", len(c.Peers))
	}
	if c.Peers[0].Get("AllowedIPs") != "10.0.0.2/32" {
		t.Errorf("первый пир: AllowedIPs = %q", c.Peers[0].Get("AllowedIPs"))
	}
	if !strings.HasPrefix(c.Peers[1].Get("PublicKey"), "cGFwYS") {
		t.Errorf("второй пир: PublicKey = %q", c.Peers[1].Get("PublicKey"))
	}
}

func TestSectionBytesAreExactSlices(t *testing.T) {
	raw := fixture(t)
	c, _ := wgconf.Parse(raw)
	iface := c.Interface.Bytes(raw)
	if !strings.HasPrefix(iface, "[Interface]") {
		t.Fatalf("секция [Interface] начинается не с заголовка: %q", iface[:20])
	}
	if !strings.Contains(iface, "PostDown = iptables -D FORWARD -i awg3 -j ACCEPT") {
		t.Error("секция [Interface] обрезана — потеряна последняя строка PostDown")
	}
	if strings.Contains(iface, "[Peer]") {
		t.Error("в секцию [Interface] затянут блок [Peer]")
	}
	// Секции покрывают исходник без пропусков и наложений.
	if c.Interface.StartByte != 0 {
		t.Errorf("StartByte первой секции = %d, ожидалось 0", c.Interface.StartByte)
	}
	if c.Peers[0].StartByte != c.Interface.EndByte {
		t.Error("между [Interface] и первым [Peer] есть непокрытый диапазон")
	}
	// Проверяем контигуальность между всеми соседними пирами.
	for i := 0; i < len(c.Peers)-1; i++ {
		if c.Peers[i].EndByte != c.Peers[i+1].StartByte {
			t.Errorf("между пиром %d и пиром %d есть непокрытый диапазон или наложение", i, i+1)
		}
	}
	if c.Peers[len(c.Peers)-1].EndByte != len(raw) {
		t.Error("последняя секция не доходит до конца файла")
	}
}

func TestParseNoPeers(t *testing.T) {
	c, err := wgconf.Parse("[Interface]\nPrivateKey = k\nListenPort = 1\n")
	if err != nil {
		t.Fatalf("конфиг без пиров — валидный: %v", err)
	}
	if len(c.Peers) != 0 {
		t.Errorf("пиров %d, ожидалось 0", len(c.Peers))
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"без [Interface]":    "[Peer]\nPublicKey = k\n",
		"ключ до секции":     "PrivateKey = k\n[Interface]\n",
		"два [Interface]":    "[Interface]\nPrivateKey = a\n[Interface]\nPrivateKey = b\n",
		"строка без знака =": "[Interface]\nPrivateKey\n",
		"неизвестная секция": "[Interface]\nPrivateKey = k\n[Wat]\nX = 1\n",
	}
	for name, body := range cases {
		if _, err := wgconf.Parse(body); err == nil {
			t.Errorf("%s: ожидалась ошибка, получено nil", name)
		}
	}
}

// TestParseErrorsDoNotLeakSecretValues — регрессия на незыблемое правило репозитория
// (CLAUDE.md, п.4: приватные ключи и PSK не пишутся в логи). Раньше обе ветки ниже
// эхом печатали сырую строку конфига целиком в тексте ошибки: если строка была
// значением "PrivateKey = <base64>" — потерянный или повреждённый заголовок
// [Interface] превращал ошибку разбора в канал утечки ключа во всё, что читает
// err.Error() (лог, тело HTTP-ответа).
func TestParseErrorsDoNotLeakSecretValues(t *testing.T) {
	// Настоящие base64-ключи WireGuard/AWG почти всегда оканчиваются на "=" —
	// это символ дополнения (padding), а не знак присваивания. У secretNoEq
	// он тоже есть внутри строки: важно, что для ветки "нет знака =" мы берём
	// значение, где "=" не встречается ВООБЩЕ, иначе strings.Cut найдёт его
	// в дополнении и распарсит строку как валидную пару ключ/значение.
	secretWithEq := "zQ8mLpX2vRtNfYkBsWqAoCuHjGiEnDkVxZbTcPd9AbCd="
	secretNoEq := "zQ8mLpX2vRtNfYkBsWqAoCuHjGiEnDkVxZbTcPd9AbCdXY"

	t.Run("значение вне секции", func(t *testing.T) {
		// Заголовок [Interface] потерян/повреждён — PrivateKey оказывается
		// первой строкой файла, до какой-либо секции.
		_, err := wgconf.Parse("PrivateKey = " + secretWithEq + "\n[Interface]\nListenPort = 1\n")
		if err == nil {
			t.Fatal("ожидалась ошибка")
		}
		if strings.Contains(err.Error(), secretWithEq) {
			t.Fatalf("текст ошибки эхом печатает секрет целиком: %v", err)
		}
		// Нормальный случай не должен пострадать от защиты: если слева от "="
		// стоит настоящее имя ключа, оно обязано остаться в сообщении —
		// иначе оператор не поймёт, что чинить. Деградация допустима только
		// для значений, не похожих на имя ключа (см. следующий подтест).
		if !strings.Contains(err.Error(), "PrivateKey") {
			t.Errorf("текст ошибки потерял имя ключа PrivateKey (полезная диагностика): %v", err)
		}
	})

	t.Run("строка без знака =", func(t *testing.T) {
		// Строка внутри секции без "=" — например, потерян знак равенства
		// и вся строка представляет собой голый base64-огрызок ключа.
		_, err := wgconf.Parse("[Interface]\n" + secretNoEq + "\n")
		if err == nil {
			t.Fatal("ожидалась ошибка")
		}
		if strings.Contains(err.Error(), secretNoEq) {
			t.Fatalf("текст ошибки эхом печатает секрет целиком: %v", err)
		}
	})

	t.Run("голое значение с padding вне секции", func(t *testing.T) {
		// Симметричный случай, который остался открытым в round 1: строка —
		// ГОЛОЕ значение (без имени ключа слева), но благодаря padding-"="
		// в самом конце строки strings.Cut(line, "=") всё равно находит "="
		// и отдаёт тело ключа как "имя". Заголовок [Interface] потерян, и
		// это первая строка файла — единственная строка, значит слева от "="
		// не имя ключа, а буквально всё тело секрета за вычетом дополнения.
		_, err := wgconf.Parse(secretWithEq + "\n[Interface]\nListenPort = 1\n")
		if err == nil {
			t.Fatal("ожидалась ошибка")
		}
		secretBody := strings.TrimSuffix(secretWithEq, "=")
		if strings.Contains(err.Error(), secretBody) {
			t.Fatalf("текст ошибки эхом печатает тело секрета (без padding-«=»): %v", err)
		}
	})
}

func TestEOL(t *testing.T) {
	if got := wgconf.EOL("a\r\nb\r\n"); got != "\r\n" {
		t.Errorf("EOL для CRLF = %q", got)
	}
	if got := wgconf.EOL("a\nb\n"); got != "\n" {
		t.Errorf("EOL для LF = %q", got)
	}
	if got := wgconf.EOL("однострочник без перевода"); got != "\n" {
		t.Errorf("EOL по умолчанию = %q, ожидалось \\n", got)
	}
}
