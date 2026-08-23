package issuer_test

import (
	"bytes"
	"image/png"
	"os"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

const serverConf = `[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = c2VydmVyLXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9
MTU = 1280
S1 = 17
S2 = 21
S3 = 16
S4 = 12
H1 = 1633177
H2 = 2114993
H3 = 1287653
H4 = 1955441
HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0=
ContentPaddingAddition = 0-96
`

func serverIface(t *testing.T, body string) *wgconf.Section {
	t.Helper()
	c, err := wgconf.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	return c.Interface
}

func TestExtractObfuscationTakesAllV3Fields(t *testing.T) {
	got, err := issuer.ExtractObfuscation(serverIface(t, serverConf))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range issuer.RequiredObfuscationKeys {
		if got[k] == "" {
			t.Errorf("поле %s не извлечено", k)
		}
	}
	if got["S1"] != "17" || got["H4"] != "1955441" {
		t.Errorf("значения искажены: %v", got)
	}
}

// Главный страховочный тест: пропущенное v3-поле даёт молчаливый отказ
// подключения на стороне клиента (0 B received). Ловим это на выпуске.
func TestExtractObfuscationFailsLoudlyOnMissingField(t *testing.T) {
	body := strings.Replace(serverConf, "HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LWZha2UtMDAwMDAwMD0=\n", "", 1)
	_, err := issuer.ExtractObfuscation(serverIface(t, body))
	if err == nil {
		t.Fatal("ожидалась ошибка: без HeaderProtectionKey клиент не подключится")
	}
	if !strings.Contains(err.Error(), "HeaderProtectionKey") {
		t.Errorf("ошибка не называет недостающее поле: %v", err)
	}
}

// Fix round 1, находка 2: тест с ОДНИМ недостающим полем не отличает
// накопление всех недостающих ключей от отказа на первом же промахе — при
// единственном пропуске оба поведения дают одинаковый результат. Убираем
// два поля сразу: если бы ExtractObfuscation останавливалась на первом
// промахе, оператор чинил бы конфиг по одному полю за прогон и ходил бы по
// кругу столько раз, сколько полей забыл.
func TestExtractObfuscationNamesAllMissingFieldsAtOnce(t *testing.T) {
	body := serverConf
	body = strings.Replace(body, "H3 = 1287653\n", "", 1)
	body = strings.Replace(body, "ContentPaddingAddition = 0-96\n", "", 1)
	_, err := issuer.ExtractObfuscation(serverIface(t, body))
	if err == nil {
		t.Fatal("ожидалась ошибка: без H3 и ContentPaddingAddition клиент не подключится")
	}
	for _, want := range []string{"H3", "ContentPaddingAddition"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ошибка не называет недостающее поле %s целиком: %v", want, err)
		}
	}
}

func params(t *testing.T) issuer.ClientParams {
	t.Helper()
	obf, err := issuer.ExtractObfuscation(serverIface(t, serverConf))
	if err != nil {
		t.Fatal(err)
	}
	return issuer.ClientParams{
		PrivateKey:      "Y2xpZW50LXByaXZhdGUta2V5LWZha2UtMDAwMDAwMDAwMDA9",
		Address:         "10.0.0.4/32",
		ServerPublicKey: "c2VydmVyLXB1YmxpYy1rZXktZmFrZS0wMDAwMDAwMDAwMD0=",
		PresharedKey:    "cHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=",
		Endpoint:        "203.0.113.10:51820",
		AllowedIPs:      "0.0.0.0/0",
		Keepalive:       "22-30",
		MTU:             "1280",
		Obfuscation:     obf,
	}
}

// render — обёртка над RenderClientConfig для тестов, где на входе заведомо
// валидные параметры и ошибка означает поломку теста, а не проверяемое
// поведение.
func render(t *testing.T, p issuer.ClientParams) string {
	t.Helper()
	out, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatalf("RenderClientConfig вернула ошибку на валидных параметрах: %v", err)
	}
	return out
}

func TestRenderClientConfigMatchesGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/client_golden.conf")
	if err != nil {
		t.Fatal(err)
	}
	got := render(t, params(t))
	if got != string(want) {
		t.Errorf("конфиг разошёлся с эталоном.\nПолучено:\n%s\nЭталон:\n%s", got, want)
	}
}

func TestRenderClientConfigIsParseable(t *testing.T) {
	c, err := wgconf.Parse(render(t, params(t)))
	if err != nil {
		t.Fatalf("выданный конфиг не разбирается: %v", err)
	}
	if len(c.Peers) != 1 {
		t.Fatalf("пиров в клиентском конфиге %d, ожидался 1", len(c.Peers))
	}
	if c.Peers[0].Get("Endpoint") != "203.0.113.10:51820" {
		t.Errorf("Endpoint = %q", c.Peers[0].Get("Endpoint"))
	}
}

// Обфускация клиента обязана совпасть с серверной байт в байт,
// иначе туннель просто не поднимется.
func TestClientObfuscationEqualsServer(t *testing.T) {
	srv := serverIface(t, serverConf)
	c, err := wgconf.Parse(render(t, params(t)))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range issuer.RequiredObfuscationKeys {
		if got, want := c.Interface.Get(k), srv.Get(k); got != want {
			t.Errorf("%s: клиент %q, сервер %q", k, got, want)
		}
	}
}

func TestRenderOmitsEmptyDNSAndJc(t *testing.T) {
	out := render(t, params(t))
	if strings.Contains(out, "DNS") {
		t.Error("пустой DNS не должен попадать в конфиг — он конфликтует с AGH в домашней сети")
	}
	if strings.Contains(out, "Jc") {
		t.Error("Jc = 0 не должен попадать в конфиг")
	}
}

func TestRenderIncludesJcWhenSet(t *testing.T) {
	p := params(t)
	p.Jc, p.Jmin, p.Jmax = 4, 40, 70
	p.DNS = "1.1.1.1"
	out := render(t, p)
	for _, want := range []string{"Jc = 4", "Jmin = 40", "Jmax = 70", "DNS = 1.1.1.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("в конфиге нет %q:\n%s", want, out)
		}
	}
}

func TestQRPNGIsValidImage(t *testing.T) {
	data, err := issuer.QRPNG(render(t, params(t)))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("QR не является корректным PNG: %v", err)
	}
	if img.Bounds().Dx() < 256 {
		t.Errorf("ширина QR = %d, слишком мелко для сканирования телефоном", img.Bounds().Dx())
	}
}

// Fix round 1, находка 1: RenderClientConfig — последний рубеж перед тем,
// как байты уедут пользователю. Если Obfuscation собрана в обход
// ExtractObfuscation (например, вручную или из повреждённого состояния) и
// неполна, функция обязана отказать, а не тихо выпустить конфиг без части
// S1..S4/H1..H4/HeaderProtectionKey/ContentPaddingAddition — именно такой
// файл клиент примет и не подключится молча (0 B received при растущем
// sent, без единого признака причины).
func TestRenderClientConfigFailsOnPartialObfuscation(t *testing.T) {
	p := params(t)
	// Копируем карту, чтобы удаление ключа не задело общие данные других тестов.
	partial := make(map[string]string, len(p.Obfuscation))
	for k, v := range p.Obfuscation {
		partial[k] = v
	}
	delete(partial, "H3")
	p.Obfuscation = partial

	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при неполной Obfuscation, а получен конфиг:\n%s", out)
	}
	if !strings.Contains(err.Error(), "H3") {
		t.Errorf("ошибка не называет недостающее поле H3: %v", err)
	}
}

func TestRenderClientConfigFailsOnNilObfuscation(t *testing.T) {
	p := params(t)
	p.Obfuscation = nil
	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при nil Obfuscation, а получен конфиг:\n%s", out)
	}
}

// Fix round 1, находка 3: Jc/Jmin/Jmax подавлялись независимо друг от
// друга по условию v > 0, поэтому ClientParams{Jc: 4} с нулевыми
// Jmin/Jmax тихо рендерил одинокую строку "Jc = 4" без границ диапазона.
// Настоящий AmneziaWG требует Jmin < Jmax и осмысленный диапазон размеров
// джиттер-пакетов — частично заданная тройка не то, что клиент способен
// применить осмысленно. Решение: тройка задаётся целиком или не задаётся
// вовсе, иначе — явная ошибка конфигурации.
func TestRenderClientConfigFailsOnPartialJitterTriple(t *testing.T) {
	p := params(t)
	p.Jc = 4 // Jmin, Jmax остаются нулевыми
	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при частично заданной тройке Jc/Jmin/Jmax, а получен конфиг:\n%s", out)
	}
}

func TestRenderClientConfigAcceptsFullJitterTriple(t *testing.T) {
	p := params(t)
	p.Jc, p.Jmin, p.Jmax = 4, 40, 70
	if _, err := issuer.RenderClientConfig(p); err != nil {
		t.Fatalf("полностью заданная тройка Jc/Jmin/Jmax не должна давать ошибку: %v", err)
	}
}

func TestRenderClientConfigAcceptsZeroJitterTriple(t *testing.T) {
	p := params(t)
	p.Jc, p.Jmin, p.Jmax = 0, 0, 0
	if _, err := issuer.RenderClientConfig(p); err != nil {
		t.Fatalf("полностью нулевая тройка Jc/Jmin/Jmax (джиттер выключен) не должна давать ошибку: %v", err)
	}
}

// Fix round 2, находка (a): проверка «задано» в jitterTripleErr использовала
// условие v != 0, а рендер печатает поле по условию v > 0. Из-за расхождения
// Jc = -1 проходил проверку «все три ненулевые» (allSet = true, ошибки нет),
// но не печатался в файл (-1 не больше нуля) — частичная тройка уходила в
// конфиг без единой ошибки. Отрицательные значения джиттера бессмысленны и
// теперь отвергаются явно, вне зависимости от того, что стоит рядом.
func TestRenderClientConfigFailsOnNegativeJitterValue(t *testing.T) {
	p := params(t)
	p.Jc, p.Jmin, p.Jmax = -1, 40, 70
	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при отрицательном Jc, а получен конфиг:\n%s", out)
	}
}

// Fix round 2, находка (b): комментарий к полям ClientParams заявлял, что
// требуется Jmin < Jmax, но код это не проверял — перевёрнутый диапазон
// проходил молча. Настоящий клиент AmneziaWG таким диапазоном junk-пакетов
// не воспользуется осмысленно, поэтому проверка приведена в соответствие с
// комментарием, а не наоборот.
func TestRenderClientConfigFailsOnInvertedJitterRange(t *testing.T) {
	p := params(t)
	p.Jc, p.Jmin, p.Jmax = 4, 70, 40 // Jmin > Jmax
	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при Jmin > Jmax, а получен конфиг:\n%s", out)
	}
}

// Граница: Jmin == Jmax тоже не даёт осмысленного диапазона размеров
// (единственный допустимый размер junk-пакета), протокол требует строгое
// неравенство — проверяем именно строгость (>=), а не просто "разные".
func TestRenderClientConfigFailsOnEqualJitterRange(t *testing.T) {
	p := params(t)
	p.Jc, p.Jmin, p.Jmax = 4, 50, 50
	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при Jmin == Jmax, а получен конфиг:\n%s", out)
	}
}
