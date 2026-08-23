package issuer_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// strp и intp собирают указатель на литерал прямо в табличных тестах:
// store.Overrides различает «поле не задано» и «поле задано» через nil,
// поэтому даже разовое значение в тесте нужно адресовать.
func strp(s string) *string { return &s }
func intp(n int) *int       { return &n }

func TestEffectiveInheritsAndOverrides(t *testing.T) {
	d := store.Defaults{Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0",
		Keepalive: "22-30", DNS: "", Jc: 0}
	dns := "10.0.0.1"
	mtu := "1380"
	e := issuer.Effective(d, &store.Overrides{DNS: &dns, MTU: &mtu}, "1280")
	if e.Endpoint != "1.2.3.4:51820" || e.AllowedIPs != "0.0.0.0/0" || e.Keepalive != "22-30" {
		t.Fatalf("незаданные поля обязаны наследоваться: %+v", e)
	}
	if e.DNS != "10.0.0.1" {
		t.Fatalf("DNS = %q, ожидался оверрайд", e.DNS)
	}
	if e.MTU != "1380" {
		t.Fatalf("MTU = %q: оверрайд обязан побеждать MTU сервера", e.MTU)
	}
}

func TestEffectiveEmptyOverrideBeatsNonEmptyDefault(t *testing.T) {
	empty := ""
	e := issuer.Effective(store.Defaults{DNS: "1.1.1.1"}, &store.Overrides{DNS: &empty}, "1280")
	if e.DNS != "" {
		t.Fatalf("DNS = %q: явно пустой оверрайд обязан отменить умолчание", e.DNS)
	}
}

func TestEffectiveTakesServerMTUWhenNotOverridden(t *testing.T) {
	e := issuer.Effective(store.Defaults{}, nil, "1280")
	if e.MTU != "1280" {
		t.Fatalf("MTU = %q, ожидался MTU сервера", e.MTU)
	}
}

// Правка результата Effective не должна быть видна вызывающему: задача 2
// отметила отложенной находкой, что Defaults копируется поверхностно и
// делит карту Extra с вызывающим. Этот тест — на случай, если реализация
// Effective когда-нибудь "упростится" до присваивания карты.
func TestEffectiveDefaultsExtraIsIndependentCopy(t *testing.T) {
	d := store.Defaults{Extra: map[string]string{"I1": "aaa"}}
	e := issuer.Effective(d, nil, "1280")
	e.Extra["I1"] = "испорчено"
	e.Extra["I2"] = "добавлено"
	if d.Extra["I1"] != "aaa" {
		t.Fatalf("правка результата задела store.Defaults.Extra вызывающего: %v", d.Extra)
	}
	if len(d.Extra) != 1 {
		t.Fatalf("новый ключ результата протёк в карту умолчаний вызывающего: %v", d.Extra)
	}
}

func TestEffectiveOverridesExtraIsIndependentCopy(t *testing.T) {
	oExtra := map[string]string{"I2": "bbb"}
	o := &store.Overrides{Extra: oExtra}
	e := issuer.Effective(store.Defaults{}, o, "1280")
	e.Extra["I2"] = "испорчено"
	e.Extra["I3"] = "добавлено"
	if oExtra["I2"] != "bbb" {
		t.Fatalf("правка результата задела store.Overrides.Extra вызывающего: %v", oExtra)
	}
	if len(oExtra) != 1 {
		t.Fatalf("новый ключ результата протёк в карту оверрайдов вызывающего: %v", oExtra)
	}
}

func TestValidateExtraRejectsInjectionAndCollisions(t *testing.T) {
	cases := map[string]map[string]string{
		"перевод строки в значении": {"I1": "abc\nPrivateKey = x"},
		"скобка в значении":         {"I1": "[Peer]"},
		"пробел по краям":           {"I1": " abc"},
		"пустое имя":                {"": "abc"},
		"имя с дефисом":             {"I-1": "abc"},
		"имя начинается с цифры":    {"1I": "abc"},
		"слишком длинное имя":       {"Iaaaaaaaaaaaaaaaaaaaa": "abc"},
		"дублирует известное поле":  {"DNS": "1.1.1.1"},
		"дублирует MTU":             {"MTU": "1380"},
		"дублирует Jc":              {"Jc": "4"},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			if err := issuer.ValidateExtra(m); err == nil {
				t.Fatalf("%s: ожидалась ошибка", name)
			}
		})
	}
	if err := issuer.ValidateExtra(map[string]string{"I1": "<b 0xf1>", "Itime": "10"}); err != nil {
		t.Fatalf("законные поля отвергнуты: %v", err)
	}
}

// Кейсы "allowed_ips пуст"/"перевод строки в ..." — находка финального
// ревью I2: соседние с extra поля (dns/allowed_ips/keepalive/endpoint) не
// проверялись вовсе. allowed_ips: "" принимался и в выданном клиентском
// конфиге строка AllowedIPs пропадала совсем (issuer.RenderClientConfig
// печатает её только когда она непуста) — клиент переставал заворачивать в
// туннель хоть что-то. dns/keepalive/endpoint с переводом строки печатались
// в файл клиента как есть, как дописанная строка в чужой секции — тот же
// вектор, от которого защищает ValidateExtra, но соседние именованные поля
// эту защиту не проходили.
func TestValidateOverridesRejectsInvalidFields(t *testing.T) {
	cases := map[string]*store.Overrides{
		"endpoint без порта":         {Endpoint: strp("1.2.3.4")},
		"endpoint не разбирается":    {Endpoint: strp("не-адрес-совсем")},
		"mtu не число":               {MTU: strp("jumbo")},
		"mtu меньше 576":             {MTU: strp("575")},
		"mtu больше 9000":            {MTU: strp("9001")},
		"отрицательный Jc":           {Jc: intp(-1)},
		"отрицательный Jmin":         {Jmin: intp(-1)},
		"отрицательный Jmax":         {Jmax: intp(-1)},
		"невалидный extra":           {Extra: map[string]string{"DNS": "1.1.1.1"}},
		"allowed_ips явно пуст":      {AllowedIPs: strp("")},
		"перевод строки в dns":       {DNS: strp("1.1.1.1\nPostUp = touch /tmp/pwned")},
		"скобка в allowed_ips":       {AllowedIPs: strp("0.0.0.0/0\n[Interface]")},
		"перевод строки в keepalive": {Keepalive: strp("25\nPostUp = touch /tmp/pwned")},
		"перевод строки в endpoint":  {Endpoint: strp("1.2.3.4\nPostUp = pwn:51820")},
	}
	for name, o := range cases {
		t.Run(name, func(t *testing.T) {
			err := issuer.ValidateOverrides(o)
			if err == nil {
				t.Fatalf("%s: ожидалась ошибка", name)
			}
			if !errors.Is(err, issuer.ErrInvalidInput) {
				t.Errorf("%s: ошибка не классифицирована как ErrInvalidInput: %v", name, err)
			}
		})
	}
}

func TestValidateOverridesAcceptsBoundaryValues(t *testing.T) {
	o := &store.Overrides{
		Endpoint: strp("1.2.3.4:51820"),
		MTU:      strp("576"), // нижняя граница диапазона MTU
		Jc:       intp(0), Jmin: intp(0), Jmax: intp(0),
		Extra: map[string]string{"I1": "abc"},
	}
	if err := issuer.ValidateOverrides(o); err != nil {
		t.Fatalf("валидные оверрайды отвергнуты: %v", err)
	}
	o.MTU = strp("9000") // верхняя граница диапазона MTU
	if err := issuer.ValidateOverrides(o); err != nil {
		t.Fatalf("MTU = 9000 (верхняя граница) отвергнут: %v", err)
	}
}

func TestValidateOverridesNilIsValid(t *testing.T) {
	// Вызывающий код (patch-обработчик) сам решает, звать ли валидацию,
	// когда оверрайдов нет вовсе; ValidateOverrides не обязан диктовать
	// это через панику на нулевом указателе — тот же контракт, что и у
	// Effective для этого же типа параметра.
	if err := issuer.ValidateOverrides(nil); err != nil {
		t.Fatalf("nil-оверрайды не должны считаться невалидными: %v", err)
	}
}

// Кейсы "перевод строки в ..." — та же находка I2, симметрично для умолчаний
// интерфейса: dns/allowed_ips/keepalive/endpoint прогоняются через ту же
// проверку на "\r\n[]", что и extra (см. комментарий у
// TestValidateOverridesRejectsInvalidFields).
func TestValidateDefaultsRejectsInvalidFields(t *testing.T) {
	cases := map[string]store.Defaults{
		"endpoint пуст":              {Endpoint: "", AllowedIPs: "0.0.0.0/0"},
		"endpoint без порта":         {Endpoint: "1.2.3.4", AllowedIPs: "0.0.0.0/0"},
		"allowed_ips пуст":           {Endpoint: "1.2.3.4:51820", AllowedIPs: ""},
		"отрицательный Jc":           {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Jc: -1},
		"отрицательный Jmin":         {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Jmin: -1},
		"отрицательный Jmax":         {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Jmax: -1},
		"невалидный extra":           {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Extra: map[string]string{"MTU": "1380"}},
		"перевод строки в dns":       {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", DNS: "1.1.1.1\nPostUp = touch /tmp/pwned"},
		"скобка в allowed_ips":       {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0\n[Interface]"},
		"перевод строки в keepalive": {Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Keepalive: "25\nPostUp = touch /tmp/pwned"},
		"перевод строки в endpoint":  {Endpoint: "1.2.3.4\nPostUp = pwn:51820", AllowedIPs: "0.0.0.0/0"},
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			err := issuer.ValidateDefaults(d)
			if err == nil {
				t.Fatalf("%s: ожидалась ошибка", name)
			}
			if !errors.Is(err, issuer.ErrInvalidInput) {
				t.Errorf("%s: ошибка не классифицирована как ErrInvalidInput: %v", name, err)
			}
		})
	}
}

func TestValidateDefaultsAcceptsValidInput(t *testing.T) {
	d := store.Defaults{
		Endpoint: "1.2.3.4:51820", AllowedIPs: "0.0.0.0/0", Keepalive: "22-30",
		DNS: "1.1.1.1", Jc: 4, Jmin: 40, Jmax: 70,
		Extra: map[string]string{"I1": "abc"},
	}
	if err := issuer.ValidateDefaults(d); err != nil {
		t.Fatalf("валидные умолчания отвергнуты: %v", err)
	}
}

// params — существующий хелпер тестов пакета (internal/issuer/client_test.go),
// возвращающий заведомо валидный issuer.ClientParams; брифом задачи назван
// validClientParams(t), но в пакете он один и называется params(t).
func TestRenderClientConfigPrintsExtraSorted(t *testing.T) {
	p := params(t) // существующий хелпер тестов пакета
	p.Extra = map[string]string{"Itime": "10", "I1": "<b 0xf1>"}
	out, err := issuer.RenderClientConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	i1 := strings.Index(out, "I1 = <b 0xf1>")
	it := strings.Index(out, "Itime = 10")
	if i1 < 0 || it < 0 {
		t.Fatalf("поля extra не напечатаны:\n%s", out)
	}
	if i1 > it {
		t.Fatal("порядок extra обязан быть детерминированным (сортировка по имени): " +
			"иначе один и тот же конфиг даёт разный QR при каждой выдаче")
	}
	// Секция клиента одна: extra не должна оказаться после [Peer].
	if strings.Index(out, "[Peer]") < i1 {
		t.Fatal("extra обязана печататься в [Interface] клиента, до [Peer]")
	}
}

// RenderClientConfig — последний рубеж перед выдачей файла пользователю
// (см. комментарий к ClientParams.Obfuscation), и Extra до него можно
// собрать в обход Effective/ValidateOverrides. Без своей проверки внутри
// самого RenderClientConfig карта с переводом строки в значении ушла бы в
// файл как дописанная строка в чужой секции — именно то, от чего защищает
// ValidateExtra.
func TestRenderClientConfigFailsOnInvalidExtra(t *testing.T) {
	p := params(t)
	p.Extra = map[string]string{"I1": "abc\n[Peer]\nPublicKey = evil"}
	out, err := issuer.RenderClientConfig(p)
	if err == nil {
		t.Fatalf("ожидалась ошибка при невалидном Extra, а получен конфиг:\n%s", out)
	}
	if !errors.Is(err, issuer.ErrInvalidInput) {
		t.Errorf("ошибка не классифицирована как ErrInvalidInput: %v", err)
	}
}
