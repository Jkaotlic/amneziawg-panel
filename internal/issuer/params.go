package issuer

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/store"
)

// EffectiveClient — итоговый набор клиентских параметров одного пира после
// слияния умолчаний интерфейса (store.Defaults) с его персональными
// оверрайдами (store.Overrides). Это вход для сборки ClientParams в
// RenderClientConfig, а не отдельный источник правды: конфиг всегда
// собирается заново из Effective(...), файла с застывшим результатом нет
// (раздел 5.2 спеки).
type EffectiveClient struct {
	Endpoint       string
	AllowedIPs     string
	Keepalive      string
	DNS            string
	MTU            string
	Jc, Jmin, Jmax int
	Extra          map[string]string
}

// Effective накладывает персональные оверрайды пира на умолчания интерфейса.
// MTU по умолчанию берётся у сервера: клиент, чей MTU больше серверного,
// молча теряет крупные пакеты, и заметно это становится не на ping, а на
// загрузке страниц.
func Effective(d store.Defaults, o *store.Overrides, serverMTU string) EffectiveClient {
	e := EffectiveClient{
		Endpoint: d.Endpoint, AllowedIPs: d.AllowedIPs, Keepalive: d.Keepalive,
		DNS: d.DNS, MTU: serverMTU, Jc: d.Jc, Jmin: d.Jmin, Jmax: d.Jmax,
		Extra: map[string]string{},
	}
	for k, v := range d.Extra {
		e.Extra[k] = v
	}
	if o == nil {
		return e
	}
	setStr(&e.Endpoint, o.Endpoint)
	setStr(&e.AllowedIPs, o.AllowedIPs)
	setStr(&e.Keepalive, o.Keepalive)
	setStr(&e.DNS, o.DNS)
	setStr(&e.MTU, o.MTU)
	setInt(&e.Jc, o.Jc)
	setInt(&e.Jmin, o.Jmin)
	setInt(&e.Jmax, o.Jmax)
	// Extra пира заменяет карту умолчаний ЦЕЛИКОМ, а не сливается по ключам:
	// частичное слияние оставило бы пиру поле, которое оператор снял в
	// умолчаниях, и объяснить такое поведение в UI невозможно.
	if o.Extra != nil {
		e.Extra = map[string]string{}
		for k, v := range o.Extra {
			e.Extra[k] = v
		}
	}
	return e
}

func setStr(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

func setInt(dst *int, src *int) {
	if src != nil {
		*dst = *src
	}
}

// knownClientKeys — поля, у которых в конфиге есть своё место. Их дубль в
// extra дал бы две строки одного ключа с неопределённым приоритетом у
// клиента, поэтому отвергается.
var knownClientKeys = map[string]bool{
	"privatekey": true, "address": true, "dns": true, "mtu": true,
	"publickey": true, "presharedkey": true, "endpoint": true,
	"allowedips": true, "persistentkeepalive": true,
	"jc": true, "jmin": true, "jmax": true,
	"s1": true, "s2": true, "s3": true, "s4": true,
	"h1": true, "h2": true, "h3": true, "h4": true,
	"headerprotectionkey": true, "contentpaddingaddition": true,
}

// ValidateExtra проверяет карту дополнительных client-side полей. Её
// содержимое печатается прямо в файл конфига, поэтому проверка отвергает, а
// не экранирует: экранировать в ini-подобном формате нечего, а перевод
// строки в значении — это дописанная строка в чужой секции.
func ValidateExtra(m map[string]string) error {
	for k, v := range m {
		if !extraKeyRe.MatchString(k) {
			return fmt.Errorf("%w: имя поля %q недопустимо: ожидается буква, затем до 15 букв и цифр",
				ErrInvalidInput, k)
		}
		if knownClientKeys[strings.ToLower(k)] {
			return fmt.Errorf("%w: поле %s задаётся отдельным параметром, а не через extra",
				ErrInvalidInput, k)
		}
		if err := rejectInjection(k, v); err != nil {
			return err
		}
		if strings.TrimSpace(v) != v {
			return fmt.Errorf("%w: значение поля %s содержит пробелы по краям", ErrInvalidInput, k)
		}
		if v == "" {
			return fmt.Errorf("%w: значение поля %s пусто — уберите поле вместо пустого значения",
				ErrInvalidInput, k)
		}
	}
	return nil
}

// rejectInjection отклоняет значение, способное вставить строку в чужую
// секцию печатаемого конфига: перевод строки заканчивает текущую строку
// параметра раньше времени, а квадратные скобки — заголовок секции. Общая
// проверка для extra (ValidateExtra) и для dns/allowed_ips/keepalive/endpoint
// в ValidateOverrides/ValidateDefaults: все они печатаются в тот же файл тем
// же способом (issuer.RenderClientConfig, функция line), и то, что раньше
// эту проверку проходили только элементы карты extra, было случайностью
// адресации кода, а не сознательной границей доверия (находка финального
// ревью, I2) — "dns: \"1.1.1.1\nPostUp = ...\"" и "endpoint" с переводом
// строки проходили ValidateOverrides и печатались в клиентский конфиг
// готовой второй строкой.
func rejectInjection(field, v string) error {
	if strings.ContainsAny(v, "\r\n[]") {
		return fmt.Errorf("%w: значение поля %s содержит перевод строки или скобки", ErrInvalidInput, field)
	}
	return nil
}

var extraKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,15}$`)

// ValidateOverrides проверяет персональные оверрайды пира перед сохранением
// в peers.json. Полная проверка тройки Jc/Jmin/Jmax (частичность заданности,
// Jmin < Jmax) сюда сознательно не входит: на уровне одних оверрайдов
// неизвестно, унаследует ли итоговый набор недостающие члены тройки из
// умолчаний интерфейса, — эту проверку по факту слияния делает
// RenderClientConfig. Здесь отвергается то, что негодно вне зависимости от
// умолчаний, с которыми оверрайд сольётся.
func ValidateOverrides(o *store.Overrides) error {
	if o == nil {
		return nil
	}
	if err := ValidateExtra(o.Extra); err != nil {
		return err
	}
	// dns/allowed_ips/keepalive/endpoint печатаются в клиентский конфиг тем
	// же способом, что и extra (issuer.RenderClientConfig, функция line), но
	// раньше эту проверку проходили только элементы карты extra — находка
	// финального ревью I2: "dns: \"1.1.1.1\nPostUp = touch /tmp/pwned\"" и
	// endpoint с переводом строки проходили ValidateOverrides и печатались в
	// клиентский конфиг готовой второй строкой.
	for _, f := range []struct {
		name string
		v    *string
	}{
		{"dns", o.DNS}, {"allowed_ips", o.AllowedIPs}, {"keepalive", o.Keepalive}, {"endpoint", o.Endpoint},
	} {
		if f.v == nil {
			continue
		}
		if err := rejectInjection(f.name, *f.v); err != nil {
			return err
		}
	}
	// allowed_ips, явно заданный оверрайдом пустым, — не то же самое, что "не
	// задан" (для наследования умолчания указатель остаётся nil, а не
	// становится указателем на ""). issuer.RenderClientConfig печатает
	// AllowedIPs, только когда строка непуста, поэтому явно пустой оверрайд
	// не наследует умолчание, а обрывает клиенту маршрутизацию в туннель
	// целиком. У dns/keepalive пустая строка легальна ("явно ничего"), а у
	// allowed_ips — нет: соседняя ValidateDefaults то же самое поле уже
	// требовала непустым, и это расхождение между проверками — находка
	// финального ревью I2 (форма при этом ещё и предлагала пустой allowed_ips
	// галочкой — см. OVR_META в assets/index.html, там же и исправлено).
	if o.AllowedIPs != nil && *o.AllowedIPs == "" {
		return fmt.Errorf("%w: allowed_ips не может быть явно пустым — клиент не будет "+
			"заворачивать в туннель ничего", ErrInvalidInput)
	}
	if o.Endpoint != nil {
		if _, _, err := net.SplitHostPort(*o.Endpoint); err != nil {
			return fmt.Errorf("%w: endpoint %q не в формате адрес:порт: %v", ErrInvalidInput, *o.Endpoint, err)
		}
	}
	if o.MTU != nil {
		if err := validateMTU(*o.MTU); err != nil {
			return err
		}
	}
	return validateNonNegativeJitter(o.Jc, o.Jmin, o.Jmax)
}

// validateMTU проверяет MTU как строку из store: конфиг печатает MTU
// текстом, но допустимость определяется числовым диапазоном. 576 — минимум
// IPv4 согласно RFC 791, ниже которого гарантий доставки без фрагментации
// нет; 9000 — верхняя граница распространённых jumbo-кадров. Вне диапазона
// интерфейс с таким MTU либо не поднимется, либо будет фрагментировать
// пакеты в противоречии с самим смыслом настройки этого поля.
func validateMTU(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("%w: mtu %q не является целым числом", ErrInvalidInput, s)
	}
	if n < 576 || n > 9000 {
		return fmt.Errorf("%w: mtu %d вне диапазона 576..9000", ErrInvalidInput, n)
	}
	return nil
}

// validateNonNegativeJitter отвергает отрицательные параметры джиттера по
// отдельности, не требуя полноты тройки, — см. комментарий к ValidateOverrides.
func validateNonNegativeJitter(jc, jmin, jmax *int) error {
	if jc != nil && *jc < 0 {
		return fmt.Errorf("%w: jc не может быть отрицательным: %d", ErrInvalidInput, *jc)
	}
	if jmin != nil && *jmin < 0 {
		return fmt.Errorf("%w: jmin не может быть отрицательным: %d", ErrInvalidInput, *jmin)
	}
	if jmax != nil && *jmax < 0 {
		return fmt.Errorf("%w: jmax не может быть отрицательным: %d", ErrInvalidInput, *jmax)
	}
	return nil
}

// ValidateDefaults проверяет умолчания интерфейса перед сохранением в
// defaults.json. Те же проверки, что у ValidateOverrides (extra, формат
// Endpoint, неотрицательный джиттер), но без MTU — у Defaults такого поля
// нет: MTU интерфейса всегда берётся из живого серверного [Interface], а не
// из умолчаний (см. Effective). Endpoint и AllowedIPs здесь, в отличие от
// оверрайдов, обязаны быть непустыми: Defaults ничего не наследует, и
// пустое значение ушло бы в Effective как есть, а не как «не задано».
func ValidateDefaults(d store.Defaults) error {
	if err := ValidateExtra(d.Extra); err != nil {
		return err
	}
	// Симметрично ValidateOverrides — см. её комментарий (находка финального
	// ревью I2).
	for _, f := range []struct{ name, v string }{
		{"dns", d.DNS}, {"allowed_ips", d.AllowedIPs}, {"keepalive", d.Keepalive}, {"endpoint", d.Endpoint},
	} {
		if err := rejectInjection(f.name, f.v); err != nil {
			return err
		}
	}
	if d.Endpoint == "" {
		return fmt.Errorf("%w: endpoint не задан", ErrInvalidInput)
	}
	if _, _, err := net.SplitHostPort(d.Endpoint); err != nil {
		return fmt.Errorf("%w: endpoint %q не в формате адрес:порт: %v", ErrInvalidInput, d.Endpoint, err)
	}
	if d.AllowedIPs == "" {
		return fmt.Errorf("%w: allowed_ips не задан", ErrInvalidInput)
	}
	return validateNonNegativeJitter(&d.Jc, &d.Jmin, &d.Jmax)
}
