package runtime

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

// Fake — Runner поверх текста конфига в памяти. Ведёт себя как живое
// устройство: syncconf заменяет состояние содержимым переданного файла,
// show строит dump из этого состояния.
//
// Поля Fault* моделируют те самые молчаливые отказы, ради которых
// существует проверка постусловия: применение может «потерять»
// device-параметр, сбросить handshake или потерять пира, вернув успех.
type Fake struct {
	Conf       string           // текущее состояние УСТРОЙСТВА в формате конфига
	ConfPath   string           // путь к ФАЙЛУ конфига; из него читает Strip
	Calls      []string         // журнал вызовов
	Handshakes map[string]int64 // публичный ключ → последний handshake
	// Counters — публичный ключ → накопленный rx. ВНИМАНИЕ: растёт на каждый
	// вызов Show, а не на реальное событие трафика (см. инкремент в Show).
	// Поэтому рост Counters между двумя снимками НЕЛЬЗЯ использовать как
	// признак «туннель жив»/«применение прошло успешно» в проверке
	// постусловия: он будет расти одинаково и при здоровом состоянии, и при
	// сработавшей порче — это ложный сигнал успеха, а не свидетельство.
	Counters map[string]int64

	FaultDropDeviceKey   string // при syncconf выбросить этот ключ из [Interface]
	FaultResetHandshakes bool   // при syncconf обнулить все handshake
	FaultDropPeer        string // при syncconf не применять пира с этим ключом
	FaultSyncErr         error  // syncconf возвращает эту ошибку
	// FaultChangePeerPSK — при syncconf молча подменить PresharedKey у
	// существующего пира с этим публичным ключом на случайный. Моделирует
	// расхождение, которое не меняет ни присутствие пира, ни allowed-ips, ни
	// handshake активной сессии (она продолжает жить на старом PSK) — клиент
	// умирает только на следующем rekey, то есть без этой проверки постусловие
	// его не поймает вообще.
	FaultChangePeerPSK string
}

func NewFake(conf string) *Fake {
	f := &Fake{Conf: conf, Handshakes: map[string]int64{}, Counters: map[string]int64{}}
	if c, err := wgconf.Parse(conf); err == nil {
		for _, p := range c.Peers {
			f.Handshakes[p.Get("PublicKey")] = 1754049600
		}
	}
	return f
}

func (f *Fake) Show(iface string) (string, error) {
	f.Calls = append(f.Calls, "show "+iface)
	c, err := wgconf.Parse(f.Conf)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s\tfake-server-pub\t%s\toff\n",
		c.Interface.Get("PrivateKey"), c.Interface.Get("ListenPort"))
	for _, p := range c.Peers {
		pub := p.Get("PublicKey")
		// Растёт от числа вызовов Show, а не от реального трафика — см.
		// предупреждение над полем Counters. Не использовать как признак
		// живости в проверках постусловия.
		f.Counters[pub] += 1000
		psk := p.Get("PresharedKey")
		if psk == "" {
			psk = "(none)"
		}
		fmt.Fprintf(&b, "%s\t%s\t(none)\t%s\t%d\t%d\t%d\toff\n",
			pub, psk, p.Get("AllowedIPs"), f.Handshakes[pub], f.Counters[pub], f.Counters[pub]/2)
	}
	return b.String(), nil
}

func (f *Fake) ShowConf(iface string) (string, error) {
	f.Calls = append(f.Calls, "showconf "+iface)
	return f.stripped(f.Conf), nil
}

// Strip читает ФАЙЛ конфига, а не состояние устройства — ровно как настоящий
// awg-quick strip. Разница принципиальна: после отката файла из бэкапа
// повторный syncconf обязан вернуть устройство к исходному состоянию, и это
// работает только потому, что strip берёт данные из файла. Фейк, читающий
// здесь состояние устройства, сделал бы тест на откат бессодержательным.
func (f *Fake) Strip(iface string) (string, error) {
	f.Calls = append(f.Calls, "strip "+iface)
	src := f.Conf
	if f.ConfPath != "" {
		b, err := os.ReadFile(f.ConfPath)
		if err != nil {
			return "", err
		}
		src = string(b)
	}
	return f.stripped(src), nil
}

// stripped повторяет поведение awg-quick strip: убирает только
// Address, MTU, DNS, Table, SaveConfig и Pre/Post-хуки. Всё остальное,
// включая S1..S4, H1..H4 и HeaderProtectionKey, остаётся и применяется —
// в этом и состоит опасность, которую сторожит постусловие.
func (f *Fake) stripped(conf string) string {
	drop := map[string]bool{
		"address": true, "mtu": true, "dns": true, "table": true,
		"saveconfig": true, "preup": true, "postup": true,
		"predown": true, "postdown": true,
	}
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && drop[strings.ToLower(strings.TrimSpace(key))] {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func (f *Fake) SyncConf(iface, path string) error {
	f.Calls = append(f.Calls, "syncconf "+iface+" "+path)
	if f.FaultSyncErr != nil {
		return f.FaultSyncErr
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	// Состояние устройства заменяется содержимым пушимого конфига ЦЕЛИКОМ, в
	// том числе для [Interface]: device-поле, отсутствующее во входных данных,
	// syncconf СБРАСЫВАЕТ. Это измерено живым экспериментом на полигоне nl2,
	// AmneziaWG v3.0.20260730 (находка 3 выката):
	//
	//	awg set awg3 fwmark 42     -> awg show awg3 fwmark = 0x2a
	//	awg-quick strip awg3 > tmp -> в strip 10 полей обфускации, 0 wg-quick-директив
	//	awg syncconf awg3 tmp      -> rc=0
	//	awg show awg3 fwmark       -> off
	//
	// Прежняя редакция моделировала ОБРАТНОЕ («поле вне входных данных не
	// обнуляется») и опиралась на понимание протокола IPC, а не на измерение;
	// риск был честно записан в журнале Task 8 словами «если допущение
	// неверно, фейк маскирует реальное расхождение» — так и вышло. Никакого
	// слияния секций здесь больше нет: и пиры, и [Interface] заменяются
	// полностью, ровно как на живом устройстве. См.
	// TestFakeSyncConfResetsDeviceOnlyFieldsAbsentFromPushedConf.
	next := string(b)
	if f.FaultDropDeviceKey != "" {
		var kept []string
		for _, line := range strings.Split(next, "\n") {
			key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
			if ok && strings.EqualFold(strings.TrimSpace(key), f.FaultDropDeviceKey) {
				continue
			}
			kept = append(kept, line)
		}
		next = strings.Join(kept, "\n")
	}
	if f.FaultDropPeer != "" {
		stripped, err := wgconf.RemovePeerByPublicKey(next, f.FaultDropPeer)
		if err != nil {
			// Молчаливый промах здесь недопустим: если ключ не найден, инъекция
			// отказа не сработала, а тест, построенный поверх неё, отрапортовал
			// бы об успехе, ни разу не проверив тот сценарий, который якобы
			// проверяет. Громкий отказ честнее тихого притворного успеха.
			return fmt.Errorf("FaultDropPeer: пир с ключом %q не найден в применяемом конфиге: %w",
				f.FaultDropPeer, err)
		}
		next = stripped
	}
	if f.FaultChangePeerPSK != "" {
		changed, err := replacePeerPSK(next, f.FaultChangePeerPSK)
		if err != nil {
			// Тот же принцип, что и у FaultDropPeer выше: если пир не найден,
			// инъекция отказа тихо не сработала бы, а тест решил бы, что
			// проверил сценарий смены PSK, хотя не проверил ничего.
			return fmt.Errorf("FaultChangePeerPSK: %w", err)
		}
		next = changed
	}
	f.Conf = next
	c, err := wgconf.Parse(next)
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, p := range c.Peers {
		pub := p.Get("PublicKey")
		live[pub] = true
		if _, seen := f.Handshakes[pub]; !seen {
			f.Handshakes[pub] = 0 // новый пир ещё ни разу не подключался
		}
		if f.FaultResetHandshakes {
			f.Handshakes[pub] = 0
		}
	}
	for pub := range f.Handshakes {
		if !live[pub] {
			delete(f.Handshakes, pub)
		}
	}
	return nil
}

func (f *Fake) GenKey() (string, error) { return randKey(), nil }
func (f *Fake) GenPSK() (string, error) { return randKey(), nil }

func (f *Fake) PubKey(priv string) (string, error) {
	if priv == "" {
		return "", fmt.Errorf("пустой приватный ключ")
	}
	// PubKey — часть контракта Runner и обязан возвращать ошибку, как это
	// делает execRunner, а не паниковать: priv[:8] ниже требует длину не
	// короче 8 байт.
	if len(priv) < 8 {
		return "", fmt.Errorf("приватный ключ короче 8 символов: длина %d", len(priv))
	}
	// Детерминированное производное значение — достаточно для тестов.
	return "pub-" + priv[:8], nil
}

func randKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// replacePeerPSK подменяет строку PresharedKey строго внутри блока пира с
// данным публичным ключом, не трогая остальные поля этого пира или любые
// другие секции. Используется FaultChangePeerPSK для имитации syncconf,
// который меняет PSK существующему пиру, не удаляя и не пересоздавая его.
func replacePeerPSK(conf, publicKey string) (string, error) {
	c, err := wgconf.Parse(conf)
	if err != nil {
		return "", err
	}
	sec, ok := wgconf.FindPeer(c, publicKey)
	if !ok {
		return "", fmt.Errorf("пир с ключом %q не найден в применяемом конфиге", publicKey)
	}
	block := sec.Bytes(conf)
	var out []string
	changed := false
	for _, line := range strings.Split(block, "\n") {
		key, _, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "PresharedKey") {
			out = append(out, "PresharedKey = "+randKey())
			changed = true
			continue
		}
		out = append(out, line)
	}
	if !changed {
		return "", fmt.Errorf("у пира с ключом %q нет PresharedKey", publicKey)
	}
	return conf[:sec.StartByte] + strings.Join(out, "\n") + conf[sec.EndByte:], nil
}
