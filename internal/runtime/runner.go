// Package runtime изолирует все побочные эффекты работы с AmneziaWG:
// вызовы awg и awg-quick. Всё, что выше по стеку, зависит только от
// интерфейса Runner, поэтому логика применения изменений тестируется
// без живого туннеля.
//
// Метода SetConf здесь нет и не должно появиться: awg setconf рвёт живые
// сессии, awg syncconf — нет (раздел 6.1 спеки).
package runtime

type Runner interface {
	// Show возвращает вывод `awg show <iface> dump`.
	Show(iface string) (string, error)
	// ShowConf возвращает вывод `awg showconf <iface>` — конфиг живого устройства.
	ShowConf(iface string) (string, error)
	// Strip возвращает вывод `awg-quick strip <iface>` — конфиг без
	// Address/MTU/PostUp/PostDown, пригодный для syncconf.
	Strip(iface string) (string, error)
	// SyncConf применяет конфиг из файла по пути path, не разрывая сессии.
	SyncConf(iface, path string) error
	GenKey() (string, error)
	GenPSK() (string, error)
	PubKey(priv string) (string, error)
}
