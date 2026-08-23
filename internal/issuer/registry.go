package issuer

import (
	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
)

// IfaceMeta — то, что панель показывает про интерфейс, не заглядывая в его
// состояние: заголовок вкладки в UI, id для URL и CLI-флага --iface, и то,
// разрешена ли правка секции [Interface] (раздел 5.5 спеки). PendingActive
// заполняется задачей 14 (несохранённая правка [Interface], ждущая
// подтверждения); до неё всегда false.
type IfaceMeta struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Interface     string `json:"interface"`
	InterfaceEdit bool   `json:"interface_edit"`
	PendingActive bool   `json:"pending_active"`
}

// Registry хранит по Service на управляемый интерфейс. Порядок — тот же,
// что в config.yaml: он же порядок вкладок в UI и он же определяет
// интерфейс по умолчанию для CLI (Default возвращает первый).
type Registry struct {
	order []string
	byID  map[string]*Service
}

// NewRegistry строит Registry из конфига: по Service на каждый
// config.Interface. newRunner конструирует Runner для конкретного
// интерфейса из его bin_dir — разные интерфейсы могут указывать на разные
// сборки awg-инструментов, поэтому Runner не может быть общим на весь
// реестр.
func NewRegistry(cfg *config.Config, newRunner func(binDir string) runtime.Runner) *Registry {
	reg := &Registry{byID: map[string]*Service{}}
	for _, i := range cfg.Interfaces {
		reg.order = append(reg.order, i.ID)
		reg.byID[i.ID] = New(i, cfg.Listen, newRunner(i.BinDir))
	}
	return reg
}

// Metas возвращает описания всех интерфейсов в порядке config.yaml.
func (r *Registry) Metas() []IfaceMeta {
	out := make([]IfaceMeta, 0, len(r.order))
	for _, id := range r.order {
		s := r.byID[id]
		out = append(out, IfaceMeta{
			ID: s.iface.ID, Title: s.iface.Title, Interface: s.iface.Interface,
			InterfaceEdit: s.iface.InterfaceEdit,
		})
	}
	return out
}

// Lister и Mutator возвращают один и тот же *Service под разными именами не
// по недосмотру: web зависит от узких интерфейсов (PeerLister/PeerMutator,
// internal/web/server.go), и в read-only сборке Mutator не вызывается
// ниоткуда — обработчиков мутаций в таком бинаре физически нет (раздел 12.1
// спеки).
func (r *Registry) Lister(id string) (*Service, bool)  { s, ok := r.byID[id]; return s, ok }
func (r *Registry) Mutator(id string) (*Service, bool) { s, ok := r.byID[id]; return s, ok }

// Default возвращает Service первого интерфейса из config.yaml — то, что
// панель и CLI обслуживают, пока оператор явно не выбрал другой (--iface).
// nil, только если интерфейсов нет вовсе — недостижимо после config.Load:
// Validate отвергает пустой список (раздел 11 спеки).
func (r *Registry) Default() *Service {
	if len(r.order) == 0 {
		return nil
	}
	return r.byID[r.order[0]]
}

// All возвращает все сервисы реестра в порядке config.yaml.
func (r *Registry) All() []*Service {
	out := make([]*Service, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}
