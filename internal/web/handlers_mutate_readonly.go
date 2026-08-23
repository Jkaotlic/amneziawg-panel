//go:build readonly

package web

import "net/http"

// PeerMutator в read-only сборке не имеет методов: подставить в сервер
// нечего, обработчиков мутаций в бинаре физически нет (раздел 12.1 спеки).
// NewServerWithMutator в этой сборке тоже не существует — единственный
// конструктор, NewServer, оставляет поле mutators нулевым навсегда.
type PeerMutator interface{}

// MutatorRegistry пуст по той же причине, что и PeerMutator выше: read-only
// сборке нечем удовлетворить ни один из его методов в полной сборке,
// потому что вызывать у отданного мутатора всё равно нечего. Пустая
// структура удовлетворяет пустому интерфейсу — компиляционное доказательство
// отсутствия символов мутации в бинаре (см. readonly_test.go).
type MutatorRegistry interface{}

func (s *Server) registerMutations(mux *http.ServeMux) {}

// ReadOnlyBuild сообщает, собран ли бинарь без обработчиков мутаций.
const ReadOnlyBuild = true
