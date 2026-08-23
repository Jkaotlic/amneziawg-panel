//go:build readonly

package main

import (
	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/web"
)

// newServer в read-only сборке отдаёт сервер без мутаторов: подставить в
// него нечего — web.MutatorRegistry здесь пустой интерфейс, обработчиков
// мутаций в бинаре нет.
func newServer(cfg *config.Config, reg *issuer.Registry) *web.Server {
	return web.NewServer(cfg, web.Adapt(reg))
}
