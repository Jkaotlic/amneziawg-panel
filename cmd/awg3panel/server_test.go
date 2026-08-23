package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"github.com/Jkaotlic/awg3-panel/internal/runtime"
	"github.com/Jkaotlic/awg3-panel/internal/web"
	"golang.org/x/crypto/bcrypt"
)

// TestNewServerMatchesBuildFlavour проверяет проводку точки входа: в полной
// сборке сервис обязан быть подставлен мутатором (страница не показывает
// плашку «режим только чтения»), в read-only — не подставлен. Забытый
// аргумент в newServer иначе дал бы молча читающую панель в полной сборке —
// внешне рабочую, без единой ошибки компиляции.
//
// Одно утверждение покрывает обе сборки: признак берётся из того же
// web.ReadOnlyBuild, по которому разведены файлы server_full.go и
// server_readonly.go.
func TestNewServerMatchesBuildFlavour(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	// Страница индекса не обращается ни к конфигу awg, ни к устройству —
	// фейкового runner'а с пустым состоянием достаточно.
	reg := issuer.NewRegistry(cfg, func(binDir string) runtime.Runner { return runtime.NewFake("") })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	rec := httptest.NewRecorder()
	newServer(cfg, reg).Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("код = %d, тело: %s", rec.Code, rec.Body)
	}
	readOnlyPage := strings.Contains(rec.Body.String(), "режим только чтения")
	if readOnlyPage != web.ReadOnlyBuild {
		t.Errorf("страница в режиме только чтения = %v, а сборка read-only = %v — "+
			"точка входа подставила не тот сервер", readOnlyPage, web.ReadOnlyBuild)
	}
}
