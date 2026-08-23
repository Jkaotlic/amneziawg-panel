package web_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// doAuthed выполняет аутентифицированный запрос к тестовому серверу. body
// — io.Reader, а не строка (задача 10): часть новых тестов шлёт nil (GET/
// POST без тела), часть — strings.NewReader(json) с телом мутации, и один
// общий хелпер на оба случая проще, чем пара похожих функций.
func doAuthed(t *testing.T, h http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = "10.0.0.2:40000"
	req.SetBasicAuth("admin", "секрет")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
