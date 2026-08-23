package web

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Jkaotlic/awg3-panel/internal/config"
	"github.com/Jkaotlic/awg3-panel/internal/issuer"
	"golang.org/x/crypto/bcrypt"
)

// blockingLister задерживается внутри обработчика, пока тест не разрешит ему
// завершиться — так моделируется долгая мутация (снимок → запись → syncconf →
// постусловие), посреди которой приходит сигнал остановки.
type blockingLister struct {
	entered chan struct{}
	release chan struct{}
}

func (b *blockingLister) List() ([]issuer.PeerView, error) {
	b.entered <- struct{}{}
	<-b.release
	return []issuer.PeerView{}, nil
}

// blockingRegistry — минимальная Registry вокруг blockingLister: тесту
// нужен ровно один интерфейс ("test"), чей List зависает до release
// (задача 10 перевела Server с одиночного PeerLister на Registry).
type blockingRegistry struct{ l PeerLister }

func (r blockingRegistry) Metas() []issuer.IfaceMeta {
	return []issuer.IfaceMeta{{ID: "test", Title: "test", Interface: "test"}}
}

func (r blockingRegistry) Lister(id string) (PeerLister, bool) {
	if id != "test" {
		return nil, false
	}
	return r.l, true
}

// TestServeFinishesInFlightRequestBeforeStopping: пока панель только читала,
// обрыв на SIGTERM стоил максимум одного GET. С мутациями сигнал может
// прийти между syncconf и проверкой постусловия — то есть в единственной
// точке, где откат ещё возможен, но ещё не начат. Сервер обязан дождаться
// уже начатого обработчика, а не рвать его вместе с процессом.
func TestServeFinishesInFlightRequestBeforeStopping(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("секрет"), 4)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Auth.User, cfg.Auth.Bcrypt = "admin", string(hash)
	bl := &blockingLister{entered: make(chan struct{}, 1), release: make(chan struct{})}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- NewServer(cfg, blockingRegistry{bl}).serve(ctx, ln) }()

	resps := make(chan *http.Response, 1)
	reqErrs := make(chan error, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, "http://"+ln.Addr().String()+"/api/ifaces/test/peers", nil)
		if err != nil {
			reqErrs <- err
			return
		}
		req.SetBasicAuth("admin", "секрет")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			reqErrs <- err
			return
		}
		resps <- resp
	}()

	select {
	case <-bl.entered: // обработчик реально начал работу
	case err := <-reqErrs:
		t.Fatalf("запрос не дошёл до обработчика: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("обработчик не начал работу")
	}

	cancel() // сигнал остановки ровно посреди обработки

	select {
	case err := <-served:
		t.Fatalf("serve вернулся, не дождавшись обработчика: %v", err)
	case <-time.After(200 * time.Millisecond):
		// Ожидаемо: остановка ждёт. Проверка направлена в безопасную
		// сторону — на медленной машине ожидание только надёжнее.
	}

	close(bl.release)

	select {
	case resp := <-resps:
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("код ответа = %d, ожидался 200: начатый запрос обязан быть доведён до конца", resp.StatusCode)
		}
	case err := <-reqErrs:
		t.Fatalf("запрос оборван остановкой сервера: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("ответ не пришёл")
	}

	select {
	case err := <-served:
		if err != nil {
			t.Errorf("serve вернул ошибку: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("serve не завершился после того, как обработчик доработал")
	}
}
