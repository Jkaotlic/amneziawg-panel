package wgconf_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Jkaotlic/awg3-panel/internal/wgconf"
)

const (
	mePub   = "bWUtcHVibGljLWtleS1mYWtlLTAwMDAwMDAwMDAwMDAwMD0="
	papaPub = "cGFwYS1wdWJsaWMta2V5LWZha2UtMDAwMDAwMDAwMDAwMD0="
)

var newPeer = wgconf.PeerSpec{
	Name:         "тест",
	PublicKey:    "bmV3LXB1YmxpYy1rZXktZmFrZS0wMDAwMDAwMDAwMDAwMD0=",
	PresharedKey: "bmV3LXBzay1mYWtlLTAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=",
	AllowedIPs:   "10.0.0.4/32",
}

func load(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ifaceBytes возвращает точные байты секции [Interface] в тексте.
func ifaceBytes(t *testing.T, text string) string {
	t.Helper()
	c, err := wgconf.Parse(text)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	return c.Interface.Bytes(text)
}

// peerBytes возвращает точные байты блока [Peer] с данным публичным ключом.
func peerBytes(t *testing.T, text, pub string) string {
	t.Helper()
	c, err := wgconf.Parse(text)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	sec, ok := wgconf.FindPeer(c, pub)
	if !ok {
		t.Fatalf("пир %s не найден", pub[:8])
	}
	return sec.Bytes(text)
}

// --- Тест 3a спеки: неприкосновенность [Interface] для каждой мутации ---

func TestInterfaceUntouchedByEveryMutation(t *testing.T) {
	for _, name := range []string{"main.conf", "main_crlf.conf", "no_trailing_newline.conf"} {
		t.Run(name, func(t *testing.T) {
			orig := load(t, name)
			before := ifaceBytes(t, orig)

			added, err := wgconf.AppendPeer(orig, newPeer)
			if err != nil {
				t.Fatalf("AppendPeer: %v", err)
			}
			if got := ifaceBytes(t, added); got != before {
				t.Errorf("AppendPeer изменил [Interface]:\nбыло:  %q\nстало: %q", before, got)
			}

			removed, err := wgconf.RemovePeerByPublicKey(orig, mePub)
			if err != nil {
				t.Fatalf("RemovePeerByPublicKey: %v", err)
			}
			if got := ifaceBytes(t, removed); got != before {
				t.Errorf("RemovePeerByPublicKey изменил [Interface]:\nбыло:  %q\nстало: %q", before, got)
			}
		})
	}
}

// TestAppendToConfigWithoutPeersKeepsInterfaceByteIdentical — Размен 1
// финального ревью. В конфиге БЕЗ пиров Interface.EndByte равен концу файла,
// поэтому лишний разделитель, который AppendPeer дописывал перед блоком
// (out + eol + block), растягивал секцию [Interface] на один байт. Дальше
// Applier.assertInterfaceUntouched законно отказывал — незыблемое правило 2
// срабатывало правильно, виноват был AppendPeer.
//
// Радиус шире, чем «чистый хост»: RemovePeerByPublicKey последнего пира
// даёт Interface.EndByte == StartByte следующего... то есть конец файла, и
// проходит без возражений. Значит панель могла удалить всех пиров, но уже
// не могла добавить ни одного обратно — необратимое состояние за несколько
// нажатий (полный цикл проверяется в issuer:
// TestAddRemoveAddCycleOnServerWithoutPeers).
func TestAppendToConfigWithoutPeersKeepsInterfaceByteIdentical(t *testing.T) {
	orig := load(t, "no_peers.conf")
	c, err := wgconf.Parse(orig)
	if err != nil {
		t.Fatalf("фикстура не разбирается: %v", err)
	}
	if len(c.Peers) != 0 {
		t.Fatalf("фикстура сломана: в no_peers.conf %d пиров, ожидалось 0", len(c.Peers))
	}
	before := ifaceBytes(t, orig)

	out, err := wgconf.AppendPeer(orig, newPeer)
	if err != nil {
		t.Fatalf("AppendPeer: %v", err)
	}
	if got := ifaceBytes(t, out); got != before {
		t.Errorf("AppendPeer в конфиг без пиров изменил байты [Interface] — "+
			"Applier откажет применять такой результат, и завести первого пира станет нельзя:\n"+
			"было:  %q\nстало: %q", before, got)
	}
	if !strings.HasPrefix(out, orig) {
		t.Error("добавление изменило предшествующее содержимое файла")
	}
	oc, err := wgconf.Parse(out)
	if err != nil {
		t.Fatalf("результат не разбирается: %v", err)
	}
	if len(oc.Peers) != 1 {
		t.Fatalf("пиров после добавления %d, ожидался 1", len(oc.Peers))
	}
	if oc.Peers[0].Get("PublicKey") != newPeer.PublicKey {
		t.Error("добавлен не тот пир")
	}
	if oc.Peers[0].Get("AllowedIPs") != newPeer.AllowedIPs {
		t.Error("AllowedIPs не записан")
	}
}

// --- Тест 3b спеки: неприкосновенность чужих [Peer] ---

func TestAppendDoesNotTouchAnythingBefore(t *testing.T) {
	orig := load(t, "main.conf")
	out, err := wgconf.AppendPeer(orig, newPeer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, orig) {
		t.Fatal("добавление изменило предшествующее содержимое файла")
	}
	c, err := wgconf.Parse(out)
	if err != nil {
		t.Fatalf("результат не разбирается: %v", err)
	}
	if len(c.Peers) != 3 {
		t.Fatalf("пиров после добавления %d, ожидалось 3", len(c.Peers))
	}
	if c.Peers[2].Get("PublicKey") != newPeer.PublicKey {
		t.Error("новый пир не в конце файла")
	}
	if c.Peers[2].Get("PresharedKey") != newPeer.PresharedKey {
		t.Error("PSK не записан")
	}
	if !strings.Contains(c.Peers[2].Bytes(out), "# awg3panel: тест") {
		t.Error("имя пира не записано комментарием внутри блока")
	}
}

func TestRemoveKeepsOtherPeersByteIdentical(t *testing.T) {
	orig := load(t, "main.conf")
	papaBefore := peerBytes(t, orig, papaPub)

	out, err := wgconf.RemovePeerByPublicKey(orig, mePub)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, mePub) {
		t.Error("удалённый пир остался в тексте")
	}
	if got := peerBytes(t, out, papaPub); got != papaBefore {
		t.Errorf("блок соседнего пира изменился:\nбыло:  %q\nстало: %q", papaBefore, got)
	}
	c, _ := wgconf.Parse(out)
	if len(c.Peers) != 1 {
		t.Errorf("пиров после удаления %d, ожидалось 1", len(c.Peers))
	}
}

// TestRemoveLastPeerByteIdentical покрывает ветку, которую не задевал ни один
// другой тест: удаление ПОСЛЕДНЕГО блока [Peer] в файле, где sec.EndByte ==
// len(text). Это самая опасная по последствиям ветка функции — ошибка
// границы там даёт не расхождение байтов, а панику по выходу за пределы
// среза (см. Fix round 1 в отчёте: мутация StartByte-1 это подтверждает).
//
// Ожидание уточнено находкой 1 живого выката. Прежняя редакция требовала,
// чтобы байты СЕКЦИИ предыдущего пира совпали целиком, — а в них по устройству
// парсера входит и разделительная пустая строка перед удаляемым заголовком.
// Требовать её сохранения значило требовать ровно того накопления пустых строк,
// которое и есть находка: разделитель осиротел бы. Собственные СТРОКИ блока
// обязаны остаться байт в байт (это и проверяется), а разделитель уходит
// вместе с блоком, которому он предшествовал.
func TestRemoveLastPeerByteIdentical(t *testing.T) {
	orig := load(t, "main.conf")
	meBefore := peerBytes(t, orig, mePub)

	out, err := wgconf.RemovePeerByPublicKey(orig, papaPub)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, papaPub) {
		t.Error("удалённый последний пир остался в тексте")
	}
	wantMe := strings.TrimSuffix(meBefore, "\n")
	if got := peerBytes(t, out, mePub); got != wantMe {
		t.Errorf("строки блока первого пира изменились при удалении последнего:\nбыло:  %q\nстало: %q", wantMe, got)
	}
	if !strings.HasSuffix(out, "AllowedIPs = 10.0.0.2/32\n") {
		t.Errorf("после удаления последнего пира остался осиротевший разделитель: %q", tailOf(out))
	}
	c, err := wgconf.Parse(out)
	if err != nil {
		t.Fatalf("результат не разбирается: %v", err)
	}
	if len(c.Peers) != 1 {
		t.Errorf("пиров после удаления последнего %d, ожидалось 1", len(c.Peers))
	}
}

// --- Находка 1 живого выката: конфиг обязан быть стабилен на круговом обходе ---
//
// Измерено на полигоне: awg3.conf в 1073 байта, оканчивавшийся одним "\n",
// после цикла add → disable → enable → delete стал 1075 байт и оканчивается
// тремя "\n". Состав пиров при этом вернулся к исходному, [Interface] не
// изменилась. Механизм: AppendPeer дописывает разделительную пустую строку
// ПЕРЕД блоком [Peer], а по устройству парсера пустая строка перед заголовком
// принадлежит ПРЕДЫДУЩЕЙ секции — RemovePeerByPublicKey режет от StartByte
// заголовка, и разделитель остаётся. Байт за цикл, без верхней границы.

// TestAddRemoveCycleIsByteIdentical — главное свойство находки: добавить и тут
// же удалить пира обязано вернуть файл ровно к исходным байтам.
func TestAddRemoveCycleIsByteIdentical(t *testing.T) {
	for _, name := range []string{"main.conf", "main_crlf.conf", "no_peers.conf"} {
		t.Run(name, func(t *testing.T) {
			orig := load(t, name)
			added, err := wgconf.AppendPeer(orig, newPeer)
			if err != nil {
				t.Fatalf("AppendPeer: %v", err)
			}
			back, err := wgconf.RemovePeerByPublicKey(added, newPeer.PublicKey)
			if err != nil {
				t.Fatalf("RemovePeerByPublicKey: %v", err)
			}
			if back != orig {
				t.Errorf("круговой обход не вернул исходные байты (%d → %d байт):\nбыло:  %q\nстало: %q",
					len(orig), len(back), tailOf(orig), tailOf(back))
			}
		})
	}
}

// TestRepeatedAddRemoveCyclesDoNotGrowConfig — та же находка с другой стороны:
// рост не обязан быть нулевым на первом шаге (в файле без завершающего
// перевода строки AppendPeer законно дописывает его), но обязан прекратиться.
// Начиная со второго цикла текст не имеет права меняться вообще.
func TestRepeatedAddRemoveCyclesDoNotGrowConfig(t *testing.T) {
	fixtures := []string{"main.conf", "main_crlf.conf", "no_peers.conf", "no_trailing_newline.conf"}
	for _, name := range fixtures {
		t.Run(name, func(t *testing.T) {
			text := load(t, name)
			var first string
			for i := 1; i <= 5; i++ {
				added, err := wgconf.AppendPeer(text, newPeer)
				if err != nil {
					t.Fatalf("цикл %d, AppendPeer: %v", i, err)
				}
				back, err := wgconf.RemovePeerByPublicKey(added, newPeer.PublicKey)
				if err != nil {
					t.Fatalf("цикл %d, RemovePeerByPublicKey: %v", i, err)
				}
				if i == 1 {
					first = back
				} else if back != first {
					t.Fatalf("цикл %d изменил файл после первого цикла (%d → %d байт):\nбыло:  %q\nстало: %q",
						i, len(first), len(back), tailOf(first), tailOf(back))
				}
				text = back
			}
		})
	}
}

// TestRemoveOnlyPeerKeepsInterfaceByteIdentical — рубеж незыблемого правила 2
// для правки находки 1. Когда удаляемый пир ПЕРВЫЙ, пустая строка перед ним
// принадлежит секции [Interface], и наивная уборка разделителя изменила бы её
// байты. Здесь пир одновременно первый и последний — то есть попадает и в
// ветку уборки, и под защиту правила 2. Ослаблять правило нельзя: Applier
// откажет применять такой результат, и это будет правильный отказ.
func TestRemoveOnlyPeerKeepsInterfaceByteIdentical(t *testing.T) {
	full := load(t, "main.conf")
	before := ifaceBytes(t, full)

	// Остаётся ровно один пир, и перед ним — пустая строка из [Interface].
	single, err := wgconf.RemovePeerByPublicKey(full, papaPub)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := wgconf.Parse(single); len(c.Peers) != 1 {
		t.Fatalf("подготовка сломана: пиров %d, ожидался 1", len(c.Peers))
	}

	out, err := wgconf.RemovePeerByPublicKey(single, mePub)
	if err != nil {
		t.Fatal(err)
	}
	if got := ifaceBytes(t, out); got != before {
		t.Errorf("удаление единственного пира изменило байты [Interface] — "+
			"разделитель перед первым пиром принадлежит ей и неприкосновенен:\n"+
			"было:  %q\nстало: %q", tailOf(before), tailOf(got))
	}
	if c, _ := wgconf.Parse(out); len(c.Peers) != 0 {
		t.Errorf("пиров после удаления %d, ожидалось 0", len(c.Peers))
	}
	// И обратный шаг обязан вернуть файл к состоянию с одним пиром байт в байт:
	// в конфиге без пиров AppendPeer разделитель не дописывает.
	if back, err := wgconf.AppendPeer(out, wgconf.PeerSpec{
		Name: "me", PublicKey: mePub,
		PresharedKey: "bWUtcHNrLWZha2UtMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD0=",
		AllowedIPs:   "10.0.0.2/32",
	}); err != nil {
		t.Fatal(err)
	} else if back != single {
		t.Errorf("возврат единственного пира не воспроизвёл байты:\nбыло:  %q\nстало: %q",
			tailOf(single), tailOf(back))
	}
}

// TestRemoveMiddlePeerKeepsNeighborsByteIdentical — удаление среднего пира
// разделителей не копит и соседей не трогает: вырезаемый диапазон уносит
// разделитель, стоящий ПОСЛЕ блока, а тот, что перед ним, принадлежит
// предыдущему пиру и остаётся его разделителем со следующим.
func TestRemoveMiddlePeerKeepsNeighborsByteIdentical(t *testing.T) {
	three, err := wgconf.AppendPeer(load(t, "main.conf"), newPeer)
	if err != nil {
		t.Fatal(err)
	}
	meBefore := peerBytes(t, three, mePub)
	newBefore := peerBytes(t, three, newPeer.PublicKey)
	ifaceBefore := ifaceBytes(t, three)

	out, err := wgconf.RemovePeerByPublicKey(three, papaPub)
	if err != nil {
		t.Fatal(err)
	}
	if got := ifaceBytes(t, out); got != ifaceBefore {
		t.Error("удаление среднего пира изменило [Interface]")
	}
	if got := peerBytes(t, out, mePub); got != meBefore {
		t.Errorf("блок предыдущего пира изменился:\nбыло:  %q\nстало: %q", meBefore, got)
	}
	if got := peerBytes(t, out, newPeer.PublicKey); got != newBefore {
		t.Errorf("блок следующего пира изменился:\nбыло:  %q\nстало: %q", newBefore, got)
	}
	if strings.Contains(out, "\n\n\n") {
		t.Error("после удаления среднего пира в файле накопились пустые строки")
	}
}

// tailOf укорачивает текст до последних 48 байт — в сообщениях об ошибках
// этого теста значим именно хвост файла, а печатать конфиг целиком незачем
// (и в нём есть строки PrivateKey/PresharedKey — правило 4).
func tailOf(s string) string {
	if len(s) <= 48 {
		return s
	}
	return "…" + s[len(s)-48:]
}

func TestRemoveTakesCommentInsideBlockWithIt(t *testing.T) {
	orig := load(t, "main.conf")
	out, err := wgconf.RemovePeerByPublicKey(orig, mePub)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "# awg3panel: me") {
		t.Error("комментарий удалённого пира осиротел в файле")
	}
	if !strings.Contains(out, "# awg3panel: papa") {
		t.Error("комментарий соседнего пира пропал")
	}
}

// --- Поведение и ошибки ---

func TestAppendUsesFileEOL(t *testing.T) {
	out, err := wgconf.AppendPeer(load(t, "main_crlf.conf"), newPeer)
	if err != nil {
		t.Fatal(err)
	}
	tail := out[strings.LastIndex(out, "[Peer]"):]
	if strings.Contains(strings.ReplaceAll(tail, "\r\n", ""), "\n") {
		t.Error("в CRLF-файл дописан блок с LF — вышел смешанный перевод строк")
	}
}

func TestAppendToFileWithoutTrailingNewline(t *testing.T) {
	orig := load(t, "no_trailing_newline.conf")
	out, err := wgconf.AppendPeer(orig, newPeer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, orig) {
		t.Fatal("исходные байты изменились")
	}
	c, err := wgconf.Parse(out)
	if err != nil {
		t.Fatalf("результат не разбирается: %v", err)
	}
	if len(c.Peers) != 2 {
		t.Errorf("пиров %d, ожидалось 2", len(c.Peers))
	}
}

func TestAppendRejectsDuplicateKey(t *testing.T) {
	dup := newPeer
	dup.PublicKey = mePub
	if _, err := wgconf.AppendPeer(load(t, "main.conf"), dup); err == nil {
		t.Fatal("ожидалась ошибка на дубликат публичного ключа")
	}
}

// TestAppendRejectsDuplicateKeyWithTrailingSpace проверяет находку ревью:
// Get() при чтении конфига возвращает значения после TrimSpace, а PeerSpec
// не обрезался нигде, поэтому "тот же" ключ с хвостовым пробелом обходил
// сравнение в FindPeer и создавал в конфиге два блока [Peer] с одним
// публичным ключом (отзыв доступа переставал отзывать, а syncconf схлопывал
// PresharedKey/AllowedIPs одного пира в другой).
func TestAppendRejectsDuplicateKeyWithTrailingSpace(t *testing.T) {
	dup := newPeer
	dup.PublicKey = mePub + " "
	if _, err := wgconf.AppendPeer(load(t, "main.conf"), dup); err == nil {
		t.Fatal("ожидалась ошибка на публичный ключ с хвостовым пробелом, совпадающий с существующим после нормализации")
	}
}

func TestAppendRejectsInjection(t *testing.T) {
	bad := newPeer
	bad.Name = "злой\n[Interface]\nS1 = 1"
	out, err := wgconf.AppendPeer(load(t, "main.conf"), bad)
	if err == nil {
		t.Fatalf("ожидалась ошибка на перевод строки в имени, получен конфиг:\n%s", out)
	}
}

func TestRemoveUnknownKey(t *testing.T) {
	if _, err := wgconf.RemovePeerByPublicKey(load(t, "main.conf"), "bmV0LXRha29nby1rbHl1Y2hhLTAwMDAwMDAwMDAwMDAwMD0="); err == nil {
		t.Fatal("ожидалась ошибка на отсутствующий публичный ключ")
	}
}

// --- Задача 6: ReplacePeerBlock ---

func TestReplacePeerBlockTouchesOnlyTargetBlock(t *testing.T) {
	const src = "[Interface]\nPrivateKey = S\nListenPort = 51820\nS1 = 100\n\n" +
		"[Peer]\n# awg3panel: первый\nPublicKey = P1\nPresharedKey = K1\nAllowedIPs = 10.0.0.2/32\n\n" +
		"[Peer]\n# awg3panel: второй\nPublicKey = P2\nPresharedKey = K2\nAllowedIPs = 10.0.0.3/32\n"

	out, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		Name: "переименованный", PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.9/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	oc, _ := wgconf.Parse(src)
	nc, _ := wgconf.Parse(out)
	if oc.Interface.Bytes(src) != nc.Interface.Bytes(out) {
		t.Fatal("[Interface] обязана совпасть побайтово")
	}
	if oc.Peers[1].Bytes(src) != nc.Peers[1].Bytes(out) {
		t.Fatal("чужой [Peer] обязан совпасть побайтово")
	}
	sec, ok := wgconf.FindPeer(nc, "P1")
	if !ok || sec.Get("AllowedIPs") != "10.0.0.9/32" {
		t.Fatalf("целевой блок не обновлён: %v", ok)
	}
	if !strings.Contains(sec.Bytes(out), "# awg3panel: переименованный") {
		t.Fatal("имя в комментарии не обновлено")
	}
}

func TestReplacePeerBlockKeepsFileStable(t *testing.T) {
	const src = "[Interface]\nPrivateKey = S\n\n[Peer]\nPublicKey = P1\nPresharedKey = K1\nAllowedIPs = 10.0.0.2/32\n"
	same := wgconf.PeerSpec{PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.2/32"}
	out, err := wgconf.ReplacePeerBlock(src, "P1", same)
	if err != nil {
		t.Fatal(err)
	}
	if out != src {
		t.Fatalf("замена блока на идентичный обязана давать тот же файл байт в байт:\n%q\n%q", src, out)
	}
}

func TestReplacePeerBlockCRLF(t *testing.T) {
	src := "[Interface]\r\nPrivateKey = S\r\n\r\n[Peer]\r\nPublicKey = P1\r\nPresharedKey = K1\r\nAllowedIPs = 10.0.0.2/32\r\n"
	out, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.7/32"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ReplaceAll(out, "\r\n", ""), "\n") {
		t.Fatal("в CRLF-файле не должно появиться голых переводов строки")
	}
}

func TestReplacePeerBlockErrors(t *testing.T) {
	const src = "[Interface]\nPrivateKey = S\n\n[Peer]\nPublicKey = P1\nPresharedKey = K1\nAllowedIPs = 10.0.0.2/32\n" +
		"\n[Peer]\nPublicKey = P2\nPresharedKey = K2\nAllowedIPs = 10.0.0.3/32\n"
	if _, err := wgconf.ReplacePeerBlock(src, "НЕТ-ТАКОГО", wgconf.PeerSpec{
		PublicKey: "X", PresharedKey: "K", AllowedIPs: "10.0.0.4/32"}); err == nil {
		t.Fatal("замена несуществующего пира обязана быть ошибкой")
	}
	if _, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		Name: "зло\n[Peer]", PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.2/32"}); err == nil {
		t.Fatal("перевод строки в имени обязан быть отвергнут")
	}
	if _, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		PublicKey: "P2", PresharedKey: "K1", AllowedIPs: "10.0.0.2/32"}); err == nil {
		t.Fatal("новый публичный ключ, совпавший с ключом ДРУГОГО пира, обязан быть отвергнут: " +
			"два блока с одним ключом — молча потерянный пир")
	}
}

// TestReplacePeerBlockPreservesUnknownLines — находка финального ревью, I1:
// прежняя редакция ReplacePeerBlock собирала блок заново из четырёх полей
// PeerSpec через RenderPeerBlock, стирая всё, чего там нет. На боевом
// сервере этой панели есть пиры, заведённые руками (см. комментарии в
// internal/issuer/service.go), и у них в блоке бывают PersistentKeepalive и
// собственные комментарии оператора — переименование такого пира не должно
// уносить их с собой.
func TestReplacePeerBlockPreservesUnknownLines(t *testing.T) {
	const src = "[Interface]\nPrivateKey = S\n\n" +
		"[Peer]\n# awg3panel: старое имя\n# заведён руками, не трогать вручную\n" +
		"PublicKey = P1\nPresharedKey = K1\nAllowedIPs = 10.0.0.2/32\nPersistentKeepalive = 25\n"

	out, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		Name: "новое имя", PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.2/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	nc, perr := wgconf.Parse(out)
	if perr != nil {
		t.Fatalf("результат не разбирается: %v", perr)
	}
	sec, ok := wgconf.FindPeer(nc, "P1")
	if !ok {
		t.Fatal("пир P1 пропал из результата")
	}
	block := sec.Bytes(out)
	if !strings.Contains(block, "PersistentKeepalive = 25") {
		t.Errorf("PersistentKeepalive пропал после переименования:\n%s", block)
	}
	if !strings.Contains(block, "# заведён руками, не трогать вручную") {
		t.Errorf("комментарий оператора пропал после переименования:\n%s", block)
	}
	if !strings.Contains(block, "# awg3panel: новое имя") {
		t.Errorf("новое имя не записано:\n%s", block)
	}
	if strings.Contains(block, "старое имя") {
		t.Errorf("старое имя обязано быть заменено, а не сохранено рядом:\n%s", block)
	}
}

// TestReplacePeerBlockRenamesPeerWithoutPresharedKey — второй симптом той же
// находки: у пира, заведённого руками, PresharedKey часто нет вовсе, а
// прежняя PeerSpec.validate() требовала его безусловно и на пути замены
// тоже — отклоняя переименование обычной fmt.Errorf, не issuer.ErrInvalidInput
// (то есть оператор получал 500 «внутренняя ошибка» вместо причины). Спека
// 3.1 прямо обещает, что таких пиров можно переименовывать.
func TestReplacePeerBlockRenamesPeerWithoutPresharedKey(t *testing.T) {
	const src = "[Interface]\nPrivateKey = S\n\n[Peer]\nPublicKey = P1\nAllowedIPs = 10.0.0.2/32\n"

	out, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		Name: "переименован", PublicKey: "P1", AllowedIPs: "10.0.0.2/32", // PresharedKey не задан
	})
	if err != nil {
		t.Fatalf("переименование пира без PresharedKey обязано пройти: %v", err)
	}
	nc, perr := wgconf.Parse(out)
	if perr != nil {
		t.Fatalf("результат не разбирается: %v", perr)
	}
	sec, ok := wgconf.FindPeer(nc, "P1")
	if !ok {
		t.Fatal("пир P1 пропал из результата")
	}
	if sec.Get("PresharedKey") != "" {
		t.Errorf("PresharedKey не должен появиться из ниоткуда: %q", sec.Get("PresharedKey"))
	}
	if strings.Contains(sec.Bytes(out), "PresharedKey") {
		t.Errorf("строка PresharedKey не должна печататься вовсе, если её не было:\n%s", sec.Bytes(out))
	}
	if !strings.Contains(sec.Bytes(out), "# awg3panel: переименован") {
		t.Errorf("новое имя не записано:\n%s", sec.Bytes(out))
	}
}

// --- Регресс повторного финального ревью: дописанная управляемая строка
// приклеивалась к предыдущей, если та скопирована байт в байт без
// собственного перевода строки. ---
//
// Условие срабатывания: целевой блок — последний в файле, файл не
// оканчивается переводом строки, ПОСЛЕДНЯЯ строка блока — неуправляемая
// (комментарий оператора или чужой параметр) и потому копируется байт в байт
// БЕЗ добавления eol, а следом в out дописывается управляемая строка,
// которой не было (PresharedKey или AllowedIPs). Опаснее всего именно
// PresharedKey: если предыдущая строка — комментарий, склеенная строка вида
// "# коммент...PresharedKey = ..." остаётся ОДНИМ ВАЛИДНЫМ комментарием при
// разборе — Parse доволен, assertInterfaceUntouched доволен, syncconf
// комментарии игнорирует, а checkPostcondition для пира из exp.Added
// (Applier.Apply) сверяет только факт появления на устройстве и
// PresharedKey не проверяет вовсе. Панель рапортует успех и отдаёт
// оператору клиентский конфиг С PresharedKey, которого на сервере НЕТ:
// клиент молча и навсегда не подключается.

func TestReplacePeerBlockAppendedPresharedKeyDoesNotGlueToPrecedingComment(t *testing.T) {
	// Без завершающего перевода строки: блок последний в файле, и его
	// последняя строка (комментарий оператора) — последний байт файла.
	const src = "[Interface]\nPrivateKey = S\n\n" +
		"[Peer]\nPublicKey = P1\nAllowedIPs = 10.0.0.2/32\n# hand made peer"

	out, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		Name: "alice", PublicKey: "PNEW", PresharedKey: "KNEW", AllowedIPs: "10.0.0.2/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "# hand made peerPresharedKey") {
		t.Fatalf("дописанная строка PresharedKey приклеилась к предыдущему комментарию:\n%q", out)
	}
	nc, perr := wgconf.Parse(out)
	if perr != nil {
		t.Fatalf("результат не разбирается: %v\n%q", perr, out)
	}
	sec, ok := wgconf.FindPeer(nc, "PNEW")
	if !ok {
		t.Fatalf("пир PNEW не найден в результате:\n%q", out)
	}
	if got := sec.Get("PresharedKey"); got != "KNEW" {
		t.Errorf("PresharedKey = %q, ожидался %q — строка проглочена комментарием и не распознана как параметр", got, "KNEW")
	}
	if !strings.Contains(sec.Bytes(out), "# hand made peer\n") {
		t.Errorf("комментарий оператора обязан остаться отдельной строкой:\n%q", sec.Bytes(out))
	}
}

func TestReplacePeerBlockAppendedAllowedIPsDoesNotGlueToPrecedingComment(t *testing.T) {
	// Симметрично предыдущему тесту, но для второго append из той же пары:
	// AllowedIPs отсутствовал в исходном блоке, а PresharedKey — присутствовал
	// (чтобы дописывался именно AllowedIPs, а не PresharedKey).
	const src = "[Interface]\nPrivateKey = S\n\n" +
		"[Peer]\nPublicKey = P1\nPresharedKey = K1\n# hand made peer"

	out, err := wgconf.ReplacePeerBlock(src, "P1", wgconf.PeerSpec{
		PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.5/32",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "# hand made peerAllowedIPs") {
		t.Fatalf("дописанная строка AllowedIPs приклеилась к предыдущему комментарию:\n%q", out)
	}
	nc, perr := wgconf.Parse(out)
	if perr != nil {
		t.Fatalf("результат не разбирается: %v\n%q", perr, out)
	}
	sec, ok := wgconf.FindPeer(nc, "P1")
	if !ok {
		t.Fatalf("пир P1 не найден в результате:\n%q", out)
	}
	if got := sec.Get("AllowedIPs"); got != "10.0.0.5/32" {
		t.Errorf("AllowedIPs = %q, ожидался %q — строка проглочена комментарием и не распознана как параметр", got, "10.0.0.5/32")
	}
	if !strings.Contains(sec.Bytes(out), "# hand made peer\n") {
		t.Errorf("комментарий оператора обязан остаться отдельной строкой:\n%q", sec.Bytes(out))
	}
}

// TestReplacePeerBlockOnFileWithoutTrailingNewlineGrowsOnceThenStabilizes —
// соседний пункт повторного финального ревью: "замена блока на идентичный
// даёт файл байт в байт" держится только для файлов, УЖЕ оканчивающихся
// переводом строки. Когда последняя строка блока — управляемое поле
// (здесь AllowedIPs) и файл не оканчивается переводом строки, синтезированная
// замена этой строки ("Key = Value" + eol) добавляет перевод строки, которого
// в исходнике не было, — рост на 1 байт.
//
// Решение (см. отчёт и доккомментарий ReplacePeerBlock): это НЕ чинится —
// рост односторонний и самостабилизируется на первом же шаге, тем же образом,
// каким AppendPeer уже дописывает перевод строки в конфиг без пиров (см. её
// доккомментарий). Это НЕ находка 1 живого выката: там рост был неограниченным,
// по байту за КАЖДЫЙ цикл add/remove. Здесь — ровно один лишний байт один раз;
// тест закрепляет именно эту границу, чтобы будущая правка, случайно вернувшая
// рост на каждой замене, была поймана.
func TestReplacePeerBlockOnFileWithoutTrailingNewlineGrowsOnceThenStabilizes(t *testing.T) {
	const src = "[Interface]\nPrivateKey = S\n\n" +
		"[Peer]\nPublicKey = P1\nPresharedKey = K1\nAllowedIPs = 10.0.0.2/32" // без \n на конце

	same := wgconf.PeerSpec{PublicKey: "P1", PresharedKey: "K1", AllowedIPs: "10.0.0.2/32"}

	first, err := wgconf.ReplacePeerBlock(src, "P1", same)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != len(src)+1 {
		t.Fatalf("первая замена: длина %d, ожидалась %d (+1 байт перевода строки, которого не было в исходнике):\nбыло:  %q\nстало: %q",
			len(first), len(src)+1, src, first)
	}
	if !strings.HasSuffix(first, "\n") {
		t.Fatalf("после первой замены файл обязан оканчиваться переводом строки: %q", first)
	}

	second, err := wgconf.ReplacePeerBlock(first, "P1", same)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Errorf("рост не остановился на втором шаге — так росла находка 1 живого выката:\nбыло:  %q\nстало: %q", first, second)
	}
}
