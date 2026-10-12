package termstate

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// fixtures are byte streams any program could write: no agent's habits.
var fixtures = map[string]string{
	"scrolling text": strings.Repeat("a line of text\r\n", 30) + "last",
	"renditions":     "\x1b[1;4;31mbold red\x1b[0m \x1b[38;5;208mindexed\x1b[48;2;10;20;30m rgb bg\x1b[22;24;39m mixed\x1b[0m\r\n\x1b[38:2::1:2:3mcolon\x1b[m",
	"alternate screen": "main screen\r\n\x1b[1mprompt\x1b[0m$ \x1b7\x1b[?1049h\x1b[H\x1b[2Jfull screen app\x1b[5;10H\x1b[7mstatus\x1b[0m" +
		"\x1b[?25l\x1b[?1h\x1b=",
	"leaving the alternate screen": "before\x1b[?1049h\x1b[2;2Hinside\x1b[?1049lafter",
	"scroll region":                "\x1b[2;5r\x1b[5;1H" + strings.Repeat("in region\n", 8) + "\x1b[2;1H\x1bM\x1bMreverse\x1b[3;1H\x1b[2L\x1b[1M\x1b[r",
	"wrap and wide characters": strings.Repeat("x", 79) + "Ж" + "end\r\n" + strings.Repeat("y", 79) + "宽字" +
		"é combining\r\n" + strings.Repeat("z", 80),
	"modes": "\x1b[?2004h\x1b[?1002h\x1b[?1006h\x1b[?1004h\x1b[4 q\x1b]2;a title\x07\x1b[?7l" + strings.Repeat("w", 90) + "\x1b[?7h",
	"editing": "0123456789abcdef\x1b[1;5H\x1b[3@\x1b[2P\x1b[4X\x1b[1;12H\x1b[1K\r\n" + "line two\x1b[2;3H\x1b[4hINS\x1b[4l\x1b[0K\r\n" +
		"three\x1b[J\x1b[3;2H\x1b[1J",
	"line drawing":  "\x1b(0lqqk\r\nx  x\r\nmqqj\x1b(B normal \x1b)0\x0elqk\x0f",
	"tabs":          "\x1b[3g\x1b[1;5H\x1bH\x1b[1;20H\x1bH\r\ta\tb\x1b[2I\x1b[1Zc",
	"queries":       "before\x1b[6n\x1b[c\x1b[>c\x1b[?2004$p\x1b]11;?\x07\x1b[5n after",
	"origin mode":   "\x1b[3;10r\x1b[?6h\x1b[2;4Horigin\x1b[?6l\x1b[1;1Hhome",
	"saved cursor":  "\x1b[5;5H\x1b[32m\x1b7\x1b[1;1Hmoved\x1b8restored",
	"rep and erase": "ab\x1b[5b\r\n\x1b[44m\x1b[2Kblue line\x1b[0m\x1b[3S\x1b[2T",
}

// same reports how two terminals' visible states differ, or "" when they
// render the same. A printed space and a blank are the same.
func same(a, b *Terminal) string {
	if a.cols != b.cols || a.rows != b.rows {
		return "size"
	}
	if a.altActive != b.altActive {
		return "screen"
	}
	if a.cur != b.cur {
		return fmt.Sprintf("cursor %+v != %+v", a.cur, b.cur)
	}
	if a.modes != b.modes {
		return fmt.Sprintf("modes %+v != %+v", a.modes, b.modes)
	}
	if a.top != b.top || a.bot != b.bot {
		return "scroll region"
	}
	if fmt.Sprint(a.tabs) != fmt.Sprint(b.tabs) {
		return "tabs"
	}
	if a.title != b.title || a.cursorStyle != b.cursorStyle {
		return "title or cursor style"
	}
	if a.p.g != b.p.g || a.p.shift != b.p.shift {
		return "character sets"
	}
	if (a.savedSet || a.altActive) && (a.saved.x != b.saved.x || a.saved.y != b.saved.y || a.saved.attr != b.saved.attr) {
		return fmt.Sprintf("saved cursor %+v != %+v", a.saved, b.saved)
	}
	grids := [][2][][]Cell{{a.main, b.main}}
	if a.altActive {
		grids = append(grids, [2][][]Cell{a.alt, b.alt})
	}
	for _, g := range grids {
		for y := range g[0] {
			for x := range g[0][y] {
				ca, cb := g[0][y][x], g[1][y][x]
				if ca.S == " " {
					ca.S = ""
				}
				if cb.S == " " {
					cb.S = ""
				}
				if ca != cb {
					return fmt.Sprintf("cell %d,%d %+v != %+v (rows %q / %q)", x, y, ca, cb, rowText(g[0][y]), rowText(g[1][y]))
				}
			}
		}
	}
	return ""
}

// A snapshot taken at any point, followed by what is forwarded after it,
// renders exactly what the uninterrupted stream does (ZEOAPP's
// continuation requirement, SOW179). Every cut of every fixture is tried,
// cuts inside characters and sequences included.
func TestASnapshotPlusWhatFollowsEqualsTheWholeStream(t *testing.T) {
	skipped := 0
	for name, stream := range fixtures {
		whole := New(80, 24, 100)
		whole.Feed([]byte(stream))
		for k := 0; k <= len(stream); k++ {
			src := New(80, 24, 100)
			src.Feed([]byte(stream[:k]))
			snap := src.Snapshot()
			rest := src.Feed([]byte(stream[k:])) // what clients get after the cut: a sequence split by it arrives whole
			if !src.Exact() || (!src.RepExact() && repeats.Match(rest)) {
				skipped++
				continue // the snapshot says so: only these cuts may differ
			}
			client := New(80, 24, 100)
			client.Feed(snap)
			client.Feed(rest)
			if d := same(whole, client); d != "" {
				t.Fatalf("%s, cut at %d: %s", name, k, d)
			}
		}
	}
}

// A sequence or character split across writes is held and forwarded whole,
// so a cut never falls inside one.
func TestASplitSequenceIsForwardedWhole(t *testing.T) {
	term := New(80, 24, 0)
	if out := term.Feed([]byte("\x1b[3")); len(out) != 0 {
		t.Fatalf("a partial sequence was forwarded: %q", out)
	}
	if out := term.Feed([]byte("1mé"[:3])); string(out) != "\x1b[31m" {
		t.Fatalf("forwarded %q", out)
	}
	if out := term.Feed([]byte("\xa9")); string(out) != "é" {
		t.Fatalf("forwarded %q", out)
	}
}

// Queries are answered by the host from the model and never forwarded, so
// no attached terminal answers them as well.
func TestQueriesAreAnsweredAndNotForwarded(t *testing.T) {
	term := New(80, 24, 0)
	out := term.Feed([]byte("\x1b[3;7Hx\x1b[6n\x1b[c\x1b[?2004$p\x1b]11;?\x1b\\\x1b[5n\x1b[18tok"))
	if bytes.Contains(out, []byte("6n")) || bytes.Contains(out, []byte("$p")) || bytes.Contains(out, []byte("]11")) || bytes.Contains(out, []byte("[c")) {
		t.Fatalf("a query was forwarded: %q", out)
	}
	if !bytes.HasSuffix(out, []byte("ok")) || !bytes.Contains(out, []byte("x")) {
		t.Fatalf("output lost around the queries: %q", out)
	}
	want := "\x1b[3;8R\x1b[?62;22c\x1b[?2004;2$y\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[0n\x1b[8;24;80t"
	if got := string(term.Replies()); got != want {
		t.Fatalf("replies %q, want %q", got, want)
	}
	if len(term.Replies()) != 0 {
		t.Fatal("replies weren't cleared")
	}
}

// Lines scrolled off the main screen keep stable identities, and the
// history is bounded.
func TestHistoryLinesHaveStableIdentities(t *testing.T) {
	term := New(20, 5, 10)
	for i := 0; i < 30; i++ {
		term.Feed([]byte(fmt.Sprintf("line %d\r\n", i)))
	}
	h := term.History()
	if len(h) != 10 {
		t.Fatalf("%d history lines", len(h))
	}
	for i, l := range h {
		if want := uint64(16 + i); l.ID != want || rowText(l.Cells) != fmt.Sprintf("line %d", want) {
			t.Fatalf("line %d: id %d %q", i, l.ID, rowText(l.Cells))
		}
	}
	term.Feed([]byte("\x1b[?1049h" + strings.Repeat("alt\r\n", 20) + "\x1b[?1049l"))
	if len(term.History()) != 10 || term.History()[9].ID != 25 {
		t.Fatal("the alternate screen's scrolling entered history")
	}
}

// pushHistory is a ring once full (LOW 4): wrapping around it several
// times, then clearing the scrollback and refilling it, still gives the
// right lines in the right order.
func TestHistoryRingWrapsCleanly(t *testing.T) {
	term := New(20, 5, 4)
	for i := 0; i < 50; i++ { // many times around a small ring
		term.Feed([]byte(fmt.Sprintf("line %d\r\n", i)))
	}
	h := term.History()
	if len(h) != 4 {
		t.Fatalf("%d history lines", len(h))
	}
	for i, l := range h {
		if want := fmt.Sprintf("line %d", l.ID); rowText(l.Cells) != want {
			t.Fatalf("line %d: id %d holds %q, want %q", i, l.ID, rowText(l.Cells), want)
		}
		if i > 0 && h[i-1].ID >= l.ID {
			t.Fatalf("ids out of order: %d then %d", h[i-1].ID, l.ID)
		}
	}
	term.Feed([]byte("\x1b[3J")) // clear scrollback
	if len(term.History()) != 0 {
		t.Fatal("scrollback survived its clear")
	}
	for i := 0; i < 30; i++ { // enough to fill and wrap the ring from scratch
		term.Feed([]byte(fmt.Sprintf("fresh %d\r\n", i)))
	}
	h = term.History()
	if len(h) != 4 {
		t.Fatalf("%d history lines after a clear and refill", len(h))
	}
	for i, l := range h {
		if i > 0 && h[i-1].ID >= l.ID {
			t.Fatalf("ids out of order after a clear and refill: %d then %d", h[i-1].ID, l.ID)
		}
	}
	if !strings.HasPrefix(rowText(h[3].Cells), "fresh ") {
		t.Fatalf("newest line after wrapping is %q, want a fresh one", rowText(h[3].Cells))
	}
}

// A snapshot asks the terminal nothing, so replaying it can't make a
// client's terminal answer.
func TestASnapshotHoldsNoQuery(t *testing.T) {
	for name, stream := range fixtures {
		term := New(80, 24, 0)
		term.Feed([]byte(stream))
		snap := string(term.Snapshot())
		for _, q := range []string{"[6n", "[5n", "[c", "[>c", "$p", ";?\x07", "[18t"} {
			if strings.Contains(snap, q) {
				t.Fatalf("%s: the snapshot holds a query %q", name, q)
			}
		}
	}
}

// A bare ESC inside an OSC or DCS string ends it there, unterminated: its
// content is never applied, and the ESC (with what follows) is reprocessed
// as a fresh sequence, so a smuggled OSC hiding inside what looked like a
// title is parsed for real, not swallowed as inert text and replayed on
// every snapshot (zeocouncil's review of #126, LOW 2).
func TestABareESCEndsAnOSCOrDCSString(t *testing.T) {
	term := New(80, 24, 0)
	// The outer OSC 2 (set title) never completes: a nested OSC 52 (set the
	// clipboard) arrives, with its own BEL, before the outer string's own
	// terminator would.
	term.Feed([]byte("\x1b]2;smuggled\x1b]52;c;QkFE\x07innocent\x07"))
	if strings.Contains(term.title, "smuggled") || strings.Contains(term.title, "52") {
		t.Fatalf("the unterminated prefix leaked into the title: %q", term.title)
	}
	// What matters here is only that the title holds nothing from the
	// smuggled prefix: the nested OSC 52 was reprocessed as its own
	// sequence, not swallowed as the outer string's text.
	term.Feed([]byte("\x1b]2;clean\x07"))
	if term.title != "clean" {
		t.Fatalf("title %q, want %q", term.title, "clean")
	}
	// A query smuggled the same way is answered, not swallowed: its
	// recognised reply comes back, which only happens if it was reprocessed
	// as a real sequence rather than held as string content.
	term2 := New(80, 24, 0)
	term2.Feed([]byte("\x1b]2;x\x1b[6nBEL_never_arrives"))
	if len(term2.Replies()) == 0 {
		t.Fatal("a query smuggled inside an unterminated OSC string was never answered")
	}
}

// A control byte never reaches the title, however it got there.
func TestTheTitleNeverHoldsAControlByte(t *testing.T) {
	term := New(80, 24, 0)
	term.Feed([]byte("\x1b]2;a\x01b\x7fc\xc2\x80d\x07"))
	for _, r := range term.title {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("title %q holds control rune %U", term.title, r)
		}
	}
	if term.title != "abcd" {
		t.Fatalf("title %q, want %q", term.title, "abcd")
	}
}

// A flood of combining marks on one cell is bounded, not stored whole: the
// cell, and so every Snapshot that reconstructs it, stays small however
// many marks a program (hostile or not) sends (zeocouncil's review of
// #126, MEDIUM: unbounded growth under the session lock).
func TestCombiningMarksAreBoundedPerCell(t *testing.T) {
	term := New(80, 24, 0)
	term.Feed([]byte("e" + strings.Repeat("́", 10000))) // 'e' plus 10000 acute accents
	cell := term.main[0][0]
	if n := utf8.RuneCountInString(cell.S); n > 1+maxCombiningMarks {
		t.Fatalf("cell holds %d runes, want at most %d", n, 1+maxCombiningMarks)
	}
	if len(cell.S) > utf8.UTFMax+maxCombiningMarkBytes {
		t.Fatalf("cell holds %d bytes, want at most %d", len(cell.S), utf8.UTFMax+maxCombiningMarkBytes)
	}
	// REP then can't amplify a flooded cell into an unbounded snapshot: it
	// replays the same bounded text into up to 65536 cells.
	term2 := New(1000, 500, 0)
	term2.Feed([]byte("e" + strings.Repeat("́", 10000) + "\x1b[65535b"))
	snap := term2.Snapshot()
	const generous = 50 << 20 // 50 MiB: far more than a bounded 1000x500 screen needs, far less than the 32 GB the review measured
	if len(snap) > generous {
		t.Fatalf("a flooded cell plus REP produced a %d-byte snapshot, want well under %d", len(snap), generous)
	}
}

// tokens are the pieces random streams are made of.
var tokens = []string{
	"text", "\r\n", "\n", "\r", "\t", "\b", "宽", "Ж", "é", "😀", "\x1b[1m", "\x1b[0m", "\x1b[38;5;9m", "\x1b[48;2;1;2;3m",
	"\x1b[7m", "\x1b[27m", "\x1b[H", "\x1b[5;20H", "\x1b[24;80H", "\x1b[3A", "\x1b[2B", "\x1b[10C", "\x1b[4D", "\x1b[3G", "\x1b[7d",
	"\x1b[J", "\x1b[1J", "\x1b[2J", "\x1b[K", "\x1b[1K", "\x1b[2K", "\x1b[2@", "\x1b[3P", "\x1b[2X", "\x1b[2L", "\x1b[1M",
	"\x1b[S", "\x1b[T", "\x1b[3;12r", "\x1b[r", "\x1b[?1049h", "\x1b[?1049l", "\x1b[?47h", "\x1b[?47l", "\x1b[?6h", "\x1b[?6l",
	"\x1b[?7l", "\x1b[?7h", "\x1b[4h", "\x1b[4l", "\x1bH", "\x1b[3g", "\x1b[g", "\x1b7", "\x1b8", "\x1b[s", "\x1b[u",
	"\x1bM", "\x1bD", "\x1bE", "\x1b(0", "\x1b(B", "\x0e", "\x0f", "lqk", "\x1b[6n", "\x1b[c", "\x1b[?25l", "\x1b[?25h",
	"\x1b[?2004h", "\x1b[?1000h", "\x1b[?1006h", "\x1b[2 q", "\x1b]2;t\x07", "\x1b[3b", strings.Repeat("w", 85),
}

// Random streams, cut at random places, still continue exactly: a seeded
// search for any state the snapshot misses.
func TestRandomStreamsContinueExactlyFromAnyCut(t *testing.T) {
	originSkips, repSkips, total := 0, 0, 0
	r := rand.New(rand.NewPCG(1, 2))
	for i := 0; i < 400; i++ {
		var b strings.Builder
		for n := r.IntN(120) + 10; n > 0; n-- {
			b.WriteString(tokens[r.IntN(len(tokens))])
		}
		stream := b.String()
		whole := New(80, 24, 50)
		whole.Feed([]byte(stream))
		for c := 0; c < 12; c++ {
			k := r.IntN(len(stream) + 1)
			total++
			src := New(80, 24, 50)
			src.Feed([]byte(stream[:k]))
			snap := src.Snapshot()
			rest := src.Feed([]byte(stream[k:])) // what clients get after the cut: a sequence split by it arrives whole
			if !src.Exact() {
				originSkips++
				continue // the snapshot says so: only these cuts may differ
			}
			if !src.RepExact() && repeats.Match(rest) {
				repSkips++
				continue
			}
			client := New(80, 24, 50)
			client.Feed(snap)
			client.Feed(rest)
			if d := same(whole, client); d != "" {
				t.Fatalf("stream %d cut at %d: %s\nstream %q", i, k, d, stream)
			}
		}
	}
	// Skipping must stay rare, or it would hide what the test is for. Cuts
	// the snapshot can't make exact for every program are near zero; cuts
	// it can't make exact for a REP that follows are rarer in real output
	// than in this deliberately REP-heavy mix.
	if originSkips*50 > total || repSkips*100 > total*15 {
		t.Fatalf("%d and %d of %d cuts skipped as not exact", originSkips, repSkips, total)
	}
	t.Logf("skipped: %d (origin), %d (REP) of %d cuts", originSkips, repSkips, total)
}

// repeats finds a REP (repeat the last character) in a stream.
var repeats = regexp.MustCompile("\x1b\\[[0-9]*b")

// FuzzFeedNeverPanics feeds raw, often malformed bytes to a fresh
// terminal: truncated escapes, a huge CSI parameter, a flood of
// combining marks, a nested OSC inside an unterminated one, and invalid
// UTF-8 among them. Nothing here is well-formed by construction, unlike
// tokens above, which TestRandomStreamsContinueExactlyFromAnyCut draws
// from (zeocouncil's review of #126, LOW 5: "fuzzed" there is a seeded
// search over well-formed tokens only, never hostile input).
func FuzzFeedNeverPanics(f *testing.F) {
	for _, s := range []string{
		"", "\x1b", "\x1b[", "\x1b]", "\x1bP", "\x1b]2;x\x1b]52;c;QkFE\x07y\x07",
		"\x1b[" + strings.Repeat("9", 100) + "b", "\x1b[999999999b",
		"a" + strings.Repeat("́", 5000), "\x1bP$q",
		strings.Repeat("\xff", 200), "\xc0\x80", "\xed\xa0\x80", "\xe2\x28\xa1",
		fixtures["queries"], fixtures["rep and erase"],
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			b = b[:1<<16] // the model's own bounds are what's under test, not an unbounded corpus
		}
		term := New(80, 24, 100)
		fwd := term.Feed(b)
		if len(fwd) > len(b) {
			t.Fatalf("forwarded %d bytes from %d: queries are removed, never added", len(fwd), len(b))
		}
		snap := term.Snapshot()
		const bound = 4 << 20 // generous for an 80x24 screen with full history; unbounded is exactly the MEDIUM this review found
		if len(snap) > bound {
			t.Fatalf("a %d-byte snapshot from a %d-byte input, want under %d", len(snap), len(b), bound)
		}
	})
}

// Held counts exactly the bytes a cut must resend: a snapshot, then the
// held bytes, then the rest, renders the whole stream's screen.
func TestHeldBytesCompleteACut(t *testing.T) {
	stream := []byte("one\r\n\x1b[1;31mred\x1b[0m two \xe2\x82\xac\x1b]0;title\x07end")
	for cut := 0; cut <= len(stream); cut++ {
		whole := New(20, 4, 10)
		whole.Feed(stream)
		a := New(20, 4, 10)
		a.Feed(stream[:cut])
		held, ok := a.Held()
		if !ok {
			t.Fatalf("cut %d: not exact", cut)
		}
		b := New(20, 4, 10)
		b.Feed(a.Snapshot())
		b.Feed(stream[cut-held : cut])
		b.Feed(stream[cut:])
		for y := 0; y < 4; y++ {
			if b.Row(y) != whole.Row(y) {
				t.Fatalf("cut %d (held %d), row %d: %q, want %q", cut, held, y, b.Row(y), whole.Row(y))
			}
		}
		if b.Title() != whole.Title() {
			t.Fatalf("cut %d: title %q", cut, b.Title())
		}
	}
}
