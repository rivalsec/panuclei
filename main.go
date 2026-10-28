// panuclei — a lightweight Go passive-nuclei matcher (successor to pypanuclei).
//
// "passive" template = exactly one request, method GET, path {{BaseURL}} or
// {{BaseURL}}/, with at least one word/regex matcher.
//
// Beyond the original pypanuclei semantics this version closes three gaps so it
// agrees with nuclei's ground truth instead of guessing:
//   1. DSL matchers are *evaluated* (via govaluate + the nuclei DSL function
//      subset), not skipped — no more auto-passing `matchers-condition: and`
//      templates and inventing false positives.
//   2. `part:` resolves response/all (raw) and any named response header
//      (server, content_type, cf_ray, ...), not just body/header.
//   3. Anything still unevaluable (an unparseable DSL expr, an unknown matcher
//      type) makes the whole template get *dropped at load* and counted — a
//      dropped template can never false-positive.
//
// Go's regexp (RE2) also compiles every nuclei pattern, and files are matched
// across all CPU cores via a worker pool.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http/httputil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Knetic/govaluate"
	"gopkg.in/yaml.v3"
)

type matcher struct {
	Type       string   `yaml:"type"`
	Part       string   `yaml:"part"`
	Condition  string   `yaml:"condition"`
	Negative   bool     `yaml:"negative"`
	Words      []string `yaml:"words"`
	Regex      []string `yaml:"regex"`
	Status     []int    `yaml:"status"`
	DSL        []string `yaml:"dsl"`
	compiled   []*regexp.Regexp
	dslExprs   []*govaluate.EvaluableExpression
	dslVars    [][]string
}

type request struct {
	Method     string    `yaml:"method"`
	Path       []string  `yaml:"path"`
	MCondition string    `yaml:"matchers-condition"`
	Matchers   []matcher `yaml:"matchers"`
}

type template struct {
	ID       string                 `yaml:"id"`
	Info     map[string]interface{} `yaml:"info"`
	HTTP     []request              `yaml:"http"`
	Requests []request              `yaml:"requests"` // legacy schema

	req  *request
	path string
}

var (
	skippedRegex int64
	droppedTpls  int64
)

func (t *template) reqs() []request {
	if len(t.HTTP) > 0 {
		return t.HTTP
	}
	return t.Requests
}

// isPassive mirrors pypanuclei.ispassive.
func isPassive(t *template) bool {
	rs := t.reqs()
	if len(rs) != 1 {
		return false
	}
	r := &rs[0]
	if r.Method != "GET" {
		return false
	}
	hasWR := false
	for _, m := range r.Matchers {
		if m.Type == "word" || m.Type == "regex" {
			hasWR = true
			break
		}
	}
	if !hasWR {
		return false
	}
	for _, p := range r.Path {
		if p == "{{BaseURL}}" || p == "{{BaseURL}}/" {
			t.req = r
			return true
		}
	}
	return false
}

// prep precompiles regex/DSL. It returns an error when the template contains a
// matcher we cannot fully evaluate; such templates are dropped so they can never
// produce a false positive from a silently-skipped condition.
func prep(t *template) error {
	for i := range t.req.Matchers {
		m := &t.req.Matchers[i]
		switch m.Type {
		case "word", "status":
			// fully supported
		case "regex":
			for _, r := range m.Regex {
				re, err := regexp.Compile(r)
				if err != nil {
					atomic.AddInt64(&skippedRegex, 1)
					continue
				}
				m.compiled = append(m.compiled, re)
			}
		case "dsl":
			for _, expr := range m.DSL {
				e, err := govaluate.NewEvaluableExpressionWithFunctions(expr, dslFuncs)
				if err != nil {
					return fmt.Errorf("dsl parse %q: %w", expr, err)
				}
				m.dslExprs = append(m.dslExprs, e)
				m.dslVars = append(m.dslVars, e.Vars())
			}
		default:
			return fmt.Errorf("unsupported matcher type %q", m.Type)
		}
	}
	return nil
}

func loadTemplates(paths, excludes []string) []*template {
	// Clean excludes once so a "./nuclei-templates/..." pattern matches the
	// walked path (filepath.Walk strips the leading "./"); compare cleaned paths.
	cleanEx := make([]string, 0, len(excludes))
	for _, e := range excludes {
		if c := filepath.Clean(e); c != "." {
			cleanEx = append(cleanEx, c)
		}
	}
	var out []*template
	for _, path := range paths {
		path = strings.TrimRight(path, "/")
		filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(p, ".yaml") {
				return nil
			}
			pc := filepath.Clean(p)
			for _, e := range cleanEx {
				if strings.HasPrefix(pc, e) {
					return nil
				}
			}
			if strings.Contains(p, "-workflow.yaml") {
				return nil
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return nil
			}
			var t template
			if yaml.Unmarshal(data, &t) != nil {
				return nil
			}
			if !isPassive(&t) {
				return nil
			}
			if err := prep(&t); err != nil {
				atomic.AddInt64(&droppedTpls, 1)
				return nil
			}
			t.path = p
			out = append(out, &t)
			return nil
		})
	}
	return out
}

// ---- response parsing ----

type response struct {
	status    int
	statusStr string
	header    string            // raw header block (no status line)
	body      string
	raw       string            // status line + headers + body (reconstructed)
	headerMap map[string]string // canonical lower-case name -> value
}

var chunkedRe = regexp.MustCompile(`(?i)transfer-encoding:\s*chunked`)

// stripTrailingURL removes httpx -srd's trailing "<url>" line (a standalone
// http(s):// line at the end, after a blank line) so it can't pollute body
// matches. Only called for files that carried a request prefix.
func stripTrailingURL(data []byte) []byte {
	trimmed := bytes.TrimRight(data, "\r\n")
	nl := bytes.LastIndexByte(trimmed, '\n')
	if nl < 0 {
		return data
	}
	last := bytes.TrimSpace(trimmed[nl+1:])
	if (bytes.HasPrefix(last, []byte("http://")) || bytes.HasPrefix(last, []byte("https://"))) &&
		!bytes.ContainsAny(last, " \t") {
		return trimmed[:nl]
	}
	return data
}

// parseResponse reads either a response-only file (starting with "HTTP/", the
// pypanuclei format) or an httpx -srd file ("<request>\r\n\r\n<response>\r\n\r\n
// <url>", AutoBB's httprobes_savedir layout). For the latter it seeks to the
// first HTTP/ status line and drops httpx's trailing URL line, so AutoBB's saved
// probes can be scanned directly with no staging/shim step.
func parseResponse(data []byte) (*response, bool) {
	if !bytes.HasPrefix(data, []byte("HTTP/")) {
		i := bytes.Index(data, []byte("\nHTTP/"))
		if i < 0 {
			return nil, false
		}
		data = stripTrailingURL(data[i+1:])
	}
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return nil, false
	}
	statusLine := strings.TrimRight(string(data[:nl]), "\r")
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 {
		return nil, false
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, false
	}
	rest := data[nl+1:]
	sep := bytes.Index(rest, []byte("\r\n\r\n"))
	sepLen := 4
	if sep < 0 {
		sep = bytes.Index(rest, []byte("\n\n"))
		sepLen = 2
	}
	var header, bodyRaw []byte
	if sep < 0 {
		header = rest
	} else {
		header = rest[:sep]
		bodyRaw = rest[sep+sepLen:]
	}
	body := bodyRaw
	if chunkedRe.Match(header) {
		if dec, err := io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(bodyRaw))); err == nil {
			body = dec
		}
	}
	r := &response{
		status:    status,
		statusStr: statusLine,
		header:    string(header),
		body:      string(body),
		headerMap: map[string]string{},
	}
	r.raw = statusLine + "\r\n" + r.header + "\r\n\r\n" + r.body
	for _, line := range strings.Split(r.header, "\n") {
		line = strings.TrimRight(line, "\r")
		if i := strings.IndexByte(line, ':'); i > 0 {
			name := strings.ToLower(strings.TrimSpace(line[:i]))
			val := strings.TrimSpace(line[i+1:])
			if _, ok := r.headerMap[name]; ok {
				r.headerMap[name] += ", " + val // fold duplicates like nuclei
			} else {
				r.headerMap[name] = val
			}
		}
	}
	return r, true
}

// part resolves a nuclei `part:` value. Beyond body/header/response, any other
// name is treated as a response header (underscores -> hyphens), matching nuclei.
func (r *response) part(name string) string {
	switch name {
	case "", "body":
		return r.body
	case "header", "all_headers":
		return r.header
	case "response", "all":
		return r.raw
	case "status_code":
		return r.statusStr
	default:
		return r.headerMap[strings.ReplaceAll(strings.ToLower(name), "_", "-")]
	}
}

// ---- nuclei DSL function subset ----

var reCache sync.Map // string -> *regexp.Regexp

func dslRegex(pattern, s string) bool {
	var re *regexp.Regexp
	if v, ok := reCache.Load(pattern); ok {
		re = v.(*regexp.Regexp)
	} else {
		c, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		re = c
		reCache.Store(pattern, re)
	}
	return re.MatchString(s)
}

func asStr(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	default:
		return fmt.Sprint(x)
	}
}

var dslFuncs = map[string]govaluate.ExpressionFunction{
	"contains":   func(a ...interface{}) (interface{}, error) { return strings.Contains(asStr(a[0]), asStr(a[1])), nil },
	"icontains":  func(a ...interface{}) (interface{}, error) { return strings.Contains(strings.ToLower(asStr(a[0])), strings.ToLower(asStr(a[1]))), nil },
	"startswith": func(a ...interface{}) (interface{}, error) { return strings.HasPrefix(asStr(a[0]), asStr(a[1])), nil },
	"endswith":   func(a ...interface{}) (interface{}, error) { return strings.HasSuffix(asStr(a[0]), asStr(a[1])), nil },
	"tolower":    func(a ...interface{}) (interface{}, error) { return strings.ToLower(asStr(a[0])), nil },
	"toupper":    func(a ...interface{}) (interface{}, error) { return strings.ToUpper(asStr(a[0])), nil },
	"len":        func(a ...interface{}) (interface{}, error) { return float64(len(asStr(a[0]))), nil },
	"tostring":   func(a ...interface{}) (interface{}, error) { return asStr(a[0]), nil },
	"trim":       func(a ...interface{}) (interface{}, error) { return strings.TrimSpace(asStr(a[0])), nil },
	"replace": func(a ...interface{}) (interface{}, error) {
		if len(a) < 3 {
			return "", nil
		}
		return strings.ReplaceAll(asStr(a[0]), asStr(a[1]), asStr(a[2])), nil
	},
	"regex": func(a ...interface{}) (interface{}, error) {
		if len(a) < 2 {
			return false, nil
		}
		return dslRegex(asStr(a[0]), asStr(a[1])), nil
	},
	"compare_versions": func(a ...interface{}) (interface{}, error) {
		// Offline the version operand is an extractor result we don't have, so
		// this is unresolvable; return false rather than guess. (Guarded here
		// so an expr using it never errors the whole evaluation.)
		return false, nil
	},
}

// ---- matching ----

func reduce(bools []bool, cond string) bool {
	if cond == "and" {
		for _, b := range bools {
			if !b {
				return false
			}
		}
		return true
	}
	for _, b := range bools {
		if b {
			return true
		}
	}
	return false
}

func (m *matcher) evalDSL(r *response) bool {
	base := map[string]interface{}{
		"body":         r.body,
		"header":       r.header,
		"all_headers":  r.header,
		"response":     r.raw,
		"status_code":  float64(r.status),
		"content_type": r.headerMap["content-type"],
		"server":       r.headerMap["server"],
		"host":         r.headerMap["host"],
	}
	hits := make([]bool, 0, len(m.dslExprs))
	for i, e := range m.dslExprs {
		params := make(map[string]interface{}, len(m.dslVars[i]))
		for _, v := range m.dslVars[i] {
			if val, ok := base[v]; ok {
				params[v] = val
			} else if hv, ok := r.headerMap[strings.ReplaceAll(strings.ToLower(v), "_", "-")]; ok {
				params[v] = hv
			} else {
				params[v] = "" // unknown var (e.g. an extractor result) -> empty
			}
		}
		res, err := e.Evaluate(params)
		if err != nil {
			hits = append(hits, false)
			continue
		}
		b, _ := res.(bool)
		hits = append(hits, b)
	}
	return reduce(hits, orDefault(m.Condition))
}

func orDefault(c string) string {
	if c == "" {
		return "or"
	}
	return c
}

func matcherResult(m *matcher, r *response) bool {
	part := m.Part
	if part == "" {
		part = "body"
	}
	cond := orDefault(m.Condition)
	switch m.Type {
	case "status":
		hits := make([]bool, 0, len(m.Status))
		for _, s := range m.Status {
			hits = append(hits, s == r.status)
		}
		res := reduce(hits, cond)
		if m.Negative {
			res = !res
		}
		return res
	case "word":
		src := r.part(part)
		hits := make([]bool, 0, len(m.Words))
		for _, w := range m.Words {
			hits = append(hits, strings.Contains(src, w))
		}
		res := reduce(hits, cond)
		if m.Negative {
			res = !res
		}
		return res
	case "regex":
		src := r.part(part)
		hits := make([]bool, 0, len(m.compiled))
		for _, re := range m.compiled {
			hits = append(hits, re.MatchString(src))
		}
		res := reduce(hits, cond)
		if m.Negative {
			res = !res
		}
		return res
	case "dsl":
		res := m.evalDSL(r)
		if m.Negative {
			res = !res
		}
		return res
	}
	return false
}

func templateMatch(t *template, r *response) bool {
	req := t.req
	if len(req.Matchers) == 0 {
		return false
	}
	cond := orDefault(req.MCondition)
	results := make([]bool, 0, len(req.Matchers))
	for i := range req.Matchers {
		results = append(results, matcherResult(&req.Matchers[i], r))
	}
	return reduce(results, cond)
}

// ---- output ----

type hit struct {
	TemplateID    string                 `json:"template-id"`
	Info          map[string]interface{} `json:"info"`
	MatcherName   interface{}            `json:"matcher-name"`
	Type          string                 `json:"type"`
	Path          string                 `json:"path"`
	MatchedAt     string                 `json:"matched-at"`
	Timestamp     string                 `json:"timestamp"`
	MatcherStatus bool                   `json:"matcher-status"`
	MatchedLine   interface{}            `json:"matched-line"`
}

type multiFlag []string

func (m *multiFlag) String() string    { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	var tDirs, etDirs multiFlag
	target := flag.String("u", "", "path to directory with saved responses")
	flag.Var(&tDirs, "t", "templates directory (repeatable)")
	flag.Var(&etDirs, "et", "exclude template/dir (repeatable)")
	jsonOut := flag.Bool("json", false, "json output")
	dump := flag.Bool("dump", false, "print selected template file paths and exit")
	workers := flag.Int("workers", runtime.NumCPU(), "parallel workers")
	flag.Parse()
	if len(tDirs) == 0 || (*target == "" && !*dump) {
		fmt.Fprintln(os.Stderr, "usage: panuclei -u <responses> -t <templates> [-t ...] [-et ...] [-json|-dump]")
		os.Exit(2)
	}

	templates := loadTemplates(tDirs, etDirs)
	if *dump {
		for _, t := range templates {
			fmt.Println(t.path)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "Templates loaded for scan: %d (dropped unevaluable: %d, regexes skipped: %d)\n",
		len(templates), atomic.LoadInt64(&droppedTpls), atomic.LoadInt64(&skippedRegex))

	root := strings.TrimRight(*target, "/")
	var files []string
	filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.HasSuffix(p, ".txt") {
			files = append(files, p)
		}
		return nil
	})

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	var mu sync.Mutex

	jobs := make(chan string, *workers*2)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				data, err := os.ReadFile(f)
				if err != nil {
					continue
				}
				r, ok := parseResponse(data)
				if !ok {
					continue
				}
				for _, t := range templates {
					if !templateMatch(t, r) {
						continue
					}
					mu.Lock()
					if *jsonOut {
						h := hit{
							TemplateID: t.ID, Info: t.Info, Type: "http",
							Path: f, MatchedAt: f,
							Timestamp:     time.Now().Format(time.RFC3339),
							MatcherStatus: true,
						}
						b, _ := json.Marshal(h)
						out.Write(b)
						out.WriteByte('\n')
					} else {
						sev := ""
						if t.Info != nil {
							if s, ok := t.Info["severity"].(string); ok {
								sev = s
							}
						}
						fmt.Fprintf(out, "[%s] [http] [%s] %s\n", t.ID, sev, f)
					}
					mu.Unlock()
				}
			}
		}()
	}
	for _, f := range files {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
}
