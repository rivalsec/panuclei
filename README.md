# panuclei

A lightweight, fast **passive** nuclei matcher — a Go successor to
[pypanuclei](https://github.com/rivalsec/pypanuclei).

It loads the passive subset of nuclei-templates (a single `GET {{BaseURL}}`
request with word/regex matchers) and runs them against **saved HTTP response
files**, entirely offline. On a 1,959-response / 1,601-template run it finishes
in ~2.5s vs ~3m14s for `nuclei -passive` on the same set, across all CPU cores.

## Why not just `nuclei -passive`

- It's ~80× faster here (lean matcher, RE2 regex, goroutine worker pool).
- It is **more correct** on templates whose matcher is a header DSL: nuclei's
  offline passive engine can't read `header` in DSL, so it silently misses real
  detections (e.g. `aspnet-version-detect`); panuclei evaluates the DSL and
  catches them.

Validated: on an identical template set, **every** nuclei passive hit is also
found by panuclei (nuclei ⊆ panuclei); the extra hits are detections nuclei
misses due to that offline-DSL weakness.

## What it evaluates

- Matchers: `word`, `regex`, `status`, and `dsl` (via govaluate with the nuclei
  DSL function subset: `contains`, `tolower`/`toupper`, `regex`, `replace`,
  `len`, `startswith`/`endswith`, `tostring`, `compare_versions`, …).
- Parts: `body`, `header`/`all_headers`, `response`/`all`, and any named
  response header (`server`, `content_type`, `cf_ray`, …).
- `matchers-condition`, per-matcher `condition`, and `negative`.

Any template with a matcher it cannot fully evaluate (an unparseable DSL
expression, an unknown matcher type) is **dropped at load and counted** — a
dropped template can never produce a false positive.

## Input format

Saved HTTP responses, one per `.txt`, under a `<host>/…` tree — produced by
`httpx -sr -srd ./responses`. Two layouts are read directly:

- **response-only** (file starts with `HTTP/…`), the pypanuclei format; and
- **httpx `-srd`** (`request\r\n\r\nresponse\r\n\r\nurl`) — panuclei seeks to the
  first `HTTP/` status line and ignores httpx's trailing URL line, so AutoBB's
  `httprobes_savedir` can be scanned as-is with no staging step.

Chunked bodies are decoded.

## Usage

```bash
go build -o panuclei .

# scan
./panuclei -u ./responses -t ./nuclei-templates/http -json

# exclude a dir, and run with N workers
./panuclei -u ./responses -t ./nuclei-templates/http \
    -et ./nuclei-templates/http/technologies/ -workers 8

# list the passive templates it would run (and what it drops)
./panuclei -t ./nuclei-templates/http -dump
```

Flags: `-u` target dir, `-t` templates dir (repeatable), `-et` exclude
(repeatable), `-json`, `-dump`, `-workers`.
