# LOCAL-XSS-LAB-REPORT

A small, disposable, deliberately vulnerable local web application for the first
Chanakya AI usage exercise. One endpoint, one intentional vulnerability
(reflected XSS), loopback-only. No Chanakya source code was modified.

**Final verdict: LOCAL XSS TRAINING LAB — PASS**

---

## Files created

| File | Purpose |
|---|---|
| `labs/local-xss/app.py` | The vulnerable app: stdlib `http.server`, binds `127.0.0.1:8080`, one `/search` endpoint that reflects `q` without encoding. |
| `labs/local-xss/test_app.py` | Minimal validation (5 required checks + loopback-guard checks). Runs standalone or via pytest. |
| `labs/local-xss/README.md` | Purpose, start/stop, target URL, vulnerable endpoint, the intentional vulnerability, localhost-only warning. |
| `LOCAL-XSS-LAB-REPORT.md` | This report. |

Nothing was created inside `chanakya/`. The lab is isolated under `labs/`.

## How the lab works

`app.py` is ~120 lines of standard library only (`http.server`,
`urllib.parse`). `TrainingHandler.do_GET` serves three things:

- `GET /` — a safe landing page with a search form and a red
  "INTENTIONALLY VULNERABLE TRAINING APP" banner. Nothing is reflected here.
- `GET /search?q=<input>` — renders a results page that writes `q` **straight
  into the HTML** with no output encoding (the vulnerability).
- anything else — a 404 page.

`build_server(host, port)` constructs the `HTTPServer` and **refuses any
non-loopback bind address**, so the localhost-only guarantee is enforced in
code, not just by convention. `main()` starts it on `127.0.0.1:8080` and serves
until Ctrl+C, then shuts down and closes the socket.

Start it with `python labs/local-xss/app.py`; stop it with Ctrl+C. It holds no
state and touches no database or files.

## Localhost restriction

- `HOST = "127.0.0.1"` and `PORT = 8080` are fixed constants; `main()` binds
  exactly there.
- `build_server` raises `ValueError` for any host that is not `127.0.0.1`,
  `localhost`, or `::1` — so it can **never** be bound to `0.0.0.0` or a
  routable address through its own API.
- The app makes **no outbound network connections**, runs **no subprocess or
  shell**, holds **no credentials or real data**, and has **no** auth, database,
  uploads, RCE, SSRF, SQLi, CSRF, or any second vulnerability.
- Verified at runtime during testing: the process listened on
  `127.0.0.1:8080` (LISTENING on the loopback address, never `0.0.0.0`).

## Endpoint

```
GET http://127.0.0.1:8080/search?q=<input>
```

## Intentional vulnerability

**Reflected Cross-Site Scripting (XSS).** In `render_search(q)` the value of `q`
is interpolated into the response as `"<p>You searched for: {q}</p>"` with no
`html.escape`. A request to:

```
http://127.0.0.1:8080/search?q=<script>alert(1)</script>
```

returns the `<script>` tag verbatim (Content-Type `text/html`), so it executes
in a browser. This is the single, deliberate flaw; encoding `q` would fix it.

## Validation tests

`labs/local-xss/test_app.py` starts the lab's own handler on an ephemeral
loopback port (so it never collides with a real `:8080`) and confirms:

1. **The application starts** — `build_server` binds and serves.
2. **`127.0.0.1` responds** — `GET /` returns `200` with the training banner.
3. **`/search` responds** — `GET /search?q=hello` returns `200`.
4. **`q` is reflected** — a unique marker sent in `q` appears in the response.
5. **The reflection is intentionally unsafe** — `<script>alert(1)</script>` is
   present verbatim and was **not** HTML-encoded (`&lt;script&gt;` absent).

Plus: the configured address is `127.0.0.1:8080` (never `0.0.0.0`), and
`build_server` refuses non-loopback bind addresses. No vulnerability scanner and
no exploit framework were added.

## Test result

```
$ python labs/local-xss/test_app.py
LOCAL XSS TRAINING LAB — PASS (5/5 checks + loopback guard)

$ pytest -q -W error labs/local-xss/test_app.py
6 passed
```

The lab is not part of the Chanakya suite (`pyproject.toml` sets
`testpaths = ["tests"]`), so the Chanakya test count is unaffected (still 3056).

## Confirmation: no Chanakya source code changed

`git status` shows only the new `labs/` directory (and the pre-existing,
unrelated untracked `FINAL-V1.0.0-RELEASE-REPORT.md`). No file under `chanakya/`
or `tests/` was modified, added, or removed. The `v1.0.0` tag remains at
`1f81635`, and nothing was pushed.

---

**LOCAL XSS TRAINING LAB — PASS**
