# Local XSS Training Lab

> ⚠️ **INTENTIONALLY VULNERABLE TRAINING CODE.** This application contains a
> deliberate security vulnerability. It exists only so you can practise using
> the Chanakya AI security agent against a known, controlled target. **Never
> deploy it, and never expose it beyond `127.0.0.1`.**

## 1. Purpose

A tiny, disposable, single-file web application with **exactly one** intentional
vulnerability — **reflected Cross-Site Scripting (XSS)** — used as the first
practice target for Chanakya. It has no authentication, no database, no user
data, no file uploads, no subprocess/shell execution, and makes no outbound
network connections. Standard library only (`http.server`).

## 2. How to start the application

From the repository root:

```
python labs/local-xss/app.py
```

It prints the listening address and the vulnerable endpoint, then serves until
you stop it. No arguments, no configuration, no dependencies to install.

## 3. Target URL

```
http://127.0.0.1:8080/
```

The landing page (`/`) is safe and shows a search form.

## 4. Vulnerable endpoint

```
GET /search?q=<input>
```

Example:

```
http://127.0.0.1:8080/search?q=hello
```

## 5. What vulnerability is intentionally present

**Reflected XSS.** The value of the `q` query parameter is written straight into
the HTML response with **no output encoding** (`render_search` in `app.py`
interpolates `q` without `html.escape`). A request such as:

```
http://127.0.0.1:8080/search?q=<script>alert(1)</script>
```

returns the `<script>` tag verbatim, so it executes in the browser. Encoding
`q` would fix it — that is deliberately omitted here. This is the **only**
vulnerability in the lab.

## 6. How to stop the application

Press **Ctrl+C** in the terminal running `app.py`. The server shuts down and
closes its socket. Because it holds no state and touches no database or files,
stopping it leaves nothing behind.

## 7. Warning: localhost only

The application binds **only** to `127.0.0.1` and refuses any non-loopback bind
address (`build_server` raises on anything but `127.0.0.1` / `localhost` /
`::1`). It must **never** be changed to listen on `0.0.0.0` or any routable
address, and must never be placed on a network, a shared host, or the public
internet. It is intentionally insecure; exposing it would be exposing a real
vulnerability.

---

*Validation:* `python labs/local-xss/test_app.py` (or
`pytest -q labs/local-xss/test_app.py`) confirms the app starts, responds on
`127.0.0.1`, serves `/search`, reflects `q`, and reflects it unsafely. This lab
is isolated from the Chanakya source under `labs/` and is not part of the
Chanakya test suite.
