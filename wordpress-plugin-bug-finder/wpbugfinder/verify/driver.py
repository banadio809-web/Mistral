"""Recorded browser driver for verification sessions.

`Recorder` wraps Playwright Chromium and produces .webm video + HAR of the
entire verification story: logging into WordPress (wp-login.php form fill),
setting up whatever the PoC needs (plugin activation screen, pages, files),
firing the exploit and showing the observed response on-screen.  Captions
are injected as a visible overlay so the video is self-explanatory.

If Playwright is unavailable, `PlainClient` still performs the same HTTP
flow headlessly (no video) so verification never hard-fails on a missing
optional dependency.
"""

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

try:  # optional dependency — only needed for video recording
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:  # pragma: no cover
    sync_playwright = None
    HAS_PLAYWRIGHT = False

VIEWPORT = {"width": 1366, "height": 850}


def playwright_available() -> bool:
    if not HAS_PLAYWRIGHT:
        return False
    try:
        from playwright.sync_api import sync_playwright as _sp
        with _sp() as p:
            return p.chromium.executable_path is not None
    except Exception:
        return False


class Recorder:
    """Video-recorded browser session (`recorder.video_path()` at the end)."""

    def __init__(self, out_dir: str, har: bool = True):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.har = har
        self._pw = None
        self._browser = None
        self._ctx = None
        self.page = None
        self.video_path = None
        self.dialog_fired_pids = []
        self.js_property_seen = {}
        self.steps = []

    # -- lifecycle -----------------------------------------------------------
    def start(self):
        self._pw = sync_playwright().start()
        kwargs = dict(
            viewport=VIEWPORT,
            record_video_dir=self.out_dir,
            record_video_size=VIEWPORT,
        )
        if self.har:
            kwargs["record_har_path"] = os.path.join(self.out_dir, "flow.har")
        # fresh profile per recording: the login (and only that) is on camera
        self._browser = self._pw.chromium.launch(headless=True)
        self._ctx = self._browser.new_context(**kwargs)
        self._ctx.route("**/*", self._sniff_route)
        self.page = self._ctx.new_page()
        self.page.on("dialog", lambda d: (self.dialog_fired_pids.append(d.type),
                                          d.dismiss()))
        return self

    def stop(self):
        try:
            if self._ctx:
                self.page.close()
                self._ctx.close()   # flushes the .webm
                if self.har:
                    pass            # HAR is written on context close
        finally:
            if self._browser:
                self._browser.close()
            if self._pw:
                self._pw.stop()
        return self.video_path

    def _sniff_route(self, route):
        req = route.request
        if "wpbf-redirect.invalid" in req.url:
            self.js_property_seen["navbar_event"] = req.url
            route.abort()
            return
        return route.continue_() if hasattr(route, "continue_") else None

    # -- narration -----------------------------------------------------------
    def caption(self, text: str, sub: str = ""):
        """Inject a persistent, visible step caption (shows up in the video)."""
        self.steps.append({"t": time.strftime("%H:%M:%S"), "step": text})
        safe = json.dumps(text)
        safe_sub = json.dumps(sub)
        try:
            self.page.evaluate(
                """([txt, sub]) => {
                     let bar = document.getElementById('wpbf-caption');
                     if (!bar) {
                       bar = document.createElement('div');
                       bar.id = 'wpbf-caption';
                       bar.style.cssText = ['position:fixed','left:0','right:0',
                         'bottom:0','z-index:2147483647','padding:14px 22px',
                         "font-family:monospace",'font-size:18px',
                         'background:#0b1021e6','color:#7ee787',
                         'border-top:2px solid #7ee787','white-space:pre-wrap',
                         'max-height:40%','overflow:hidden'].join(';');
                       document.documentElement.appendChild(bar);
                     }
                     bar.textContent = '> ' + txt + (sub ? '\\n  ' + sub : '');
                   }""", [text, sub])
        except Exception:
            pass

    # -- story steps ----------------------------------------------------------
    def goto(self, url: str, wait: str = "load"):
        self.page.goto(url, wait_until=wait, timeout=30000)
        return self

    def login_wordpress(self, site: str, user: str, password: str,
                        who: str = "administrator"):
        """On-camera login through the real wp-login.php form."""
        self.caption(f"Logging into WordPress as '{user}' ({who})",
                     "opening wp-login.php…")
        self.goto(site.rstrip("/") + "/wp-login.php")
        self.page.fill("#user_login", user)
        self.page.fill("#user_pass", password)
        self.caption(f"Logging into WordPress as '{user}' ({who})",
                     "submitting the login form…")
        self.page.click("#wp-submit")
        self.page.wait_for_load_state("networkidle", timeout=30000)
        self.caption(f"Logged in as '{user}'", "wp-admin dashboard")

    def create_page_with_content(self, site: str, title: str, params: dict):
        """Fallback used when wp-cli setup can't express the state (kept
        on-camera via the wp-admin page editor)."""
        from urllib.parse import urlencode
        cfg = site.rstrip("/") + "/wp-admin/post-new.php?" + urlencode(params)
        self.goto(cfg)
        self.caption(f"Preparing page '{title}'", params.get("content", ""))

    def show_exploit(self, url: str, method: str = "GET",
                     params: dict = None, body: dict = None,
                     label: str = "Firing PoC request"):
        """Navigate visually (GET), or fire the request from a runner page and
        display the raw response — both fully visible in the video."""
        plain = urllib.parse.urlencode({k: str(v) for k, v in (params or {}).items()})
        if method == "GET" and plain:
            url = url + ("&" if "?" in url else "?") + plain
        if method == "GET":
            self.caption(label, url)
            resp = self.page.goto(url, wait_until="load", timeout=30000)
            body_txt = ""
            try:
                body_txt = self.page.content()
            except Exception:
                pass
            try:  # did the injected onload handler actually run?
                ran = self.page.evaluate("window.__wpbf === 1")
                if ran:
                    self.js_property_seen["__wpbf"] = True
            except Exception:
                pass
            self.caption(f"PoC response: HTTP "
                         f"{resp.status if resp else '??'}", url)
            return str(resp.status if resp else 0), body_txt

        # POST: show it happening inside a runner page (video-visible).
        # The runner must live on the site's origin — about:blank is an
        # opaque origin and Chrome blocks cross-origin fetch() from it.
        self.caption(label, f"POST {url}")
        self._goto_origin_runner(url)
        body_ser = json.dumps({k: str(v) for k, v in (body or {}).items()})
        url_ser = json.dumps(url)
        result = self.page.evaluate(
            """async ([u, b]) => {
                 const r = await fetch(u, {
                   method: 'POST',
                   headers: {'Content-Type':
                     'application/x-www-form-urlencoded'},
                   body: b, credentials: 'include'});
                 const t = await r.text();
                 return {status: r.status,
                         body: t.slice(0, 20000)};
               }""", [url, body_ser])
        self.caption(f"PoC response: HTTP {result.get('status')}",
                     (result.get("body") or "")[:400])
        return str(result.get("status")), result.get("body") or ""

    def _goto_origin_runner(self, url: str):
        """Load any same-origin page before in-page fetch() calls."""
        p = urllib.parse.urlparse(url)
        runner = f"{p.scheme}://{p.netloc}/"
        try:
            self.page.goto(runner, wait_until="load", timeout=15000)
        except Exception:
            pass

    def upload_multipart(self, url: str, field: str, filename: str,
                         content: str, extra_params: dict = None,
                         label: str = "Uploading PoC payload"):
        """Visible multipart upload: builds the request on a runner page."""
        self.caption(label, url)
        self._goto_origin_runner(url)
        spec = json.dumps({"url": url, "field": field, "filename": filename,
                           "extra": {k: str(v) for k, v in
                                     (extra_params or {}).items()}})
        content_b64 = base64.b64encode(content.encode()).decode()
        result = self.page.evaluate(
            """async ([spec, contentB64]) => {
                 const s = JSON.parse(spec);
                 const fd = new FormData();
                 Object.entries(s.extra).forEach(([k, v]) => fd.append(k, v));
                 const bytes = atob(contentB64);
                 const arr = new Uint8Array(bytes.length);
                 for (let i = 0; i < bytes.length; i++) arr[i] =
                   bytes.charCodeAt(i);
                 fd.append(s.field, new File([arr], s.filename,
                   {type: 'application/x-php'}));
                 const r = await fetch(s.url, {method: 'POST', body: fd,
                   credentials: 'include'});
                 const t = await r.text();
                 return {status: r.status, body: t.slice(0, 20000)};
               }""", [spec, content_b64])
        self.caption(f"Upload response: HTTP {result.get('status')}",
                     (result.get("body") or "")[:300])
        return str(result.get("status")), result.get("body") or ""

    def verdict_banner(self, ok: bool, text: str):
        color = "#7ee787" if ok else "#ff7b72"
        try:
            self.page.evaluate(
                """([color, txt]) => {
                     const bar = document.getElementById('wpbf-caption');
                     if (bar) { bar.style.color = color;
                                bar.textContent = '== ' + txt + ' =='; }
                   }""", [color, text])
        except Exception:
            pass

    def screenshot(self, name: str):
        try:
            p = os.path.join(self.out_dir, name)
            self.page.screenshot(path=p, full_page=False)
            return p
        except Exception:
            return None

    def finalize_video(self) -> str:
        try:
            self.video_path = self.page.video.path()
        except Exception:
            self.video_path = None
        return self.video_path


class PlainClient:
    """Headless fallback (no video): same HTTP flow via urllib."""

    def __init__(self, out_dir=None):
        self.out_dir = out_dir
        self.cookie = ""
        self.response_body = ""
        self.js_property_seen = {}
        self.probe_hits = []
        self.steps = []

    def start(self):
        return self

    def stop(self):
        return None

    def caption(self, text, sub=""):
        self.steps.append({"t": time.strftime("%H:%M:%S"), "step": text,
                           "sub": sub})
        print(f"  | {text}" + (f" — {sub}" if sub else ""))

    def _req(self, url: str, data: bytes = None, headers: dict = None):
        req = urllib.request.Request(url, data=data, headers=headers or {})
        if self.cookie:
            req.add_header("Cookie", self.cookie)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                setc = r.headers.get_all("Set-Cookie") or []
                if setc:
                    self.cookie = "; ".join(c.split(";")[0] for c in setc)
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            setc = e.headers.get_all("Set-Cookie") or []
            if setc:
                self.cookie = "; ".join(c.split(";")[0] for c in setc)
            return e.code, ""
        except (urllib.error.URLError, OSError) as exc:
            self._last_error = str(exc)
            return 0, ""

    def goto(self, url):
        return self._req(url)

    def login_wordpress(self, site, user, password, who="admin"):
        resp = urllib.request.urlopen(
            urllib.request.Request(site.rstrip("/") + "/wp-login.php"))
        body = resp.read().decode("utf-8", "replace")
        self.cookie = ""
        fields = dict(zip(
            re.findall(r"name=['\"]([^'\"]+)['\"]", body),
            [""]))
        import re as _re
        redeem = _re.search(r"name=['\"]pwd['\"]", body)
        data = {"log": user, "pwd": password,
                "wp-submit": "Log In", "redirect_to": site,
                "testcookie": "1"}
        fields.update(data)
        enc = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(site.rstrip("/") +
                                     "/wp-login.php", data=enc)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                setc = r.headers.get_all("Set-Cookie") or []
                self.cookie = "; ".join(c.split(";")[0] for c in setc)
        except urllib.error.HTTPError as e:
            setc = e.headers.get_all("Set-Cookie") or []
            self.cookie = "; ".join(c.split(";")[0] for c in setc)

    def show_exploit(self, url, method="GET", params=None, body=None,
                     label="Firing PoC request"):
        self.caption(label, url)
        plain = urllib.parse.urlencode({k: str(v) for k, v in
                                        (params or {}).items()})
        if method == "GET" and plain:
            url = url + ("&" if "?" in url else "?") + plain
        if method == "GET":
            status, text = self._req(url)
            return str(status), text
        data = urllib.parse.urlencode(
            {k: str(v) for k, v in (body or {}).items()}).encode()
        status, text = self._req(url, data=data, headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        return str(status), text

    def upload_multipart(self, url, field, filename, content,
                         extra_params=None, label="Uploading PoC payload"):
        self.caption(label, url)
        boundary = "----wpbfpoc"
        parts = []
        for k, v in (extra_params or {}).items():
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                         f'name="{k}"\r\n\r\n{v}\r\n')
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; '
                     f'name="{field}"; filename="{filename}"\r\n'
                     f'Content-Type: application/x-php\r\n\r\n{content}\r\n'
                     f'--{boundary}--\r\n')
        data = "".join(parts).encode()
        status, text = self._req(
            url, data=data,
            headers={"Content-Type": f"multipart/form-data; "
                                     f"boundary={boundary}"})
        return str(status), text

    def verdict_banner(self, ok, text):
        self.caption(("VERIFIED" if ok else "NOT REPRODUCED"), text)

    def screenshot(self, name):
        return None

    def finalize_video(self):
        return None
