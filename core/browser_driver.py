"""
WS3 / W3.2 — First-class headless browser driver (Playwright).

A SPA's real attack surface is the set of API calls its JavaScript makes — which
never appear in the static HTML. This driver renders the page in a real headless
Chromium and captures every XHR/fetch request, feeding concrete API endpoints to
the Target Model (WS2) and authenticated testing (WS3). It also runs app flows
(e.g. submit a login form) when the AI directs it.

Designed to **degrade gracefully**: if Playwright or a browser binary is not
available, every method returns an empty/neutral result and sets
`self.available = False` — it never crashes the engagement. Reuses the
system-chromium discovery pattern from `waf_ghost_engine`.
"""

import shutil
from typing import Optional

from utils.logger import get_logger

log = get_logger("browser_driver")

_CHROMIUM_BINS = ["chromium", "chromium-browser", "google-chrome",
                  "google-chrome-stable", "/snap/bin/chromium"]
_LAUNCH_ARGS = [
    "--no-sandbox", "--disable-setuid-sandbox",
    "--disable-blink-features=AutomationControlled", "--disable-infobars",
    "--ignore-certificate-errors",
]
_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
       "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")


def playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


class BrowserDriver:
    """Render SPAs and capture their real (XHR/fetch) API traffic."""

    def __init__(self, headless: bool = True, timeout_ms: int = 45000,
                 proxy: Optional[str] = None):
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.proxy = proxy
        self.available = playwright_available()
        if not self.available:
            log.debug("Playwright not installed — BrowserDriver in no-op mode.")

    @staticmethod
    def _find_chromium() -> Optional[str]:
        for b in _CHROMIUM_BINS:
            p = shutil.which(b)
            if p:
                return p
        return None

    def render(self, url: str, wait: str = "networkidle",
               extra_headers: Optional[dict] = None,
               cookies: Optional[list] = None) -> dict:
        """Render `url`, capturing HTML + every XHR/fetch request/response.

        Returns a dict (always — empty on any failure):
          {
            "ok": bool,
            "url": str,
            "html": str,
            "api_calls": [{"method","url","status","resource_type"}],
            "api_endpoints": [unique url strings that look like API calls],
            "console_errors": [str],
            "error": str | "",
          }
        """
        blank = {"ok": False, "url": url, "html": "", "api_calls": [],
                 "api_endpoints": [], "console_errors": [], "error": ""}
        if not self.available:
            blank["error"] = "playwright_unavailable"
            return blank

        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            blank["error"] = f"import_failed: {e}"
            return blank

        api_calls = []
        console_errors = []
        html = ""
        try:
            with sync_playwright() as p:
                launch_kw = {"headless": self.headless, "args": _LAUNCH_ARGS}
                exe = self._find_chromium()
                if exe:
                    launch_kw["executable_path"] = exe
                if self.proxy:
                    launch_kw["proxy"] = {"server": self.proxy}
                browser = p.chromium.launch(**launch_kw)
                ctx_kw = {"user_agent": _UA, "viewport": {"width": 1920, "height": 1080},
                          "ignore_https_errors": True}
                if extra_headers:
                    ctx_kw["extra_http_headers"] = extra_headers
                context = browser.new_context(**ctx_kw)
                if cookies:
                    try:
                        context.add_cookies(cookies)
                    except Exception as _ce:
                        log.debug(f"add_cookies failed: {_ce}")
                page = context.new_page()
                page.add_init_script(
                    "Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")

                def _on_response(resp):
                    try:
                        req = resp.request
                        rtype = req.resource_type
                        if rtype in ("xhr", "fetch") or "/api" in req.url or "graphql" in req.url:
                            api_calls.append({
                                "method": req.method,
                                "url": req.url,
                                "status": resp.status,
                                "resource_type": rtype,
                            })
                    except Exception:
                        pass

                def _on_console(msg):
                    try:
                        if msg.type == "error":
                            console_errors.append(msg.text[:300])
                    except Exception:
                        pass

                page.on("response", _on_response)
                page.on("console", _on_console)

                page.goto(url, wait_until=wait, timeout=self.timeout_ms)
                # give late XHRs a moment
                try:
                    page.wait_for_timeout(1500)
                except Exception:
                    pass
                html = page.content()
                browser.close()
        except Exception as e:
            blank["error"] = str(e)[:300]
            blank["html"] = html
            blank["api_calls"] = api_calls
            blank["api_endpoints"] = _unique_api_endpoints(api_calls)
            blank["console_errors"] = console_errors
            return blank

        return {
            "ok": True,
            "url": url,
            "html": html,
            "api_calls": api_calls,
            "api_endpoints": _unique_api_endpoints(api_calls),
            "console_errors": console_errors,
            "error": "",
        }

    def submit_login(self, login_url: str, fields: dict,
                     submit_selector: Optional[str] = None) -> dict:
        """Drive a login form in a real browser and return the resulting cookies
        + captured API traffic (so token-in-XHR logins are caught). Degrades to
        an empty result if Playwright is unavailable."""
        result = {"ok": False, "cookies": [], "api_calls": [], "error": ""}
        if not self.available:
            result["error"] = "playwright_unavailable"
            return result
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            result["error"] = f"import_failed: {e}"
            return result

        api_calls = []
        try:
            with sync_playwright() as p:
                launch_kw = {"headless": self.headless, "args": _LAUNCH_ARGS}
                exe = self._find_chromium()
                if exe:
                    launch_kw["executable_path"] = exe
                if self.proxy:
                    launch_kw["proxy"] = {"server": self.proxy}
                browser = p.chromium.launch(**launch_kw)
                context = browser.new_context(user_agent=_UA, ignore_https_errors=True)
                page = context.new_page()
                page.on("response", lambda r: api_calls.append(
                    {"url": r.request.url, "status": r.status,
                     "method": r.request.method})
                    if r.request.resource_type in ("xhr", "fetch") else None)
                page.goto(login_url, wait_until="networkidle", timeout=self.timeout_ms)
                for selector, value in fields.items():
                    try:
                        page.fill(selector, value)
                    except Exception as _fe:
                        log.debug(f"fill {selector} failed: {_fe}")
                if submit_selector:
                    page.click(submit_selector)
                else:
                    page.keyboard.press("Enter")
                page.wait_for_timeout(2500)
                cookies = context.cookies()
                browser.close()
                result.update(ok=True, cookies=cookies,
                              api_calls=[c for c in api_calls if c])
                return result
        except Exception as e:
            result["error"] = str(e)[:300]
            return result


def _unique_api_endpoints(api_calls: list) -> list:
    seen = set()
    out = []
    for c in api_calls:
        u = c.get("url", "")
        # normalize query off for dedup of the route
        route = u.split("?")[0]
        if route and route not in seen:
            seen.add(route)
            out.append(u)
    return out[:80]
