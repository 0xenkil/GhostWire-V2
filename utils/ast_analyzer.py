"""
Grey-Box Route Extraction — AST Analyzer

Statically analyzes available source code to extract API routes,
database table names, and other structural information to seed
exploitation wordlists.

Supports: Express.js, Flask, Django, Laravel, Next.js
"""

import os
import re
from pathlib import Path
from utils.logger import get_logger

log = get_logger("ast_analyzer")

# Directories to skip during recursive crawl
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv",
    "dist", "build", ".next", ".nuxt", "coverage", ".tox",
    "vendor", "bower_components", ".cache",
}

# File extensions to skip
SKIP_EXTENSIONS = {
    ".min.js", ".map", ".lock", ".svg", ".png", ".jpg", ".ico",
    ".woff", ".ttf", ".eot", ".gif", ".pdf", ".zip", ".gz",
}

# Max file size to analyze (bytes)
MAX_FILE_SIZE = 500 * 1024  # 500KB

# Max routes to extract
MAX_ROUTES = 500

# Framework-specific route patterns
PATTERN_MAP = {
    # Express.js: app.get('/api/users', ...), router.post('/admin', ...)
    "express": [
        re.compile(
            r"""(?:app|router)\.\s*(?:get|post|put|delete|patch|options|all|use)"""
            r"""\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE
        ),
    ],
    # Flask: @app.route('/api/users')
    "flask": [
        re.compile(
            r"""@\s*(?:app|blueprint|bp)\s*\.\s*route\s*\(\s*['"]([^'"]+)['"]""",
            re.IGNORECASE
        ),
    ],
    # Django: path('api/users/', views.user_list)
    "django": [
        re.compile(
            r"""(?:path|re_path|url)\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE
        ),
    ],
    # Laravel: Route::get('/api/users', ...)
    "laravel": [
        re.compile(
            r"""Route\s*::\s*(?:get|post|put|delete|patch|options|any|match|group)"""
            r"""\s*\(\s*['"]([^'"]+)['"]""", re.IGNORECASE
        ),
    ],
    # Next.js: pages/api/*.js -> /api/* routes
    "nextjs": [
        re.compile(r"""(?:pages|app)/api/([^\s'"]+)""", re.IGNORECASE),
    ],
    # Generic: fetch('/api/...'), axios.get('/api/...')
    "generic": [
        re.compile(
            r"""(?:fetch|axios\.\w+|\.get|\.post|\.put|\.delete)"""
            r"""\s*\(\s*['"](/[^'"]+)['"]""", re.IGNORECASE
        ),
        re.compile(r"""['"](/api/[^'"]+)['"]"""),
    ],
}

# Table/model patterns
TABLE_PATTERNS = [
    re.compile(r"""__tablename__\s*=\s*['"]([^'"]+)['"]"""),
    re.compile(r"""class\s+(\w+)\s*\(\s*models\.Model\s*\)"""),
    re.compile(r"""(?:FROM|INTO|UPDATE|JOIN)\s+[`"']?(\w+)[`"']?""", re.IGNORECASE),
    re.compile(r"""model\s+(\w+)\s*\{"""),
    re.compile(r"""mongoose\.model\s*\(\s*['"](\w+)['"]"""),
]


def analyze_source_directory(source_dir: str) -> dict:
    """
    Recursively analyze a source directory for routes and database tables.

    Returns:
        {"routes": list[str], "tables": list[str], "framework": str}
    """
    source_path = Path(source_dir)
    if not source_path.exists() or not source_path.is_dir():
        log.warning(f"Source directory not found: {source_dir}")
        return {"routes": [], "tables": [], "framework": "unknown"}

    routes = set()
    tables = set()
    framework = _detect_framework(source_path)
    files_scanned = 0

    log.info(f"Scanning source: {source_dir} (detected: {framework})")

    active_patterns = PATTERN_MAP.get(framework, []) + PATTERN_MAP["generic"]

    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = Path(root) / filename

            if any(filename.endswith(ext) for ext in SKIP_EXTENSIONS):
                continue

            try:
                if filepath.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            if not _is_code_file(filename):
                continue

            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
                files_scanned += 1

                for pattern in active_patterns:
                    for match in pattern.finditer(content):
                        route = match.group(1).strip()
                        if route and _is_valid_route(route):
                            routes.add(_normalize_route(route))

                for pattern in TABLE_PATTERNS:
                    for match in pattern.finditer(content):
                        table = match.group(1).strip()
                        if table and len(table) > 1 and not table.startswith("_"):
                            tables.add(table.lower())

            except Exception as e:
                log.debug(f"Failed to read {filepath}: {e}")
                continue

            if len(routes) >= MAX_ROUTES:
                log.warning(f"Hit MAX_ROUTES cap ({MAX_ROUTES}). Stopping scan.")
                break

    route_list = sorted(list(routes))[:MAX_ROUTES]
    table_list = sorted(list(tables))

    log.info(
        f"AST analysis complete: {files_scanned} files, "
        f"{len(route_list)} routes, {len(table_list)} tables"
    )

    return {
        "routes": route_list,
        "tables": table_list,
        "framework": framework,
        "files_scanned": files_scanned,
    }


def _detect_framework(source_path: Path) -> str:
    """Detect the framework from project structure and config files."""
    indicators = {
        "nextjs":  ["next.config.js", "next.config.ts", "next.config.mjs"],
        "express": ["app.js", "server.js"],
        "flask":   ["app.py", "wsgi.py"],
        "django":  ["manage.py", "settings.py", "urls.py"],
        "laravel": ["artisan", "composer.json"],
    }

    pkg_json = source_path / "package.json"
    if pkg_json.exists():
        try:
            content = pkg_json.read_text(encoding="utf-8")
            if "next" in content:
                return "nextjs"
            if "express" in content:
                return "express"
        except Exception:
            pass

    for framework, files in indicators.items():
        for f in files:
            if (source_path / f).exists():
                return framework
            for child in source_path.iterdir():
                if child.is_dir() and (child / f).exists():
                    return framework

    return "generic"


def _is_code_file(filename: str) -> bool:
    """Check if a file is a source code file worth analyzing."""
    code_extensions = {
        ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".php",
        ".java", ".go", ".rs", ".vue", ".svelte",
    }
    return any(filename.endswith(ext) for ext in code_extensions)


def _is_valid_route(route: str) -> bool:
    """Filter out invalid or noisy route matches."""
    if len(route) < 2 or len(route) > 200:
        return False
    if not route.startswith("/"):
        return False
    static_exts = {".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"}
    if any(route.endswith(ext) for ext in static_exts):
        return False
    noise = {"/#", "/.", "//", "/*"}
    if any(n in route for n in noise):
        return False
    return True


def _normalize_route(route: str) -> str:
    """Normalize a route for wordlist use."""
    route = route.split("?")[0].split("#")[0]
    route = re.sub(r":\w+", "FUZZ", route)
    route = re.sub(r"\{[^}]+\}", "FUZZ", route)
    if not route.startswith("/"):
        route = "/" + route
    if len(route) > 1 and route.endswith("/"):
        route = route.rstrip("/")
    return route


def generate_wordlist(routes: list[str]) -> str:
    """
    Convert extracted routes into a gobuster/ffuf-compatible wordlist string.
    Each line is a path without leading slash.
    """
    words = set()
    for route in routes:
        clean = route.lstrip("/")
        if not clean:
            continue
        # Add the full path
        words.add(clean)
        # Also add each path segment individually
        for segment in clean.split("/"):
            segment = segment.strip()
            if segment and segment != "FUZZ" and not re.match(r'^[{:\[]', segment):
                words.add(segment)
    return "\n".join(sorted(words))

