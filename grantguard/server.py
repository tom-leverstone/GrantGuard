"""
GrantGuard — local web UI.

Serves a tiny single-page app from the standard-library HTTP server (no Flask,
no pip). Opens your browser, shows the classification grouped by source file,
and lets you choose what to keep or remove. Nothing is written until you apply.

Security: binds to loopback only; rejects non-loopback Host (DNS-rebinding) and
cross-origin Origin (CSRF); the secret-bearing /api endpoints require a
per-session token (passed in the launch URL) so co-located local users can't
read findings or trigger writes; writes are restricted to the exact settings
files the current audit discovered, and never through symlinks.
"""
import json
import mimetypes
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .core import audit as audit_core
from .core import sources
from .core.tolerance import tolerance_from_name
from .core.types import RISK_CATEGORY_INFO, PermissionRule, RuleReadStatus

WEB_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "web"))
MAX_BODY = 10 * 1024 * 1024  # 10 MB cap on request bodies
LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
# ThreadingHTTPServer handles each request on its own thread; _lock guards every
# read/write of _cfg, and "gen" (bumped on scope change) keeps a slow audit that
# started under an old scope from caching its report over the new scope's.
_lock = threading.Lock()
_cfg = {"paths": None, "scan": False, "deep_scan": False, "tolerance": "default",
        "token": "", "port": 8770, "report": None, "gen": 0}
SCOPE_MODES = ("user", "targets", "scan", "deep-scan")


def _snapshot():
    """A consistent view of the scope config plus its generation."""
    with _lock:
        return ({k: _cfg[k] for k in ("paths", "scan", "deep_scan", "tolerance")},
                _cfg["gen"])


def _documents():
    """Pick the documents to audit from the current session scope."""
    cfg, _ = _snapshot()
    return sources.select_documents(cfg["paths"], scan=cfg["scan"],
                                    deep_scan=cfg["deep_scan"])


def _project_root():
    """The new CLI no longer infers a project from launch location."""
    return None


def _audit_scope(paths, scan, deep_scan, tolerance):
    """Run a full audit for the given scope without touching _cfg."""
    docs = sources.select_documents(paths, scan=scan, deep_scan=deep_scan)
    return audit_core.audit_documents(docs, tolerance_from_name(tolerance),
                                      project_root=_project_root())


def _build_report():
    """Audit the current scope; cache the report unless the scope moved on."""
    cfg, gen = _snapshot()
    report = _audit_scope(cfg["paths"], cfg["scan"], cfg["deep_scan"],
                          cfg["tolerance"])
    with _lock:
        if _cfg["gen"] == gen:
            _cfg["report"] = report
    return report


def _scope_json(scope_cfg=None):
    """The active scan scope, in the shape web/app.js renders."""
    cfg = scope_cfg if scope_cfg is not None else _snapshot()[0]
    if cfg["scan"]:
        mode = "scan"
    elif cfg["deep_scan"]:
        mode = "deep-scan"
    elif cfg["paths"]:
        mode = "targets"
    else:
        mode = "user"
    return {"mode": mode, "targets": list(cfg["paths"] or [])}


def _set_scope(mode, targets):
    """Validate and apply a new session scan scope; return (status, payload).

    Mirrors the CLI contract: "user" audits user-level sources, "targets"
    audits explicit files/dirs, "scan"/"deep-scan" discover under target roots
    ("deep-scan" with no targets is the broad sweep). The new scope's report is
    built first and committed atomically, so a failed change leaves the session
    untouched; on success the scope persists and /api/audit re-runs use it.
    """
    if mode not in SCOPE_MODES:
        return 400, {"error": "mode must be one of: " + ", ".join(SCOPE_MODES)}
    if not isinstance(targets, list) or not all(isinstance(t, str) for t in targets):
        return 400, {"error": "targets must be a list of path strings"}
    targets = [t.strip() for t in targets if t.strip()] if mode != "user" else []
    if mode == "targets" and not targets:
        return 400, {"error": "'targets' scope needs at least one target path"}
    scan, deep_scan = mode == "scan", mode == "deep-scan"
    with _lock:
        tolerance = _cfg["tolerance"]
    try:
        sources.validate_scope_targets(targets)
        report = _audit_scope(targets or None, scan, deep_scan, tolerance)
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:  # keep the handler thread and session consistent
        return 500, {"error": f"audit failed: {exc}"}
    with _lock:
        _cfg.update(paths=targets or None, scan=scan, deep_scan=deep_scan,
                    report=report)
        _cfg["gen"] += 1
    # ASCII only: Windows CI pipes stdout as cp1252, where "→" raises.
    print(f"    scope -> {mode}" + (": " + ", ".join(targets) if targets else ""))
    return 200, _report_to_json(
        report, scope={"mode": mode, "targets": targets})


def _report_to_json(report, scope=None):
    """Serialize an AuditReport into the shape web/app.js consumes."""
    out_sources = []
    for da in report.document_audits:
        info = da.document.info
        items = []
        for a in da.assessments:
            ci = RISK_CATEGORY_INFO[a.category]
            items.append({
                "rule": a.rule.text,                       # raw value (exact removal identity)
                "display": a.display_text,                  # masked for display
                "reason": a.category.value,
                "label": ci.label,
                "emoji": ci.emoji,
                "tier": a.recommendation.value,
                "recommend_remove": a.should_remove,
            })
        out_sources.append({
            "path": info.path,
            "label": info.label,
            "editable": info.editable,
            "total": da.total,
            "counts": {c.value: n for c, n in da.counts.items()},
            "items": items,
            "read_error": da.read_result.status is not RuleReadStatus.OK,
        })
    return {
        "platform": report.platform,
        "home": report.home,
        "project_root": report.project_root,
        "scope": scope if scope is not None else _scope_json(),
        "sources": out_sources,
    }


def _find_audit(report, target):
    """The PermissionDocumentAudit whose document path matches target (by realpath)."""
    real = os.path.realpath(target)
    for da in report.document_audits:
        if os.path.realpath(da.document.info.path) == real:
            return da
    return None


def _safe_static(name):
    """Resolve a static asset name strictly inside WEB_DIR, else None.

    Canonical-path containment — rejects separators, traversal, drive letters and
    absolute paths (incl. the Windows `C:\\...` / backslash cases).
    """
    if not name or "/" in name or "\\" in name or ".." in name or ":" in name or os.path.isabs(name):
        return None
    fp = os.path.realpath(os.path.join(WEB_DIR, name))
    if os.path.commonpath([WEB_DIR, fp]) != WEB_DIR or not os.path.isfile(fp):
        return None
    return fp


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def _local_only(self):
        """Reject DNS-rebinding (bad Host) and cross-site/other-port Origin (CSRF)."""
        hostname = self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]")
        if hostname not in LOCAL_HOSTS:
            return False
        origin = self.headers.get("Origin")
        if origin:
            o = urlparse(origin)
            port = o.port or (443 if o.scheme == "https" else 80)
            if (o.hostname or "").strip("[]") not in LOCAL_HOSTS or port != _cfg["port"]:
                return False
        return True

    def _authed(self):
        # constant-time compare of the per-session token (header or ?t= query)
        sent = self.headers.get("X-GrantGuard-Token", "")
        if not sent:
            from urllib.parse import parse_qs
            sent = (parse_qs(urlparse(self.path).query).get("t") or [""])[0]
        return bool(_cfg["token"]) and secrets.compare_digest(sent, _cfg["token"])

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._local_only():
            return self._send(403, {"error": "forbidden"})
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            return self._serve_file(os.path.join(WEB_DIR, "index.html"))
        if path == "/api/audit":
            if not self._authed():
                return self._send(403, {"error": "unauthorized"})
            return self._send(200, _report_to_json(_build_report()))
        fp = _safe_static(path.lstrip("/"))   # static assets only, inside WEB_DIR
        if fp:
            return self._serve_file(fp)
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._local_only():
            return self._send(403, {"error": "forbidden"})
        path = self.path.split("?")[0]
        if path not in ("/api/apply", "/api/scope"):
            return self._send(404, {"error": "not found"})
        if not self._authed():
            return self._send(403, {"error": "unauthorized"})
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY:
            return self._send(413, {"error": "request too large"})
        try:
            payload = json.loads(self.rfile.read(length) or "{}")
        except (ValueError, json.JSONDecodeError):
            return self._send(400, {"error": "invalid JSON"})
        if not isinstance(payload, dict):
            return self._send(400, {"error": "body must be a JSON object"})
        if path == "/api/scope":
            code, body = _set_scope(payload.get("mode"), payload.get("targets", []))
            return self._send(code, body)
        target = payload.get("file")
        rules = payload.get("remove", [])
        if not isinstance(rules, list):
            return self._send(400, {"error": "remove must be a list"})
        # Resolve against the cached session report: only files this audit found,
        # and only editable ones (managed/claude-state are editable=False). The
        # document itself refuses to write through a symlink.
        with _lock:
            report = _cfg["report"]
        report = report or _build_report()
        da = _find_audit(report, target) if target else None
        if da is None or not da.document.info.editable:
            return self._send(400, {"error": "not an audited writable settings file"})
        rule_objs = [PermissionRule(r) for r in rules if isinstance(r, str)]
        result = da.document.remove_rules(rule_objs)
        _build_report()       # refresh the session report after the write
        self._send(200, {"removed": result.removed, "remaining": result.remaining,
                         "had_secret": result.had_secret, "status": result.status.value,
                         "message": result.message})

    def _serve_file(self, fp):
        if not os.path.isfile(fp):
            return self._send(404, "missing", "text/plain")
        with open(fp, "rb") as f:
            self._send(200, f.read(), mimetypes.guess_type(fp)[0] or "application/octet-stream")


def serve(paths=None, scan=False, deep_scan=False, tolerance="default",
          port=8770, open_browser=True):
    _cfg.update(paths=list(paths) if paths else None, scan=scan, deep_scan=deep_scan,
                tolerance=tolerance, port=port, token=secrets.token_urlsafe(24))
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/?t={_cfg['token']}"
    print("🛡️  GrantGuard UI — open this URL (it carries a one-time access token):")
    print("   ", url)
    if _cfg["paths"]:
        label = "Shallow scan" if _cfg["scan"] else "Deep scan" if _cfg["deep_scan"] else "Auditing"
        print(f"    {label}:", ", ".join(_cfg["paths"]))
    elif _cfg["deep_scan"]:
        print("    Deep scan: broad discovery")
    else:
        print("    Inspecting user-level Claude settings sources")
    print("    Press Ctrl+C to stop.")
    if open_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 GrantGuard UI closed.")
        httpd.shutdown()


if __name__ == "__main__":
    serve()
