import gzip
import hashlib
import io
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

import pytest

from campusnet import diagnostics as d
from campusnet.config import Config
from campusnet.detector import Detection, NetStatus
from campusnet.session import HttpError


@pytest.mark.parametrize("text", [
    'username=LEAK&ac_id=7', 'password="LEAK"', "'user_password': 'LEAK'",
    'access_token=LEAK', 'Cookie: session=LEAK\nServer: test',
    'Set-Cookie: any=LEAK; Path=/', 'Authorization: Bearer LEAK',
    '<input value="LEAK" name="unfamiliar_field">', '<input name=other value=LEAK>',
    '<textarea name=anything>LEAK</textarea>', 'https://someone:LEAK@portal.example/',
    'sessionStorage.setItem("x", "LEAK")', '账号：LEAK，接口：/portal',
    'http://portal/?password%3DLEAK%26ac_id%3D7',
    '{"cookie":"LEAK", "api":"/login"}',
])
def test_common_secrets_are_hidden(text):
    assert "LEAK" not in d.Redactor().text(text)


def test_known_values_encodings_and_nested_data():
    secret = 'secret<&/中文'
    redact = d.Redactor([secret])
    for value in (secret, quote(secret, safe=""), json.dumps(secret, ensure_ascii=True)[1:-1]):
        assert value not in redact.text(value)
    data = redact.data({"password": {"unexpected": "hidden"}, "ac_id": "7", "items": ["pwd=LEAK"]})
    assert data["password"] == d.HIDDEN and data["ac_id"] == "7"
    assert "LEAK" not in json.dumps(data)


def test_network_addresses_remain_useful_and_identifiers_are_hidden():
    result = d.Redactor().text(r'C:\Users\PrivateUser\app 10.2.3.4 255.255.255.0 AA-BB-CC-DD-EE-FF https://portal.example:8443/srun?ac_id=9')
    assert "PrivateUser" not in result and "AA-BB" not in result
    assert "10.2.3.4" in result and "ac_id=9" in result and ":8443/srun" in result


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(d, "network_snapshot", lambda: {"gateway": "10.1.1.1"})
    monkeypatch.setattr(d.detector, "check_online", lambda s: NetStatus(detail="离线测试"))
    monkeypatch.setattr(d.detector, "detect", lambda *a: Detection(detail="无法识别测试页面"))
    monkeypatch.setattr(Config, "resolve_password", lambda *a, **kw: "credential-secret")
    return Config(username="test-account", portal_mode="auto"), tmp_path / "现场数据.7z"


def unpack(archive, folder):
    result = subprocess.run([str(d.seven_zip_executable()), "x", str(archive), "-o" + str(folder), "-y"],
                            capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return folder


@pytest.mark.skipif(os.name != "nt", reason="Windows 内置压缩组件")
def test_export_real_archive_redaction_manifest_and_no_config_changes(isolated, tmp_path):
    cfg, output = isolated
    cfg.path = str(tmp_path / "config.json")
    cfg.save()
    before = Path(cfg.path).read_bytes()
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "watch.log").write_text("test-account credential-secret token=LEAK\nGET http://10.1.1.1/portal", encoding="utf-8")
    (logs / "not-collected.log").write_text("UNRELATED", encoding="utf-8")
    result = d.export_environment(cfg, output, log_directory=logs, ui_log="password=LEAK")
    assert result.path == str(output) and result.warnings == 1 and result.size > 0
    assert output.read_bytes()[:6] == b"7z\xbc\xaf\x27\x1c"
    extracted = unpack(output, tmp_path / "extracted")
    text = "\n".join(p.read_text(encoding="utf-8") for p in extracted.rglob("*") if p.is_file())
    for value in ("test-account", "credential-secret", "LEAK", "UNRELATED"):
        assert value not in text
    manifest = json.loads((extracted / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest:
        data = (extracted / entry["file"]).read_bytes()
        assert len(data) == entry["size"] and hashlib.sha256(data).hexdigest() == entry["sha256"]
    assert Path(cfg.path).read_bytes() == before
    assert not list(tmp_path.glob(".campusnet-export-*"))


def test_network_failure_still_exports_partial_evidence(isolated, monkeypatch):
    cfg, output = isolated
    monkeypatch.setattr(d, "network_snapshot", lambda: (_ for _ in ()).throw(OSError("offline")))
    seen = {}
    def compress(folder, target, cancel):
        seen.update(json.loads((folder / "report.json").read_text(encoding="utf-8")))
        target.write_bytes(b"test archive")
    monkeypatch.setattr(d, "compress_7z", compress)
    result = d.export_environment(cfg, output, log_directory=output.parent)
    assert result.warnings == 2 and "offline" in seen["warnings"][0]


@pytest.mark.parametrize("failure", ["cancel", "compress", "read"])
def test_cancellation_or_failure_preserves_existing_file_and_removes_staging(isolated, monkeypatch, failure):
    cfg, output = isolated
    output.write_bytes(b"existing user file")
    cancel = threading.Event()
    if failure == "cancel":
        cancel.set()
    elif failure == "compress":
        monkeypatch.setattr(d, "compress_7z", lambda *a: (_ for _ in ()).throw(d.ExportError("compression error")))
    else:
        monkeypatch.setattr(d.detector, "check_online", lambda *a: (_ for _ in ()).throw(d.ExportCancelled("cancel")))
    with pytest.raises((d.ExportCancelled, d.ExportError)):
        d.export_environment(cfg, output, cancel=cancel, log_directory=output.parent)
    assert output.read_bytes() == b"existing user file"
    assert not list(output.parent.glob(".campusnet-export-*"))


def test_manual_page_is_collected_before_unreachable_probes(isolated, monkeypatch):
    cfg, output = isolated
    cfg.portal_mode = "manual"
    cfg.portal_ip = "https://school.example/login"
    seen = []
    monkeypatch.setattr(d.detector, "detect", lambda *a: seen.append("portal") or Detection())
    monkeypatch.setattr(d.detector, "check_online", lambda *a: seen.append("probes") or NetStatus())
    monkeypatch.setattr(d, "compress_7z", lambda folder, dest, cancel: dest.write_bytes(b"archive"))
    d.export_environment(cfg, output, log_directory=output.parent)
    assert seen == ["portal", "probes"]


@pytest.fixture
def page_server():
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path, self.headers.get("Cookie"), self.headers.get("Authorization")))
            self.send_response(302 if self.path == "/redirect" else 200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            if self.path == "/redirect":
                self.send_header("Location", "/unknown?ac_id=3")
            self.send_header("Set-Cookie", "danger=LEAK")
            self.end_headers()
            self.wfile.write(b'<title>Unknown campus</title><input name="token" value="LEAK"><script>var password="LEAK";</script>')
        def log_message(self, *_):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:" + str(server.server_port), seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_real_http_capture_and_read_only_guard(page_server, tmp_path):
    base, seen = page_server
    session = d.CaptureSession(tmp_path, d.Redactor(), threading.Event(), lambda _: None, Config())
    response = session.get(base + "/redirect")
    assert response.status == 302 and len(seen) == 1  # No implicit redirect/cookies.
    session.get(base + "/unknown")
    for path in ("/logout", "/api?action=login", "/?password=LEAK", "/?access_token=LEAK"):
        with pytest.raises(HttpError):
            session.get(base + path)
    with pytest.raises(HttpError):
        session.post(base + "/submit", {"password": "LEAK"})
    assert len(seen) == 2 and all(cookie is None and auth is None for _, cookie, auth in seen)
    text = json.dumps(session.records) + "".join(p.read_text(encoding="utf-8") for p in (tmp_path / "pages").iterdir())
    assert "LEAK" not in text and "set-cookie" not in text.lower()
    assert session.records[0]["headers"]["location"] == "/unknown?ac_id=3"


@pytest.mark.parametrize("compressed", [False, True])
def test_response_size_cap_including_compressed_bomb(tmp_path, monkeypatch, compressed):
    monkeypatch.setattr(d, "BODY_LIMIT", 1024)
    session = d.CaptureSession(tmp_path, d.Redactor(), threading.Event(), lambda _: None, Config())
    raw = b"x" * 100000
    stream = io.BytesIO(gzip.compress(raw) if compressed else raw)
    stream.headers = {"Content-Encoding": "gzip" if compressed else ""}
    assert session._read(stream) == b"x" * 1024 and session.truncated and stream.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows 内置压缩组件")
def test_large_export_over_40_mib_uses_real_7z_and_roundtrips(tmp_path):
    folder = tmp_path / "input"
    folder.mkdir()
    payload = folder / "超过40MB的数据.bin"
    with payload.open("wb") as stream:
        block = bytes(range(256)) * 4096
        for _ in range(41):
            stream.write(block)
    output = tmp_path / "large.7z"
    d.compress_7z(folder, output, threading.Event())
    extracted = unpack(output, tmp_path / "large-extracted")
    assert payload.stat().st_size > 40 * 1024 * 1024
    assert hashlib.sha256(payload.read_bytes()).digest() == hashlib.sha256((extracted / payload.name).read_bytes()).digest()


def test_cli_export_parsing():
    from campusnet.cli import build_parser, cmd_export
    args = build_parser().parse_args(["export-environment", "--output", "example.7z", "--portal", "https://test.example/"])
    assert args.func is cmd_export and args.output == "example.7z"


def test_cancel_during_response_closes_stream(tmp_path):
    cancel = threading.Event()
    session = d.CaptureSession(tmp_path, d.Redactor(), cancel, lambda _: None, Config())
    class Stream(io.BytesIO):
        def read(self, size):
            cancel.set()
            return super().read(size)
    stream = Stream(b"a" * 100000)
    stream.headers = {}
    with pytest.raises(d.ExportCancelled):
        session._read(stream)
    assert stream.closed


@pytest.mark.parametrize("reason", ["requests", "deadline", "cancel"])
def test_capture_limits_do_not_start_new_request(tmp_path, reason):
    cancel = threading.Event()
    session = d.CaptureSession(tmp_path, d.Redactor(), cancel, lambda _: None, Config())
    if reason == "requests":
        session.records = [{}] * d.REQUEST_LIMIT
    elif reason == "deadline":
        session.deadline = 0
    else:
        cancel.set()
    with pytest.raises((HttpError, d.ExportCancelled)):
        session.get("http://unused.invalid/")


def test_log_cap_is_recorded_and_only_tail_is_exported(isolated, monkeypatch):
    cfg, output = isolated
    (output.parent / "watch.log").write_text("old entry\npassword=LEAK\nlast line\n", encoding="utf-8")
    monkeypatch.setattr(d, "LOG_LIMIT", 24)
    seen = {}
    def compress(folder, target, cancel):
        seen["log"] = (folder / "logs/watch.log.txt").read_text(encoding="utf-8")
        seen["report"] = json.loads((folder / "report.json").read_text(encoding="utf-8"))
        target.write_bytes(b"archive")
    monkeypatch.setattr(d, "compress_7z", compress)
    d.export_environment(cfg, output, log_directory=output.parent)
    assert "old entry" not in seen["log"] and "LEAK" not in seen["log"]
    assert "last line" in seen["log"] and seen["report"]["logs"][0]["truncated"]


def test_invalid_output_and_missing_component_fail_before_collection(isolated, monkeypatch):
    cfg, output = isolated
    monkeypatch.setattr(d, "network_snapshot", lambda: pytest.fail("should not collect"))
    with pytest.raises(d.ExportError, match="7z"):
        d.export_environment(cfg, output.with_suffix(".zip"))
    with pytest.raises(d.ExportError, match="文件夹"):
        d.export_environment(cfg, output.parent / "missing" / "out.7z")
    monkeypatch.setattr(d, "SEVEN_ZIP_SHA256", "invalid")
    with pytest.raises(d.ExportError, match="组件"):
        d.export_environment(cfg, output)


def test_compression_process_is_killed_on_cancel(tmp_path, monkeypatch):
    cancel = threading.Event()
    class Process:
        returncode = None
        killed = False
        def communicate(self, timeout=None):
            if timeout:
                cancel.set()
                raise subprocess.TimeoutExpired("7zr", timeout)
            return b"", b""
        def poll(self):
            return None
        def kill(self):
            self.killed = True
    process = Process()
    monkeypatch.setattr(d.subprocess, "Popen", lambda *a, **kw: process)
    with pytest.raises(d.ExportCancelled):
        d.compress_7z(tmp_path, tmp_path / "output.7z", cancel)
    assert process.killed
