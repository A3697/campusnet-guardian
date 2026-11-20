"""联网状态判定 + 门户探测 + 指纹识别。

联网判断使用不同类型的响应交叉验证：

1. **劫持探测** —— ``generate_204`` 这类地址在真正联网时必须返回 204；
   被 Portal 拦截时会变成 302 或直接吐登录页 HTML。
2. **真实内容校验** —— 抓一个正常网页并检查内容标记。
   探测地址可能被白名单放行，不能只看第 1 项。
   探测服务不可用且没有认证跳转时，要求至少两个正常网页通过校验。
"""

from __future__ import annotations

import platform
import re
import subprocess
import time
from html import unescape
from html.parser import HTMLParser
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urljoin, urlsplit, urlunsplit

from .config import Config
from . import carrier
from .procflags import no_window_kwargs
from .providers import DetectContext, fingerprint, rank
from .session import HttpError, Response, Session, origin

#: (地址, 期望状态码, 正文必须包含的标记)
HIJACK_PROBES: Sequence[Tuple[str, int, Optional[str]]] = (
    ("http://connect.rom.miui.com/generate_204", 204, None),
    ("http://edge.microsoft.com/captiveportal/generate_204", 204, None),
    ("http://www.msftconnecttest.com/connecttest.txt", 200, "Microsoft Connect Test"),
)

#: (地址, 正文必须包含的标记) —— 真实内容校验
CONTENT_PROBES: Sequence[Tuple[str, str]] = (
    ("http://www.baidu.com", "baidu"),
    ("http://www.qq.com", "qq"),
    ("http://www.bing.com", "bing"),
)


@dataclass
class NetStatus:
    online: bool = False
    portal_url: str = ""
    probe: str = ""
    status: int = 0
    detail: str = ""
    authenticated: Optional[bool] = None
    portal_urls: List[str] = field(default_factory=list)

    def describe(self) -> str:
        if self.online:
            return self.detail or "已联网"
        if self.authenticated is True:
            return self.detail or "账号已认证，网页连通性暂未确认"
        if self.detail == "无法核实校园网门户会话":
            return self.detail
        if self.portal_url:
            return "未认证（门户：{}）".format(self.portal_url)
        return "未联网（{}）".format(self.detail or "所有探测点都不通")


@dataclass
class Detection:
    portal: str = ""
    status: int = 0
    server: str = ""
    title: str = ""
    scores: List[Tuple[str, float]] = field(default_factory=list)
    notes: Dict[str, Any] = field(default_factory=dict)
    detail: str = ""

    @property
    def best(self) -> str:
        return self.scores[0][0] if self.scores else ""

    def order(self, limit: int = 3) -> List[str]:
        if self.scores:
            return [name for name, _ in self.scores[:limit]]
        return []


# -------------------------------------------------------------------- 联网判定
def _normal_probe_redirect(source: str, target: str) -> bool:
    """Only follow a probe site's own redirects, never a captive portal's."""
    before, after = urlsplit(source), urlsplit(target)
    if before.scheme == "https" and after.scheme != "https":
        return False
    if before.hostname == after.hostname:
        return before.port == after.port or (before.scheme == "http" and after.scheme == "https"
                                            and after.port in (None, 443))
    # These are the owners of CONTENT_PROBES; Bing uses a regional hostname.
    for domain in ("baidu.com", "qq.com", "bing.com"):
        if all(host and (host == domain or host.endswith("." + domain))
               for host in (before.hostname, after.hostname)):
            return after.scheme == "https" and after.port in (None, 443)
    return False


def _probe_response(session: Session, url: str):
    current, seen = url, set()
    for _ in range(4):
        seen.add(current)
        response = session.get(current, timeout=5)
        target = redirect_target(response, current)
        if not target:
            return response, ""
        if not _normal_probe_redirect(url, target):
            return response, target
        if target in seen:
            break
        current = target
    return response, ""


def _record_portal(status: NetStatus, url: str) -> None:
    if url and url not in status.portal_urls:
        status.portal_urls.append(url)
        if not status.portal_url:
            status.portal_url = url


def check_online(session: Session, portal_hint: str = "") -> NetStatus:
    """综合两关判断是否真的联网；顺便把 Portal 地址带回来。"""
    status = NetStatus()
    hijack_ok = False

    for url, expect, marker in HIJACK_PROBES:
        try:
            resp, location = _probe_response(session, url)
        except HttpError as exc:
            status.detail = str(exc)
            continue

        if location:
            _record_portal(status, location)
        elif not hijack_ok and _looks_like_portal(resp):
            _record_portal(status, resp.url or url)
            status.status = resp.status

        if resp.status == expect and not location:
            if marker is None or marker.lower() in resp.text.lower():
                hijack_ok = True
                status.probe = url
                status.status = resp.status

    content_ok = 0
    for url, marker in CONTENT_PROBES:
        try:
            resp, target = _probe_response(session, url)
        except HttpError:
            continue
        if target:
            _record_portal(status, target)
        if resp.status == 200 and not target and marker in resp.text.lower():
            content_ok += 1
            # Public connectivity endpoints can be unavailable/rate-limited.
            # Require two real sites in that case, and never ignore a captive redirect.
            if hijack_ok or (content_ok >= 2 and not status.portal_url):
                status.online = True
                status.detail = ""
                return status

    if not status.portal_url and portal_hint:
        status.portal_url = portal_hint
    status.detail = ("能过劫持探测，但抓不到真实网页内容（可能被白名单）" if hijack_ok
                     else "联网检测未通过，暂未确认网页可访问")
    return status


def _looks_like_portal(resp: Response) -> bool:
    if resp.status not in (200, 302, 301, 307, 308):
        return False
    text = resp.text.lower()
    hints = ("eportal", "srun_portal", "acsetting", "ddddd", "upass",
             "wlanuserip", "webloginid", "interface.do", "portal/login",
             "登录", "认证")
    return any(hint in text for hint in hints)


# -------------------------------------------------------------------- 门户候选
def default_gateway() -> str:
    """尽力取默认网关；取不到返回空串。

    注意：中文 Windows 的 ``ipconfig`` 输出是 GBK，必须让 subprocess 容错解码，
    否则在 reader 线程里抛 UnicodeDecodeError，stdout 会变成 None。
    """
    system = platform.system()
    if system == "Windows":
        from .windows_network import current_network
        physical = current_network().get("gateway")
        if physical:
            return physical
        commands = [["route", "print", "-4"], ["ipconfig"]]
    elif system == "Darwin":
        commands = [["netstat", "-rn"]]
    else:
        commands = [["ip", "route"], ["route", "-n"]]

    for command in commands:
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=4, errors="replace",
                encoding="oem" if system == "Windows" else "utf-8",
                **no_window_kwargs(),
            )
            output = completed.stdout or ""
        except Exception:  # noqa: BLE001 - 取不到就用别的办法
            continue
        try:
            found = _parse_gateway(output)
        except Exception:  # noqa: BLE001
            continue
        if found:
            return found
    return ""


def _parse_gateway(text: str) -> str:
    routes = []
    for line in (text or "").splitlines():
        parts = line.split()
        if (len(parts) >= 5 and parts[:2] == ["0.0.0.0", "0.0.0.0"]
                and _is_ipv4(parts[2]) and _is_ipv4(parts[3]) and parts[4].isdigit()
                and parts[2] != "0.0.0.0"):
            routes.append((int(parts[4]), parts[2]))
    if routes:
        return min(routes)[1]
    for line in (text or "").splitlines():
        if "默认网关" in line or "Default Gateway" in line:
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if match and match.group(1) != "0.0.0.0":
                return match.group(1)
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "0.0.0.0":
            gateway = parts[2] if parts[1] == "0.0.0.0" else parts[1]
            if _is_ipv4(gateway) and gateway != "0.0.0.0":
                return gateway
        if len(parts) >= 3 and parts[:2] == ["default", "via"] and _is_ipv4(parts[2]):
            return parts[2]
        if len(parts) >= 2 and parts[0] == "default" and _is_ipv4(parts[1]):
            return parts[1]
    return ""


def _is_ipv4(text: str) -> bool:
    parts = (text or "").split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def normalize_portal(value: str, base: str = "") -> str:
    """Keep the portal path/query; accept only usable HTTP(S) URLs without credentials."""
    value = unescape((value or "").strip()).replace("\\/", "/")
    if not value or re.search(r"[\x00-\x20\\]", value):
        return ""
    if base:
        value = urljoin(base, value)
    elif "://" not in value:
        value = "http://" + value
    try:
        parts = urlsplit(value)
        if (parts.scheme.lower() not in ("http", "https") or not parts.hostname
                or parts.username is not None or parts.password is not None):
            return ""
        _ = parts.port
        return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))
    except ValueError:
        return ""


class _Page(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.refresh = ""
        self.scripts = []
        self.ac_id = ""
        self.domains = {}
        self.option = ""
        self.feed(text[:262144])

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "meta" and (attrs.get("http-equiv") or "").lower() == "refresh":
            self.refresh = attrs.get("content") or ""
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag == "input" and attrs.get("name", attrs.get("id")) == "ac_id":
            self.ac_id = attrs.get("value") or ""
        if tag == "option":
            self.option = attrs.get("value") or ""

    def handle_data(self, data):
        if self.option.startswith("@") and re.fullmatch(r"@[\w.-]{1,64}", self.option):
            code = carrier.normalize(data.strip())
            if code in ("cmcc", "telecom", "unicom"):
                self.domains[code] = self.option[1:]

    def handle_endtag(self, tag):
        if tag == "option":
            self.option = ""


def redirect_target(resp: Response, requested_url: str = "") -> str:
    base = resp.url or requested_url
    if 300 <= resp.status < 400 and resp.location:
        return normalize_portal(resp.location, base)
    if resp.status != 200:
        return ""
    text = resp.text[:262144]
    refresh = resp.headers.get("refresh", "") or _Page(text).refresh
    match = re.search(r"url\s*=\s*['\"]?([^'\"]+)", refresh, re.I)
    if match:
        return normalize_portal(match.group(1), base)
    # Read only literal redirect targets. Never execute JavaScript from a portal.
    match = re.search(r"(?:\b(?:window|top|self)\.)?\blocation(?:\.href)?\s*=\s*(['\"])(.*?)\1\s*(?:;|$|<)", text, re.I)
    if not match:
        match = re.search(r"\blocation\.(?:replace|assign)\(\s*(['\"])(.*?)\1\s*\)", text, re.I)
    return normalize_portal(match.group(2), base) if match else ""


def portal_candidates(cfg: Config, status: NetStatus) -> List[str]:
    """门户地址候选，按可能性排序。"""
    raw: List[str] = []
    if not cfg.automatic_portal and cfg.portal_ip:
        address = normalize_portal(cfg.portal_ip)
        return [address] if address else []
    if status.portal_url:
        raw.append(status.portal_url)
    raw.extend(status.portal_urls)
    gateway = default_gateway()
    if gateway:
        raw.append(gateway)

    seen: List[str] = []
    for item in raw:
        base = normalize_portal(item)
        if base and base not in seen:
            seen.append(base)
    return seen


# -------------------------------------------------------------------- 探测识别
def detect(session: Session, cfg: Config, status: Optional[NetStatus] = None) -> Detection:
    """Follow bounded portal redirects, then identify the page without sending credentials."""
    if status is None:
        status = check_online(session, _hint(cfg)) if cfg.automatic_portal else NetStatus()
    result = Detection()
    failures = []

    visited = set()
    deadline = time.monotonic() + 30
    for candidate in portal_candidates(cfg, status):
        for _hop in range(6):
            if candidate in visited or len(visited) >= 12 or time.monotonic() >= deadline:
                break
            visited.add(candidate)
            try:
                resp = session.get(candidate, timeout=min(cfg.timeout, 4))
            except HttpError as exc:
                failures.append("{}：{}".format(candidate, exc))
                break
            target = redirect_target(resp, candidate)
            if target:
                candidate = target
                continue
            if resp.status != 200:
                failures.append("{} 返回 HTTP {}".format(candidate, resp.status))
                break
            page_url = normalize_portal(resp.url or candidate)
            text = resp.text[:262144]
            page = _Page(text)
            # Vendor code may hold the identifying endpoints and access-controller ID.
            scripts = sorted(page.scripts, key=lambda s: not re.search(r"srun|portal|login|config", s, re.I))
            for src in scripts[:3]:
                url = normalize_portal(src, page_url)
                if (not url or origin(url) != origin(page_url) or url in visited
                        or len(visited) >= 12 or time.monotonic() >= deadline):
                    continue
                visited.add(url)
                try:
                    script = session.get(url, timeout=min(cfg.timeout, 3))
                    if script.status == 200:
                        text += "\n" + script.text[:262144]
                except HttpError:
                    continue
            scores = fingerprint(DetectContext(page_url, resp, text, resp.headers))
            if not scores:
                failures.append("页面已打开，但未识别认证方式：{}".format(page_url))
                break
            query = parse_qs(urlsplit(page_url).query)
            acid = query.get("ac_id", [""])[0] or page.ac_id or _find(r"ac_id\s*[=:]\s*['\"]?(\d+)", text)
            notes = {
                "ac_id": acid if acid.isdigit() else "",
                "ssid": _find(r"\bssid\s*[=:]\s*['\"]?([\w\-\.]+)", text),
                "vlan": _find(r"vlanid?\s*[=:]\s*['\"]?(\d+)", text),
                "client_ip": _find(r"(?:v46ip|ss5|wlanuserip)\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)", text),
                "portal_ip": _find(r"v4serip\s*[=:]\s*['\"]?(\d+\.\d+\.\d+\.\d+)", text),
            }
            if page.domains and scores[0][0] == "srun":
                notes["srun_domains"] = page.domains
            for key, endpoint in (("srun_login_path", "srun_portal"), ("srun_challenge_path", "get_challenge"),
                                  ("srun_status_path", "rad_user_info")):
                path = _find(r"['\"](/[\w/-]*cgi-bin/" + endpoint + r")[?'\"]", text)
                if path:
                    notes[key] = path
            return Detection(page_url, resp.status, resp.server, _title(resp.text), scores, notes)

    if status.online and cfg.automatic_portal:
        result.detail = "当前已联网，网络没有提供可识别的认证跳转。可取消自动获取，填写地址后点击“识别此地址”。"
    elif failures:
        result.detail = "未能获取认证页面。" + "；".join(failures[-2:])
    else:
        result.detail = "当前网络未提供认证入口。请确认已接入校园网，或手动填写浏览器中的认证地址。"
    return result


def _hint(cfg: Config) -> str:
    if cfg.automatic_portal or not cfg.portal_ip:
        return ""
    return origin(cfg.portal_ip) + "/"


def _title(text: str) -> str:
    return _find(r"<title[^>]*>(.*?)</title>", text or "")


def _find(pattern: str, text: str) -> str:
    match = re.search(pattern, text or "", re.I | re.S)
    return match.group(1).strip() if match else ""


def provider_order(cfg: Config, detection: Detection, limit: int = 3) -> List[str]:
    """决定这次要按什么顺序尝试 provider。"""
    if not cfg.automatic_portal and cfg.provider and cfg.provider != "auto":
        return [cfg.provider]
    if cfg.automatic_portal:
        return detection.order(limit)
    order = detection.order(limit) or rank(
        DetectContext(url=detection.portal, text=""), limit=limit
    )
    return order
