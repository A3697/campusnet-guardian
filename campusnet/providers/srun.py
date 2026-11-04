"""深澜 Srun Portal 认证（``/cgi-bin/srun_portal``）。

流程（三步）：

1. ``GET /cgi-bin/get_challenge`` 拿一个一次性 challenge
2. 本地算三样东西
   * ``hmd5      = HMAC-MD5(challenge, password)``
   * ``info      = "{SRBX1}" + srun_base64( XXTEA(info_json, challenge) )``
   * ``chksum    = sha1(challenge + username + challenge + hmd5 + challenge + acid + challenge
                        + ip + challenge + n + challenge + type + challenge + info)``
3. ``GET /cgi-bin/srun_portal?action=login&...`` 带上上面三个值

注意：深澜的 base64 用的**不是**标准字母表，而是自己一套置换过的表（``SRUN_ALPHABET``）。
另外 ``password`` 字段传的是 ``{MD5}<hmd5>`` 这种带前缀的形式。

``ac_id`` 各校不同，绝大多数是 ``1``；不确定就用 ``campusnet detect`` 从页面里抠。

有些学校要先选运营商，深澜用 ``domain`` 参数表达（``@cmcc`` / ``@telecom`` /
``@unicom``）。用 ``carrier`` 选项指定即可，写法很宽松
（``移动`` / ``中国移动`` / ``cmcc`` 都认），见 ``campusnet.carrier``。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

from .. import carrier as carrier_mod
from ..session import local_ip
from .base import DetectContext, LoginResult, Provider

#: 深澜私有的 base64 字母表（64 个字符 + 填充符）
SRUN_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA="
_STD_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_TRANS = str.maketrans(_STD_ALPHABET, SRUN_ALPHABET[:64])


# -------------------------------------------------------------------- 算法
def srun_base64(data: bytes) -> str:
    """按深澜的字母表做 base64（保留填充，服务端解码依赖它）。"""
    return base64.b64encode(data).decode("ascii").translate(_TRANS)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def build_hmd5(password: str, challenge: str) -> str:
    # 学校页面的 blueimp md5(password, token) 是以 token 为密钥的 HMAC。
    return hmac.new(challenge.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()


def _str2long(text: str, include_length: bool = False) -> List[int]:
    """按 UTF-16 码元打包成 32 位整数数组，对应门户 JS 里的 s()。"""
    raw = text.encode("utf-16-le")
    units = [int.from_bytes(raw[i:i + 2], "little") for i in range(0, len(raw), 2)]
    values: List[int] = []
    for index in range(0, len(units), 4):
        value = 0
        for offset, unit in enumerate(units[index:index + 4]):
            value |= unit << (offset * 8)
        values.append(value & 0xFFFFFFFF)
    if include_length:
        values.append(len(units))
    return values


def _long2bytes(values: List[int]) -> bytes:
    return b"".join((value & 0xFFFFFFFF).to_bytes(4, "little") for value in values)


def _xxtea_encrypt(values: List[int], key: List[int]) -> List[int]:
    """XXTEA 加密，对应门户 JS 里的 encode()。"""
    n = len(values) - 1
    if n < 1:
        return values
    y, z, total = values[0], values[n], 0
    for _ in range(6 + 52 // (n + 1)):
        total = (total + 0x9E3779B9) & 0xFFFFFFFF
        e = (total >> 2) & 3
        for p in range(n):
            y = values[p + 1]
            mixed = (((z >> 5) ^ (y << 2))
                     + ((y >> 3) ^ (z << 4) ^ (total ^ y))
                     + (key[(p & 3) ^ e] ^ z)) & 0xFFFFFFFF
            z = (values[p] + mixed) & 0xFFFFFFFF
            values[p] = z
        y = values[0]
        mixed = (((z >> 5) ^ (y << 2))
                 + ((y >> 3) ^ (z << 4) ^ (total ^ y))
                 + (key[(n & 3) ^ e] ^ z)) & 0xFFFFFFFF
        z = (values[n] + mixed) & 0xFFFFFFFF
        values[n] = z
    return values


def build_info(username: str, password: str, ip: str, acid: str, challenge: str,
               enc_ver: str = "srun_bx1") -> str:
    payload = {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": acid,
        "enc_ver": enc_ver,
    }
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    values = _str2long(text, include_length=True)
    key = _str2long(challenge)
    while len(key) < 4:
        key.append(0)
    return "{SRBX1}" + srun_base64(_long2bytes(_xxtea_encrypt(values, key)))


def build_chksum(challenge: str, username: str, hmd5: str, acid: str, ip: str,
                 info: str, n: str = "200", type_: str = "1") -> str:
    joined = "".join([
        challenge, username, challenge, hmd5, challenge, acid, challenge, ip,
        challenge, n, challenge, type_, challenge, info,
    ])
    return hashlib.sha1(joined.encode("utf-8")).hexdigest()


# -------------------------------------------------------------------- Provider
class SrunProvider(Provider):
    name = "srun"
    display_name = "深澜 Srun"
    docs = "https://www.srun.com/"
    min_confidence = 0.4

    @classmethod
    def detect(cls, ctx: DetectContext) -> float:
        score = 0.0
        url = (ctx.url or "").lower()
        low = ctx.lower_text

        if "srun_portal" in low or "srun_portal" in url:
            score += 0.7
        if "cgi-bin/get_challenge" in low or "cgi-bin/srun_portal" in low:
            score += 0.6
        if "srun" in low:
            score += 0.3
        if "ac_id" in low:
            score += 0.2
        if "深澜" in ctx.text:
            score += 0.6
        if "/self/" in url or "nav_login" in url:
            score += 0.3
        return min(score, 1.0)

    def _identity(self, username: str) -> Tuple[str, str]:
        if "@" in username:
            return username, ""
        carrier_raw = str(self.opt("carrier", "") or "").strip()
        code = carrier_mod.normalize(carrier_raw) if carrier_raw else ""
        domain = str(self.opt("domain", "") or "").strip().lstrip("@")
        suffixes = self.opt("srun_domains", None)
        if isinstance(suffixes, dict):
            # 学校页面把运营商拼入用户名，并用同一名字取 challenge、加密和签名。
            domain = domain or str(suffixes.get(code, "")).lstrip("@")
            return (username + "@" + domain if domain else username), ""
        return username, domain or (carrier_mod.suffix_for(code).lstrip("@") if code else "")

    def login(self, portal: str, username: str, password: str, client_ip: str = "", mac: str = "") -> LoginResult:
        ip = client_ip or local_ip()
        acid = str(self.opt("ac_id", "1"))
        n = str(self.opt("n", "200"))
        type_ = str(self.opt("type", "1"))
        os_name = str(self.opt("os", "Windows 10"))
        username, domain = self._identity(username)
        errors: List[str] = []

        for origin in self.origins(portal):
            try:
                challenge, ip = self._get_challenge(origin, username, ip)
            except Exception as exc:  # noqa: BLE001
                errors.append("{}：{}".format(origin, exc))
                continue
            if not challenge:
                errors.append("{}：拿不到 challenge".format(origin))
                continue

            hmd5 = build_hmd5(password, challenge)
            info = build_info(username, password, ip, acid, challenge)
            chksum = build_chksum(challenge, username, hmd5, acid, ip, info, n=n, type_=type_)

            query = (
                "callback=jsonp&action=login&username={u}&password={pwd}&ac_id={acid}"
                "&ip={ip}&chksum={chksum}&info={info}&n={n}&type={t}"
                "&os={os}&name={name}&double_stack=0"
            ).format(
                u=quote(username, safe=""),
                pwd=quote("{MD5}" + hmd5, safe=""),
                acid=acid,
                ip=ip,
                chksum=chksum,
                info=quote(info, safe=""),
                n=n,
                t=type_,
                os=quote(os_name, safe=""),
                name=quote(os_name, safe=""),
            )
            if domain:
                query += "&domain={}".format(quote(domain, safe=""))
            query += "&_={}".format(int(time.time() * 1000))
            try:
                resp = self.session.get("{}/cgi-bin/srun_portal?{}".format(origin, query),
                                        headers={"Referer": origin + "/"})
            except Exception as exc:  # noqa: BLE001
                errors.append("{}：{}".format(origin, exc))
                continue

            result = self._as_result(resp, origin + "/cgi-bin/srun_portal")
            if result.ok or result.already_online:
                return result
            errors.append("{}：{}".format(origin, result.message))

        return LoginResult(
            ok=False,
            provider=self.name,
            message="登录失败。最后一次返回：{}".format(errors[-1] if errors else "无响应"),
            raw="\n".join(errors[-3:]),
        )

    # ------------------------------------------------------------ 内部
    def _get_challenge(self, origin: str, username: str, ip: str) -> Tuple[str, str]:
        for attempt in range(2):
            url = "{}/cgi-bin/get_challenge?callback=jsonp&username={}&ip={}&_={}".format(
                origin, quote(username, safe=""), quote(ip, safe=""), int(time.time() * 1000))
            resp = self.session.get(url, headers={"Referer": origin + "/", "Cache-Control": "no-cache"})
            data = self._json(resp)
            if not isinstance(data, dict):
                return "", ip
            # challenge 与请求 IP 绑定；发现 TUN 地址时，必须用真实地址重新取 token。
            observed_ip = str(data.get("client_ip") or "")
            try:
                ipaddress.ip_address(observed_ip)
            except ValueError:
                observed_ip = ip
            if observed_ip != ip:
                ip = observed_ip
                if attempt == 0:
                    continue
                return "", ip
            return str(data.get("challenge") or ""), ip
        return "", ip

    def online_state(self, portal: str, username: str = "") -> Optional[bool]:
        """门户明确报告离线时，不能被代理可访问的公共探测点覆盖。"""
        for origin in self.origins(portal):
            try:
                response = self.session.get(origin + "/cgi-bin/rad_user_info?callback=jsonp&_={}".format(int(time.time() * 1000)), timeout=5)
                data = self._json(response)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            if data.get("error") == "ok" and data.get("online_ip"):
                if username:
                    wire_user, domain = self._identity(username)
                    base, _, suffix = wire_user.partition("@")
                    reported = str(data.get("user_name") or "").casefold()
                    if not reported:
                        return None
                    if reported not in (wire_user.casefold(), base.casefold()):
                        return False
                    realm = str(data.get("domain") or "").lstrip("@").casefold()
                    expected = (suffix or domain).casefold()
                    if expected and not realm and "@" not in reported:
                        return None
                    if expected and realm and expected != realm:
                        return False
                return True
            if data.get("error") in ("not_online_error", "not_online"):
                return False
        return None

    def _as_result(self, resp, endpoint: str) -> LoginResult:
        text = resp.text or ""
        data = self._json(resp)
        if isinstance(data, dict):
            error = str(data.get("error", "") or "")
            error_msg = str(data.get("error_msg") or data.get("msg") or "")
            markers = {error.lower(), error_msg.lower(), str(data.get("suc_msg") or "").lower()}
            if markers.intersection({"ip_already_online_error", "already_online_error", "already_online"}):
                return LoginResult(True, self.name, "门户报告已在线", endpoint=endpoint, already_online=True)
            if error in ("ok", "0"):
                return LoginResult(True, self.name, error_msg or "认证成功",
                                   endpoint=endpoint, raw=text[:600])
            return LoginResult(False, self.name, "{} {}".format(error, error_msg).strip(),
                               endpoint=endpoint, raw=text[:600])
        return LoginResult(False, self.name, "HTTP {} 未识别响应".format(resp.status),
                           endpoint=endpoint, raw=text[:600])

    @staticmethod
    def _json(resp) -> Optional[Dict[str, Any]]:
        payload = resp.jsonp_payload
        if not payload:
            return None
        try:
            data = json.loads(payload)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None
