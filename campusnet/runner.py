"""编排：探测 → 选择认证方式 → 登录 → 校验。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from . import policy
from .config import Config
from .detector import Detection, NetStatus, check_online, detect, portal_candidates, provider_order
from .providers import LoginResult, get_provider
from .session import Session, local_ip, local_mac
from .wifi import WifiResult, ensure_wifi

LEVELS = ("debug", "info", "ok", "warn", "error")


def _null_log(message: str, level: str = "info") -> None:
    pass


@dataclass
class RunResult:
    ok: bool = False
    skipped: bool = False
    provider: str = ""
    message: str = ""
    status_before: Optional[NetStatus] = None
    detection: Optional[Detection] = None
    attempts: List[LoginResult] = field(default_factory=list)


class Runner:
    """把配置、HTTP 会话、provider 串起来。"""

    def __init__(self, cfg: Config, logger: Optional[Callable[[str, str], None]] = None) -> None:
        self.cfg = cfg
        self.log = logger or _null_log
        self._session: Optional[Session] = None
        self.follow_saved_config = False
        #: 等 Wi-Fi 关联的超时（秒）。命令行可覆盖。
        self.wifi_timeout: float = float(cfg.options.get("wifi_timeout", 30))
        #: 开机场景的 Wi-Fi 策略 —— 只在守护模式（watch）里用。
        #: 手动 login 不启用：要给"一次尝试 + 立刻给结论"的快速反馈。
        self.wifi_attempts: int = int(cfg.options.get("wifi_attempts", 2))
        self.wifi_retry_delay: float = float(cfg.options.get("wifi_retry_delay", 5))
        self.wifi_ready_timeout: float = float(cfg.options.get("wifi_ready_timeout", 25))

    # ------------------------------------------------------------ 资源
    @property
    def session(self) -> Session:
        if self._session is None:
            self._session = Session(
                timeout=self.cfg.timeout,
                use_proxy=self.cfg.use_proxy,
                verify_tls=bool(self.cfg.options.get("verify_portal_tls", False)),
                logger=lambda msg: self.log(msg, "debug"),
            )
        return self._session

    @property
    def client_ip(self) -> str:
        return local_ip()

    # ------------------------------------------------------------ 探测
    def status(self) -> NetStatus:
        hint = self.cfg.portal_ip and (self.cfg.portal_ip if "//" in self.cfg.portal_ip
                                       else "http://" + self.cfg.portal_ip + "/")
        if self.cfg.provider == "srun" and hint:
            from .providers.srun import SrunProvider
            state = SrunProvider(self.session, self.cfg.options).online_state(hint, self.cfg.username)
            if state is False:
                return NetStatus(online=False, portal_url=hint,
                                 detail="校园网门户报告未认证")
            if state is None and self.cfg.options.get("verify_srun_session"):
                return NetStatus(online=False, portal_url=hint, detail="无法核实校园网门户会话")
        return check_online(self.session, hint or "")

    def detect(self, status: Optional[NetStatus] = None) -> Detection:
        detection = detect(self.session, self.cfg, status)
        if detection.scores:
            self.log("识别到认证系统：{}（置信度 {:.2f}）".format(
                detection.best, detection.scores[0][1]), "ok")
        else:
            self.log("未能识别门户类型，将按通用顺序尝试", "warn")
        return detection

    # ------------------------------------------------------------ Wi-Fi
    def ensure_wifi(self, patient: bool = False) -> WifiResult:
        """把 Wi-Fi 抢回校园网。

        **必须在联网探测之前做。** 反过来就会出现这个 bug：

        连着手机热点 → 热点能上网 → 探测说「已联网」→ 直接返回，Wi-Fi 永远不切。

        所以这里的判断依据是「当前连的是不是校园网」，而不是「有没有网」。
        只有配置了 ``wifi_ssid`` 才会动手；没配就完全不影响原有行为。

        ``patient=True`` 用"开机级"的耐心：先等网卡就绪，失败还重试几次。
        开机那十几秒里无线驱动和 ``WlanSvc`` 常没准备好，一次不成很正常 ——
        这正是"有时候开机 wifi 没有自动连上"的来源。手动 ``login`` 不传它，
        保持一次尝试、快速给结论。

        注意 ``patient=False`` 时**只传原本那三个参数**：模块级 ``ensure_wifi``
        的其余参数走默认值，行为与旧版逐字一致。
        """
        kwargs = {"timeout": self.wifi_timeout, "logger": self.log}
        if patient:
            kwargs.update(
                attempts=self.wifi_attempts,
                retry_delay=self.wifi_retry_delay,
                ready_timeout=self.wifi_ready_timeout,
            )
        result = ensure_wifi(self.cfg.wifi_ssid, **kwargs)

        if not result.supported:
            self.log(result.message, "debug")
            return result
        if not result.ok:
            # 没抢到就是后续认证失败的根因，必须说清楚，别让人去查账号密码
            self.log("没能连上校园 Wi-Fi「{}」—— 网络没切过去，认证一定不会成功".format(
                self.cfg.wifi_ssid), "warn")
            return result
        if result.changed:
            # 刚换了 Wi-Fi，DHCP 还没走完，给它一点时间再探测
            delay = float(self.cfg.options.get("wifi_settle_delay", 3))
            if delay:
                time.sleep(delay)
        return result

    # ------------------------------------------------------------ 主流程
    def ensure_online(self, force: bool = False, limit: int = 3,
                      patient: bool = False, wifi_checked: bool = False) -> RunResult:
        """确认网络可用，必要时完成认证。

        ``wifi_checked=True`` 表示调用方**已经**做过 Wi-Fi 那一环了，
        这里就不再重复发一遍 ``netsh``（守护模式每轮都先自己抢一次网）。
        """
        cfg = self.cfg

        # 先抢 Wi-Fi，再判联网 —— 顺序不能反，理由见 ensure_wifi 的注释。
        if not wifi_checked:
            self.ensure_wifi(patient=patient)

        status = self.status()
        if status.online and not force:
            return RunResult(ok=True, skipped=True, message="已联网，无需认证", status_before=status)

        if status.online and force:
            self.log("当前已联网，但指定了 --force，仍要重新认证一次", "warn")

        if not cfg.username:
            return RunResult(ok=False, message="配置里没有账号，请先运行：campusnet setup", status_before=status)

        password = cfg.resolve_password(prompt=False)
        if not password:
            return RunResult(ok=False,
                             message="没有取到密码。请设置 CAMPUSNET_PASSWORD 环境变量，或用 campusnet setup 配置",
                             status_before=status)

        if cfg.provider and cfg.provider != "auto" and cfg.portal_ip:
            # A captive redirect or the default gateway must never displace an explicitly paired portal and provider.
            from .session import origin
            detection = Detection(portal=origin(cfg.portal_ip) + "/")
        else:
            detection = self.detect(status)
        portal = detection.portal or (portal_candidates(cfg, status) or [""])[0]
        if not portal:
            return RunResult(ok=False, message="找不到认证门户地址，请用 --portal 指定或写入配置",
                             status_before=status, detection=detection)

        order = provider_order(cfg, detection, limit=limit)
        self.log("认证门户：{}".format(portal.rstrip("/")), "info")
        self.log("尝试顺序：{}".format(" → ".join(order)), "info")

        ip, mac = self.client_ip, local_mac()
        attempts: List[LoginResult] = []

        for name in order:
            try:
                provider = get_provider(name)(self.session, cfg.options)
            except KeyError as exc:
                self.log(str(exc), "error")
                continue
            self.log("使用 {} 登录…".format(provider.display_name), "info")
            try:
                result = provider.login(portal, cfg.username, password, ip, mac)
            except Exception as exc:  # noqa: BLE001 - 单个 provider 崩了不该中断整体
                result = LoginResult(False, name, "内部异常：{}".format(exc))
            attempts.append(result)
            self.log(result.short(), "ok" if result.ok else "warn")

            verify_session = name == "srun" and bool(cfg.options.get("verify_srun_session"))
            if result.already_online and not verify_session:
                return RunResult(ok=True, provider=name, message=result.message,
                                 status_before=status, detection=detection, attempts=attempts)

            if not result.ok:
                if result.raw:
                    self.log(result.raw, "debug")
                continue

            # 接口说成功还不够，必须联网校验通过
            if force and status.online and not verify_session:
                return RunResult(ok=True, provider=name, message=result.message,
                                 status_before=status, detection=detection, attempts=attempts)

            wait = float(cfg.options.get("verify_delay", 2))
            if wait:
                time.sleep(wait)
            after = self.status()
            if after.online:
                message = ("门户返回已在线，已核实网络可用" if result.already_online
                           else "认证成功，网络已连通")
                return RunResult(ok=True, provider=name, message=message,
                                 status_before=status, detection=detection, attempts=attempts)
            if verify_session:
                return RunResult(ok=False, provider=name, message="认证接口已应答，但未能同时确认本账号的门户会话和网页连通性",
                                 status_before=status, detection=detection, attempts=attempts)
            self.log("接口返回成功，但联网校验未通过，继续尝试其它方式", "warn")

        message = attempts[-1].message if attempts else "没有可用的认证方式"
        return RunResult(ok=False, message=message, status_before=status,
                         detection=detection, attempts=attempts)

    def watch(self, interval_minutes: Optional[int] = None, on_event=None,
              warmup_seconds: Optional[float] = None, warmup_gap: Optional[float] = None,
              retry_gap: Optional[float] = None, immediate_start: bool = False):
        """常驻守护：联网正常时完全安静，断了就补登录。

        分两个阶段，这是为了解决「有时候开机 wifi 没有自动连上」：

        **阶段一 · 开机热身。** 守护进程是**登录时**启动的，而这段时间
        无线驱动、``WlanSvc``、SSID 广播往往还没准备好。旧逻辑一轮不成
        就要等满 ``interval``（默认 10 分钟），用户体感就是"开机一直没网"。
        所以开头 ``warmup_seconds`` 秒内改成每 ``warmup_gap`` 秒重试一次，
        一旦联网立刻进入常规节奏。

        **阶段二 · 常规守护。** 联网正常就按 ``interval`` 检查；
        哪一轮没弄通就用 ``retry_gap`` 快速再试，而不是干等十分钟 ——
        合盖唤醒、中途被切到热点、会话超时都能很快补回来。

        策略（见 :mod:`campusnet.policy`）在**每一轮**重新读取，所以
        改间隔、暂停、改时间段都不用重启守护进程：``interval_minutes=None``
        表示「用配置里的 ``reconnect_interval``」。
        """
        if warmup_seconds is None:
            warmup_seconds = float(self.cfg.options.get("wifi_warmup", 180))
        if warmup_gap is None:
            warmup_gap = float(self.cfg.options.get("wifi_warmup_gap", 15))
        if retry_gap is None:
            retry_gap = float(self.cfg.options.get("wifi_retry_gap", 60))

        explicit_interval = interval_minutes
        if interval_minutes is None:
            interval_minutes = policy.interval_minutes(self.cfg)
        self.log("守护模式启动，每 {} 分钟检查一次".format(interval_minutes), "ok")
        self.log("重连策略：{}".format(policy.describe(self.cfg)), "info")
        if self.cfg.wifi_ssid:
            self.log("已配置校园 Wi-Fi「{}」，每轮都会确认是否连在它上面".format(self.cfg.wifi_ssid), "info")

        self._last_block = ""
        try:
            if warmup_seconds > 0:
                self._warmup(warmup_seconds, warmup_gap, on_event, immediate_start)
                immediate_start = False
            while True:
                # 每轮重读策略：用户可能在另一个窗口里改了间隔 / 暂停了重连
                self._reload_policy()
                block = self._policy_block()
                if block:
                    immediate_start = False
                    self._log_blocked(block)
                    time.sleep(self._block_wait())
                    continue
                self._clear_blocked()

                online = self._watch_round_safe(on_event, immediate_start)
                immediate_start = False
                if online:
                    current_interval = explicit_interval if explicit_interval is not None else policy.interval_minutes(self.cfg)
                    time.sleep(max(30, current_interval * 60))
                else:
                    time.sleep(max(15.0, retry_gap))
        except KeyboardInterrupt:
            self.log("收到中断，退出守护模式", "info")
            return

    # ------------------------------------------------------------ 策略
    def _reload_policy(self) -> None:
        """只把策略相关的几个键从磁盘刷新进来。

        整个配置重载会覆盖掉命令行传的 ``--wifi`` / ``--carrier`` 等临时值，
        所以这里只挑策略键更新。
        """
        try:
            fresh_config = Config.load(self.cfg.path or None)
        except Exception:  # noqa: BLE001 - 配置被改坏时别让守护进程退出
            return
        if self.follow_saved_config:
            if (self.cfg.timeout, self.cfg.use_proxy, self.cfg.options.get("verify_portal_tls")) != (fresh_config.timeout, fresh_config.use_proxy, fresh_config.options.get("verify_portal_tls")):
                self._session = None
            self.cfg = fresh_config
            return
        fresh = fresh_config.options
        for key in policy.POLICY_KEYS:
            if key in fresh:
                self.cfg.options[key] = fresh[key]
            else:
                self.cfg.options.pop(key, None)

    def _policy_block(self) -> str:
        try:
            return policy.block_reason(self.cfg)
        except Exception:  # noqa: BLE001 - 策略出错不该挡住正常守护
            return ""

    def _log_blocked(self, reason: str) -> None:
        if reason != getattr(self, "_last_block", ""):
            self.log("{}，本轮跳过自动认证".format(reason), "info")
            self._last_block = reason

    def _clear_blocked(self) -> None:
        if getattr(self, "_last_block", ""):
            self.log("恢复自动重连", "ok")
            self._last_block = ""

    def _block_wait(self) -> float:
        """被策略挡住时睡多久：暂停到点就醒，否则一分钟看一次。"""
        remaining = policy.pause_remaining()
        if remaining > 0:
            return max(5.0, min(remaining, 300.0))
        return 60.0

    def _wait_with_policy(self, seconds: float) -> bool:
        """延时重连期间的分段等待。

        返回 ``False`` 表示等待中被暂停 / 离开了时间段，这一轮就别登录了 ——
        否则「等 60 秒」会变成绕过暂停的后门。
        """
        deadline = time.time() + max(0.0, seconds)
        while True:
            self._reload_policy()
            if self._policy_block():
                return False
            remaining = deadline - time.time()
            if remaining <= 0:
                return True
            time.sleep(min(remaining, 5.0))

    def _warmup(self, seconds: float, gap: float, on_event, immediate_start: bool = False) -> None:
        """开机后的集中抢网阶段：一直试到联网，或超过 ``seconds``。"""
        self.log("开机热身：{} 秒内每 {} 秒试一次，直到联网".format(
            int(seconds), int(gap)), "info")
        deadline = time.time() + seconds
        while True:
            self._reload_policy()
            block = self._policy_block()
            if block:
                self._log_blocked(block)
                return
            if self._watch_round_safe(on_event, immediate_start):
                self.log("热身阶段已联网", "ok")
                return
            remaining = deadline - time.time()
            if remaining <= 0:
                self.log("热身结束仍未联网，转为常规检查（这样也不会一直空转）", "warn")
                return
            time.sleep(max(1.0, min(gap, remaining)))

    def _watch_round_safe(self, on_event, immediate_start: bool = False) -> bool:
        """ ``_watch_round`` 的保险版：**单轮出错绝不能让守护进程退出**。

        守护进程要活好几天，中途 provider 抛异常、系统命令抽风都是常态，
        所以每一轮单独兜住异常，出错就当"这轮没成功"，下一轮接着来。
        """
        try:
            return self._watch_round(on_event, immediate_start)
        except Exception as exc:  # noqa: BLE001 - 守护进程必须活到最后
            self.log("本轮检查出错：{}".format(exc), "error")
            return False

    def _watch_round(self, on_event, immediate_start: bool = False) -> bool:
        """跑一轮：确认 Wi-Fi → 判断联网 → 必要时登录。返回是否已联网。

        Wi-Fi 这一环自己先做掉，然后告诉 ``ensure_online`` 别再重复一次 ——
        开机场景下每次重试都可能等网卡、等关联，省一次是一次。
        """
        wifi = self.ensure_wifi(patient=True)
        status = self.status()
        if status.online:
            if wifi.changed:
                self.log("已切回校园 Wi-Fi，网络正常", "ok")
            elif self.cfg.options.get("verify_srun_session"):
                self.log("例行检查通过：校园账号会话在线，可访问网页", "ok")
            return True

        # 延时重连：先等一会儿再抢，把网络留给手机。
        # 等待过程中每 5 秒回看一眼策略，暂停了就不再登录。
        delay = 0 if immediate_start else policy.reconnect_delay(self.cfg)
        if immediate_start:
            self.log("登录启动后检测未通过，立即尝试认证（{}）".format(
                getattr(status, "detail", "") or "网络未就绪"), "info")
        if delay > 0:
            self.log("检测到网络未认证，{} 后再尝试重连（先给手机用）".format(
                policy.format_duration(delay)), "warn")
            if not self._wait_with_policy(delay):
                self.log("等待期间策略生效，本轮不重连", "info")
                return False
            if self.status().online:
                self.log("等待期间网络已恢复，本轮不再登录", "ok")
                return True

        if immediate_start:
            self._reload_policy()
            block = self._policy_block()
            if block:
                self._log_blocked(block)
                return False
        self.log("开始自动登录…", "warn")
        result = self.ensure_online(patient=True, wifi_checked=True)
        if on_event:
            on_event(result)
        self.log(result.message, "ok" if result.ok else "error")
        return result.ok
