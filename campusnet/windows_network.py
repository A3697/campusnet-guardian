"""Read the physical connection behind a Windows VPN or virtual adapter."""

import os
import json
import re
import subprocess
from pathlib import Path
from .procflags import no_window_kwargs
import threading
import time

def run_powershell(script, timeout=45):
    # Prefer PowerShell 7. The inbox host keeps the Windows desktop package usable
    # on PCs without PowerShell 7; this application's NetAdapter commands work on both.
    ps7 = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "PowerShell/7/pwsh.exe"
    executable = ps7 if ps7.is_file() else Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    prefix = "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
    result = subprocess.run([str(executable), "-NoProfile", "-NonInteractive", "-Command", prefix + script],
                            capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
                            **no_window_kwargs())
    if result.returncode:
        raise RuntimeError("Windows 网卡操作失败：" + (result.stderr.strip() or "命令未成功")[:500])
    return json.loads(result.stdout.strip() or "{}")


def inspect_adapter(guid="") -> dict:
    if guid and not re.fullmatch(r"[0-9a-fA-F-]{36}", guid):
        raise ValueError("无效的网卡标识")
    select = ("$adapter=@($all | Where-Object { [guid]$_.InterfaceGuid -eq [guid]'" + guid + "' });"
              if guid else """
        $routes=@(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
            Where-Object { $_.InterfaceIndex -in @($all.ifIndex) } |
            Sort-Object @{Expression={$_.RouteMetric+$_.InterfaceMetric}});
        if ($routes.Count) {
            $adapter=@($all | Where-Object { $_.ifIndex -eq $routes[0].InterfaceIndex -and $_.Status -eq 'Up' });
        } else { $adapter=@($all | Where-Object Status -eq 'Up'); }
    """)
    return run_powershell("$all=@(Get-NetAdapter -Physical); " + select + """
        if ($adapter.Count -ne 1) { throw '没有唯一的当前物理网卡，已跳过 MAC 重试。'; }
        $a=$adapter[0];
        $property=Get-NetAdapterAdvancedProperty -Name $a.Name -RegistryKeyword 'NetworkAddress' -ErrorAction SilentlyContinue;
        $ip=@(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' });
        $route=@(Get-NetRoute -InterfaceIndex $a.ifIndex -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue);
        $interface=Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4;
        [ordered]@{guid=[string]([guid]$a.InterfaceGuid); name=$a.Name; mac=$a.MacAddress;
            ipv4=($ip | Select-Object -First 1 -ExpandProperty IPAddress);
            override=($property.RegistryValue -join ''); supported=($null -ne $property);
            up=([string]$a.Status -eq 'Up'); dhcp=([string]$interface.Dhcp -eq 'Enabled');
            ready=($ip.Count -gt 0 -and $route.Count -gt 0);
            gateway=($route | Select-Object -First 1 -ExpandProperty NextHop)} | ConvertTo-Json -Compress
    """)

_cache = {}
_expires = 0.0
_lock = threading.Lock()


def clear_cache():
    global _expires
    with _lock:
        _expires = 0.0


def current_network():
    global _cache, _expires
    if os.name != "nt":
        return {}
    with _lock:
        if time.monotonic() < _expires:
            return dict(_cache)
        try:
            _cache = inspect_adapter()
        except Exception:
            _cache = {}
        _expires = time.monotonic() + 3
        return dict(_cache)
