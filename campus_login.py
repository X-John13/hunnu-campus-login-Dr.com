#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HUNNU / Dr.COM 校园网自动登录脚本

用途：
  在本人账号、本人设备、被授权校园网环境下，完成 Dr.COM Portal 登录、注销、状态查询、
  守护重连、网络诊断与脱敏日志导出。

适配场景：
  1. 湖南师范大学 HUNNU / HUNNU-5G 无线网络；
  2. 校园有线网络；
  3. Windows 多网卡环境，例如 Clash/Mihomo TUN、TAP、虚拟机网卡同时存在；
  4. 多账号/多电脑共享脚本，但每台设备必须使用自己的 config.json。

认证流程概要：
  1. 自动识别真实校园网 IP/MAC，排除 Clash/Mihomo/TAP/虚拟网卡；
  2. 访问 loadConfig 获取服务器 rcn；
  3. 构造明文 JSON；
  4. AES-128-ECB/PKCS7 加密 → Base64 → URL 编码；
  5. 请求 Dr.COM Portal 登录、注销或状态接口。

默认服务器：
  登录接口: http://192.168.250.250:801/eportal/portal/login
  注销接口: http://192.168.250.250:801/eportal/portal/logout
  状态接口: http://192.168.250.250:801/eportal/portal/online_list
  loadConfig: http://192.168.250.250:801/eportal/portal/page/loadConfig

注意：
  1. 仅用于本人账号、本人设备和被授权的网络环境。
  2. --dry-run 输出的完整 URL 虽然是加密参数，但注意会包含可被本脚本密钥解密的登录信息。
  3. 建议把账号密码放入 config.json 或环境变量。
  4. 当前校园网环境实测只有浏览器兜底注销有效，因此默认 --logout 会打开浏览器注销页。

开源分享安全约定：
  - 本脚本不应写入任何真实账号、真实密码、手机号、身份证、Cookie、Token。
  - 真实配置只放在本地 config.json；config.json 必须加入 .gitignore。
  - 日志、诊断包、dry-run URL 可能含有加密参数或设备信息，上传前必须脱敏。
"""
from __future__ import annotations

import argparse
import base64
import datetime
import ipaddress
import json
import logging
import os
import random
import re
import socket
import string
import subprocess
import shutil
import sys
import time
import urllib.parse
import uuid
import zipfile
import platform
from pathlib import Path
from typing import Any, Optional

try:
    import requests
except ImportError as exc:  # pragma: no cover
    raise SystemExit("缺少依赖 requests，请先运行：pip install requests cryptography") from exc

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError as exc:  # pragma: no cover
    raise SystemExit("缺少依赖 cryptography，请先运行：pip install requests cryptography") from exc


# ========== 常量 ==========
AUTH_SERVER = "http://192.168.250.250:801/eportal/portal/login"
LOGOUT_SERVER = "http://192.168.250.250:801/eportal/portal/logout"
STATUS_SERVER = "http://192.168.250.250:801/eportal/portal/online_list"
LOAD_CONFIG_SERVER = "http://192.168.250.250:801/eportal/portal/page/loadConfig"
PORTAL_BASE = "http://192.168.250.250/"

AES_KEY = b"5c1d5ad4dea0e8dd"  # Dr.COM Portal 前端固定密钥；必须为 16/24/32 字节。
JS_VERSION = "4.2.1"
DEFAULT_TIMEOUT = 10
SERVER_IP = "192.168.250.250"
ADAPTER_PREFER = "auto"  # auto / wifi / ethernet；由命令行或配置文件在 main() 中设置。
SCHOOL_SSIDS = ("HUNNU", "HUNNU-5G")
_IP_CACHE: dict[str, str] = {}
_SUBPROCESS_TEXT_CACHE: dict[tuple[str, ...], str] = {}

# 运营商编码说明：
#   多数学校 Dr.COM 页面会把运营商编码写成数字。
#   你的学校环境中，默认使用 isp_code="0" 即可，即使状态里可能显示 @unicom。
#   若学校明确要求走运营商出口，再改为 1/2/3。
ISP_CODES = {
    "0": "校园网/学校默认（推荐）",
    "1": "移动",
    "2": "联通运营商出口",
    "3": "电信",
}

ERROR_MSG = {
    "1": "账号或密码错误",
    "2": "该账号正在使用中",
    "3": "账号已欠费",
    "4": "认证被拒绝",
    "5": "无效认证",
    "6": "服务器内部错误",
    "7": "账号不存在",
    "8": "IP地址异常",
    "9": "MAC地址绑定异常",
    "10": "达到最大在线数限制",
    "11": "流量已用尽",
    "12": "时长已用尽",
    "13": "账号被禁用",
    "14": "运营商不存在",
}

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
    ),
    "Referer": PORTAL_BASE,
}

log = logging.getLogger("campus_login")


# ========== 通用工具 ==========
def setup_logging(log_file: Optional[str] = None, verbose: bool = False) -> None:
    """配置日志；force=True 用于避免重复配置导致日志不生效或重复输出。"""
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    if log_file:
        log_path = Path(log_file).expanduser()
        if log_path.parent and str(log_path.parent) not in ("", "."):
            log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


def mask_account(account: str) -> str:
    """日志中隐藏账号中间部分。"""
    account = str(account or "")
    if len(account) <= 4:
        return "*" * len(account)
    return account[:2] + "*" * max(3, len(account) - 4) + account[-2:]


def random_v() -> str:
    return str(random.randint(500, 10500))


def random_rcn(length: int = 8) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def is_success(result: dict[str, Any]) -> bool:
    return result.get("result") in (1, "1", "ok", True)


def is_offline(result: dict[str, Any]) -> bool:
    return result.get("result") in (0, "0", False)


def validate_aes_key(key: bytes) -> None:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"AES_KEY 长度非法：{len(key)} 字节；AES 只接受 16/24/32 字节密钥")


def validate_isp(isp_code: str) -> str:
    isp_code = str(isp_code).strip()
    if isp_code not in ISP_CODES:
        raise ValueError(f"运营商编码非法：{isp_code}；允许值：0=校园网, 1=移动, 2=联通, 3=电信")
    return isp_code


def validate_adapter_prefer(value: Optional[str]) -> str:
    """校验网卡选择偏好：auto / wifi / ethernet。"""
    v = str(value or "auto").strip().lower()
    aliases = {
        "auto": "auto",
        "default": "auto",
        "wifi": "wifi",
        "wi-fi": "wifi",
        "wlan": "wifi",
        "wireless": "wifi",
        "ethernet": "ethernet",
        "eth": "ethernet",
        "wired": "ethernet",
        "lan": "ethernet",
        "有线": "ethernet",
        "以太网": "ethernet",
        "无线": "wifi",
    }
    if v not in aliases:
        raise SystemExit("网卡偏好 adapter_prefer 非法：%r；允许值：auto / wifi / ethernet" % value)
    return aliases[v]


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    """把 aa-bb-cc-dd-ee-ff / aa:bb:... / aabb... 统一为 AABBCCDDEEFF。"""
    if not mac:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(mac))
    if len(cleaned) == 12 and re.fullmatch(r"[0-9A-Fa-f]{12}", cleaned):
        return cleaned.upper()
    return None


def safe_ip_to_int(ip: str) -> Optional[int]:
    try:
        return int(ipaddress.IPv4Address(ip))
    except Exception:
        return None


def sanitize_for_log_url(url: str, max_len: int = 260) -> str:
    """日志中隐藏 params 等敏感 URL 参数，避免泄露可解密登录/注销参数。"""
    try:
        parsed = urllib.parse.urlsplit(url)
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        safe_pairs = []
        for k, v in query_pairs:
            if k.lower() in {"params", "password", "user_password", "token"}:
                safe_pairs.append((k, "***REDACTED***"))
            else:
                safe_pairs.append((k, v))
        rebuilt = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(safe_pairs), parsed.fragment))
        return rebuilt if len(rebuilt) <= max_len else rebuilt[:max_len] + "..."
    except Exception:
        return url[:max_len] + ("..." if len(url) > max_len else "")


def _json_dumps_safe(obj: Any) -> str:
    """统一 JSON 日志格式。"""
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        return str(obj)


# ========== 配置管理 ==========
def load_config(config_path: Optional[str] = None) -> dict[str, Any]:
    """
    加载配置文件。

    设计原则：
      1. 脚本源码中只保留空账号、空密码；
      2. 真实账号密码从 config.json、环境变量或命令行读取；
      3. 命令行参数优先级最高，适合临时切换账号或调试；
      4. 这里不写日志，因为日志系统此时可能尚未初始化。
    """
    # 默认值尽量保持“学校默认校园网/联通出口可用”的简洁配置。
    # user_account/user_password 为空，要求用户在本地 config.json 中自行填写。
    defaults: dict[str, Any] = {
        "user_account": "",
        "user_password": "",
        "isp_code": "0",  # 学校默认：校园网/联通环境通常先用 0；不通再尝试 2。
        "daemon_interval": 60,
        "max_retry": 3,
        "retry_delay": 5,
        "log_dir": "logs",
        "log_file": None,
        "mac": None,
        "ip": None,
        "adapter_prefer": "auto",
        "school_ssids": list(SCHOOL_SSIDS),
        "strict_school_ssid": False,
        "active_profile": None,
        "profiles": {},
        "logout_browser": True,
        "logout_browser_mode": "visible",
        "logout_browser_rounds": 3,
        "visible_browser_fallback": True,
        "_loaded_config_file": None,
    }

    candidates: list[Optional[str]] = [
        config_path,
        "config.json",
        str(Path(__file__).resolve().parent / "config.json"),
    ]
    seen: set[str] = set()

    for p in candidates:
        if not p:
            continue
        path = str(Path(p).expanduser())
        if path in seen:
            continue
        seen.add(path)

        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except json.JSONDecodeError as exc:
                raise SystemExit(f"配置文件 JSON 格式错误：{path}\n{exc}") from exc
            except OSError as exc:
                raise SystemExit(f"配置文件读取失败：{path}\n{exc}") from exc

            if not isinstance(cfg, dict):
                raise SystemExit(f"配置文件必须是 JSON 对象：{path}")
            defaults.update(cfg)
            defaults["_loaded_config_file"] = path
            break

    # 环境变量作为配置文件之后、命令行之前的补充来源。
    defaults["user_account"] = os.getenv("CAMPUS_USER", defaults.get("user_account", ""))
    defaults["user_password"] = os.getenv("CAMPUS_PASSWORD", defaults.get("user_password", ""))
    defaults["isp_code"] = os.getenv("CAMPUS_ISP", defaults.get("isp_code", "0"))
    defaults["mac"] = os.getenv("CAMPUS_MAC", defaults.get("mac"))
    defaults["ip"] = os.getenv("CAMPUS_IP", defaults.get("ip"))
    defaults["adapter_prefer"] = os.getenv("CAMPUS_ADAPTER", defaults.get("adapter_prefer", "auto"))
    return defaults


def parse_bool(value: Any, default: bool = False) -> bool:
    """兼容 JSON / 字符串 / 数字形式的布尔配置。"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    v = str(value).strip().lower()
    if v in {"1", "true", "yes", "y", "on", "启用", "是", "开"}:
        return True
    if v in {"0", "false", "no", "n", "off", "禁用", "否", "关", "关闭"}:
        return False
    return default


def apply_profile_config(cfg: dict[str, Any], profile_name: Optional[str] = None) -> dict[str, Any]:
    """合并账号/设备 profile。保持旧版平铺 config.json 兼容。"""
    profiles = cfg.get("profiles") or {}
    selected = profile_name or cfg.get("active_profile")
    if not selected:
        return cfg
    if not isinstance(profiles, dict):
        raise SystemExit("配置 profiles 必须是对象，例如 {\"main\": {...}}")
    if selected not in profiles:
        raise SystemExit(f"未找到 profile：{selected}；可用 profile：{', '.join(profiles.keys()) or '无'}")
    profile_cfg = profiles[selected]
    if not isinstance(profile_cfg, dict):
        raise SystemExit(f"profile {selected!r} 必须是对象")
    merged = dict(cfg)
    # profile 内的配置覆盖全局配置，但不覆盖 _loaded_config_file/profiles 本身。
    for k, v in profile_cfg.items():
        merged[k] = v
    merged["_active_profile"] = selected
    return merged


def int_from_cli_or_cfg(cli_value: Optional[int], cfg: dict[str, Any], key: str, default: int) -> int:
    raw = cli_value if cli_value is not None else cfg.get(key, default)
    try:
        value = int(raw)
    except Exception as exc:
        raise SystemExit(f"参数 {key} 必须是整数，当前值：{raw!r}") from exc
    if value <= 0:
        raise SystemExit(f"参数 {key} 必须大于 0，当前值：{value}")
    return value


# ========== 网络工具 ==========
# 这些关键词用于排除不应参与校园网认证的虚拟/代理/隧道/蓝牙网卡。
# 例如 Clash/Mihomo TUN 会生成 198.18.x.x 地址，不能提交给 Portal。
EXCLUDED_ADAPTER_KEYWORDS = (
    "clash", "mihomo", "tun", "tap", "wintun", "vpn", "loopback",
    "vmware", "virtualbox", "hyper-v", "vethernet", "蓝牙", "bluetooth",
)


def _is_excluded_client_ip(ip: str) -> bool:
    """排除 Clash/Mihomo TUN、回环、链路本地等不应提交给 Portal 的地址。"""
    try:
        addr = ipaddress.IPv4Address(str(ip).strip())
    except Exception:
        return True

    excluded_nets = (
        ipaddress.IPv4Network("0.0.0.0/8"),
        ipaddress.IPv4Network("127.0.0.0/8"),
        ipaddress.IPv4Network("169.254.0.0/16"),
        # Clash/Mihomo TUN 常用保留测试网段；不能作为校园网认证 IP 提交。
        ipaddress.IPv4Network("198.18.0.0/15"),
    )
    return any(addr in net for net in excluded_nets)


def _extract_ipv4_from_ipconfig_block(block: str) -> list[str]:
    """从 ipconfig /all 的适配器块中提取 IPv4 地址。"""
    ips: list[str] = []
    for m in re.finditer(r"IPv4[^:\r\n]*:\s*([0-9]+(?:\.[0-9]+){3})", block):
        ip = m.group(1)
        if not _is_excluded_client_ip(ip):
            ips.append(ip)
    return ips


def _block_is_disconnected_or_virtual(block: str) -> bool:
    lower = block.lower()
    disconnected_keywords = ("媒体已断开", "media disconnected", "已断开")
    if any(k in lower for k in disconnected_keywords):
        return True
    return any(k in lower for k in EXCLUDED_ADAPTER_KEYWORDS)


def _classify_adapter_block(block: str) -> str:
    """粗略判断 ipconfig 适配器类型：wifi / ethernet / other。"""
    lower = block.lower()
    if any(k in lower for k in ("无线局域网适配器", "wireless lan adapter", "wi-fi", "wlan")):
        return "wifi"
    if any(k in lower for k in ("以太网适配器", "ethernet adapter")):
        return "ethernet"
    return "other"


def _get_windows_ip_from_ipconfig(adapter_prefer: Optional[str] = None) -> Optional[str]:
    """从 Windows ipconfig /all 中选择真实 IPv4，跳过 Clash/TUN/虚拟网卡。

    adapter_prefer:
      - auto: 先 Wi-Fi 后 Ethernet；多网卡时建议显式指定。
      - wifi: 只优先 Wi-Fi/WLAN，失败后再兜底。
      - ethernet: 只优先有线以太网，失败后再兜底。
    """
    prefer = validate_adapter_prefer(adapter_prefer or ADAPTER_PREFER)
    try:
        output = _run_text_command(["ipconfig", "/all"], timeout=5)
        blocks = _ipconfig_blocks(output)
    except Exception as exc:
        log.debug(f"ipconfig 获取 IPv4 失败：{exc}")
        return None

    usable: list[tuple[str, str, list[str]]] = []
    for block in blocks:
        if _block_is_disconnected_or_virtual(block):
            continue
        ips = _extract_ipv4_from_ipconfig_block(block)
        if not ips:
            continue
        usable.append((_classify_adapter_block(block), block, ips))

    if prefer == "wifi":
        order = ("wifi", "ethernet", "other")
    elif prefer == "ethernet":
        order = ("ethernet", "wifi", "other")
    else:
        # 校园网常见是 Wi-Fi；若用户切有线，请用 --adapter ethernet 或 config 指定。
        order = ("wifi", "ethernet", "other")

    for adapter_type in order:
        for t, _block, ips in usable:
            if t == adapter_type:
                return ips[0]

    return None


def list_windows_adapters() -> list[dict[str, Any]]:
    """列出 ipconfig 中识别到的适配器，便于用户确认 --adapter/--ip/--mac。"""
    try:
        output = _run_text_command(["ipconfig", "/all"], timeout=5)
        blocks = _ipconfig_blocks(output)
    except Exception as exc:
        log.error(f"读取 ipconfig 失败：{exc}")
        return []

    items: list[dict[str, Any]] = []
    for block in blocks:
        header = block.splitlines()[0].strip() if block.splitlines() else "未知适配器"
        ips = _extract_ipv4_from_ipconfig_block(block)
        mac = _extract_mac_from_ipconfig_block(block) or ""
        excluded = _block_is_disconnected_or_virtual(block)
        items.append({
            "name": header,
            "type": _classify_adapter_block(block),
            "ipv4": ips,
            "mac": mac,
            "excluded": excluded,
        })
    return items

def get_current_ssid() -> Optional[str]:
    """获取当前 Windows Wi-Fi SSID；有线网卡或非 Windows 环境返回 None。"""
    if os.name != "nt":
        return None
    try:
        output = _run_text_command(["netsh", "wlan", "show", "interfaces"], timeout=5)
    except Exception as exc:
        log.debug(f"读取 Wi-Fi SSID 失败：{exc}")
        return None

    state_connected = False
    ssid: Optional[str] = None
    for line in output.splitlines():
        # 中文: 状态 : 已连接；英文: State : connected
        if re.search(r"(?:状态|State)\s*:\s*(?:已连接|connected)", line, re.I):
            state_connected = True
        # 避免匹配 BSSID
        m = re.match(r"\s*(?:SSID)\s*:\s*(.+?)\s*$", line, re.I)
        if m and "BSSID" not in line.upper():
            value = m.group(1).strip()
            if value:
                ssid = value
    return ssid if state_connected else None


def normalize_ssids(value: Any) -> list[str]:
    if value is None:
        return list(SCHOOL_SSIDS)
    if isinstance(value, str):
        return [x.strip() for x in re.split(r"[,，;；]", value) if x.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(x).strip() for x in value if str(x).strip()]
    return list(SCHOOL_SSIDS)


def log_network_context(cfg: dict[str, Any]) -> None:
    """记录当前网络上下文，帮助判断是否在 HUNNU/HUNNU-5G 或有线校园网。"""
    ssids = normalize_ssids(cfg.get("school_ssids"))
    ssid = get_current_ssid()
    if ssid:
        matched = ssid in ssids
        level = logging.INFO if matched else logging.WARNING
        log.log(level, f"Wi-Fi SSID: {ssid}；学校 SSID: {', '.join(ssids)}；匹配: {matched}")
        if parse_bool(cfg.get("strict_school_ssid"), False) and not matched:
            raise SystemExit(f"当前 Wi-Fi 不是学校网络：{ssid}；要求连接：{', '.join(ssids)}")
    else:
        log.info(f"未检测到已连接 Wi-Fi SSID；可能正在使用有线网卡，或系统不支持 netsh 检测。学校 Wi-Fi: {', '.join(ssids)}")


def _browser_candidates() -> list[str]:
    """查找可用于 headless 的 Edge/Chrome/Chromium。"""
    names = ["msedge", "chrome", "chrome.exe", "msedge.exe", "chromium", "chromium-browser", "google-chrome", "microsoft-edge"]
    paths: list[str] = []
    for name in names:
        found = shutil.which(name)
        if found:
            paths.append(found)
    if os.name == "nt":
        roots = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("LOCALAPPDATA")]
        rels = [
            r"Microsoft\Edge\Application\msedge.exe",
            r"Google\Chrome\Application\chrome.exe",
        ]
        for root in roots:
            if not root:
                continue
            for rel in rels:
                candidate = str(Path(root) / rel)
                if Path(candidate).exists():
                    paths.append(candidate)
    unique: list[str] = []
    for p in paths:
        if p and p not in unique:
            unique.append(p)
    return unique


def open_url_headless(url: str, timeout: int = 12) -> bool:
    """使用无界面 Edge/Chrome 访问 URL。返回是否成功启动并退出。"""
    browsers = _browser_candidates()
    if not browsers:
        log.warning("headless 浏览器注销不可用：未找到 Edge/Chrome/Chromium 可执行文件")
        return False
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    for browser in browsers:
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--disable-extensions",
            "--no-first-run",
            "--no-default-browser-check",
            "--dump-dom",
            url,
        ]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, creationflags=creationflags)
            log.info(f"headless 浏览器访问完成 | browser={Path(browser).name} | returncode={proc.returncode}")
            return proc.returncode in (0, 1)  # 部分 Chromium 访问内网页可能返回 1，但请求已发出。
        except Exception as exc:
            log.debug(f"headless 浏览器访问失败 | browser={browser} | {exc}")
    log.warning("headless 浏览器注销尝试失败：所有候选浏览器均不可用")
    return False


def open_url_visible(url: str) -> bool:
    try:
        import webbrowser
        return bool(webbrowser.open(url))
    except Exception as exc:
        log.warning(f"可见浏览器打开失败：{exc}")
        return False


def redact_config(obj: Any) -> Any:
    """导出日志包时脱敏配置。"""
    sensitive = {"user_password", "password", "passwd", "pwd", "token", "params"}
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if str(k).lower() in sensitive:
                out[k] = "***REDACTED***"
            elif "account" in str(k).lower() and isinstance(v, str):
                out[k] = mask_account(v)
            else:
                out[k] = redact_config(v)
        return out
    if isinstance(obj, list):
        return [redact_config(x) for x in obj]
    return obj


def redact_log_text(text: str) -> str:
    """导出诊断包时脱敏日志中的账号、密码、params 密文和完整 URL。"""
    text = re.sub(r'''(user_password|password|pwd|passwd)(['"=:\s]+)([^,}\s]+)''', r"\1\2***REDACTED***", text, flags=re.I)
    text = re.sub(r"(账号[:：]\s*)([^,，\s]+)", lambda m: m.group(1) + mask_account(m.group(2)), text)
    text = re.sub(r'''(user_account['"=:\s]+)([^,}\s]+)''', lambda m: m.group(1) + mask_account(m.group(2).strip("'\"")), text, flags=re.I)
    text = re.sub(r"([?&]params=)[^&\s]+", r"\1***REDACTED***", text)
    text = re.sub(r'''(params['"=:\s]+)([A-Za-z0-9%+/=]{24,})''', r"\1***REDACTED***", text, flags=re.I)
    return text


def _run_diag_command(cmd: list[str], timeout: int = 8) -> str:
    return _run_text_command(cmd, timeout=timeout, use_cache=False)


def export_debug_bundle(cfg: dict[str, Any], log_file: Optional[str] = None, out_dir: Optional[str] = None) -> str:
    """导出 bug 分析用日志包 ZIP，包含脱敏配置、网卡、路由、Wi-Fi、日志文件。"""
    base_dir = Path(out_dir or cfg.get("log_dir") or "logs").expanduser()
    base_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    bundle_path = base_dir / f"campus_login_debug_{stamp}.zip"
    temp_dir = base_dir / f"_debug_{stamp}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "time": stamp,
        "script": Path(__file__).name,
        "python": sys.version,
        "platform": platform.platform(),
        "cwd": os.getcwd(),
        "active_profile": cfg.get("_active_profile"),
        "adapter_prefer": ADAPTER_PREFER,
        "current_ssid": get_current_ssid(),
        "local_ip_auto": get_local_ip(cfg.get("ip")),
        "log_file": log_file,
    }
    (temp_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (temp_dir / "config.redacted.json").write_text(json.dumps(redact_config(cfg), ensure_ascii=False, indent=2), encoding="utf-8")
    (temp_dir / "adapters.json").write_text(json.dumps(list_windows_adapters(), ensure_ascii=False, indent=2), encoding="utf-8")

    commands = {
        "ipconfig_all.txt": ["ipconfig", "/all"],
        "route_print.txt": ["route", "print"],
        "netsh_wlan_interfaces.txt": ["netsh", "wlan", "show", "interfaces"],
    }
    for filename, cmd in commands.items():
        (temp_dir / filename).write_text(_run_diag_command(cmd), encoding="utf-8", errors="replace")

    # 收集当前日志和 logs 目录最近日志。
    log_candidates: list[Path] = []
    if log_file:
        log_candidates.append(Path(log_file).expanduser())
    log_dir = Path(cfg.get("log_dir") or "logs").expanduser()
    if log_dir.exists():
        log_candidates.extend(sorted(log_dir.glob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)[:10])
    for lp in log_candidates:
        try:
            if lp.exists() and lp.is_file():
                target = temp_dir / f"log_{lp.name}"
                target.write_text(redact_log_text(lp.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
        except Exception:
            pass

    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file in temp_dir.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(temp_dir))

    # 清理临时目录。
    for file in sorted(temp_dir.rglob("*"), reverse=True):
        try:
            if file.is_file():
                file.unlink()
            elif file.is_dir():
                file.rmdir()
        except Exception:
            pass
    try:
        temp_dir.rmdir()
    except Exception:
        pass
    return str(bundle_path)


def get_local_ip(ip_override: Optional[str] = None) -> str:
    """获取本机校园网 IPv4。优先使用 --ip/config/env；自动识别时跳过 Clash/Mihomo TUN 地址。"""
    if ip_override:
        try:
            ip = str(ipaddress.IPv4Address(str(ip_override).strip()))
            if _is_excluded_client_ip(ip):
                log.warning(f"指定的 IP 看起来不是校园网真实地址，仍按用户指定使用：{ip}")
            return ip
        except Exception:
            log.warning(f"指定的 IP 非法，已忽略：{ip_override!r}")

    cache_key = f"auto:{ADAPTER_PREFER}"
    if cache_key in _IP_CACHE:
        return _IP_CACHE[cache_key]

    # 先用 UDP 路由探测；如果 Clash TUN 接管，可能得到 198.18.x.x，需要回退到 ipconfig。
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.connect((SERVER_IP, 80))
            ip = s.getsockname()[0]
            if not _is_excluded_client_ip(ip):
                _IP_CACHE[cache_key] = ip
                return ip
            log.warning(f"自动探测到疑似代理/TUN/无效 IP：{ip}，改用 ipconfig 按 adapter_prefer={ADAPTER_PREFER} 选择真实物理网卡 IPv4；本次运行后续将缓存结果")
    except Exception as exc:
        log.debug(f"UDP 探测本机 IP 失败：{exc}")

    ip_from_ipconfig = _get_windows_ip_from_ipconfig(ADAPTER_PREFER)
    if ip_from_ipconfig:
        _IP_CACHE[cache_key] = ip_from_ipconfig
        return ip_from_ipconfig

    return "0.0.0.0"


def _decode_subprocess_output(stdout: bytes) -> str:
    """更稳健地解码 Windows 命令输出，避免 netsh 在部分系统出现中文乱码。"""
    if not isinstance(stdout, (bytes, bytearray)):
        return str(stdout)
    candidates: list[tuple[int, str, str]] = []
    encodings = ["utf-8-sig", "utf-8", "gbk", "cp936", "mbcs"]
    for enc in encodings:
        try:
            text = bytes(stdout).decode(enc, errors="replace")
        except LookupError:
            continue
        # replacement 越少越好；明显 mojibake 标记越少越好。
        score = text.count("�") * 10 + sum(text.count(x) for x in ("绯", "鍚", "涓", "鐗", "鐘", "鏃", "杩")) * 3
        candidates.append((score, enc, text))
    if not candidates:
        return bytes(stdout).decode(errors="replace")
    candidates.sort(key=lambda x: x[0])
    return candidates[0][2]


def _run_text_command(cmd: list[str], timeout: int = 8, use_cache: bool = True) -> str:
    """运行系统命令并返回可靠解码文本。诊断类命令默认缓存，减少重复调用。"""
    key = tuple(cmd)
    if use_cache and key in _SUBPROCESS_TEXT_CACHE:
        return _SUBPROCESS_TEXT_CACHE[key]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        text = _decode_subprocess_output(proc.stdout + (b"\n" + proc.stderr if proc.stderr else b""))
    except Exception as exc:
        text = f"COMMAND FAILED: {' '.join(cmd)}\n{exc}\n"
    if use_cache:
        _SUBPROCESS_TEXT_CACHE[key] = text
    return text


def _extract_mac_from_ipconfig_block(block: str) -> Optional[str]:
    patterns = [
        r"(?:物理地址|Physical Address)[^:\r\n]*:\s*([0-9A-Fa-f:-]{12,17})",
        r"(?:MAC Address|硬件地址)[^:\r\n]*:\s*([0-9A-Fa-f:-]{12,17})",
    ]
    for pattern in patterns:
        m = re.search(pattern, block)
        if m:
            mac = normalize_mac(m.group(1))
            if mac:
                return mac
    return None


def _ipconfig_blocks(output: str) -> list[str]:
    """更稳健地切分 Windows ipconfig /all 的适配器块。

    旧的空行切分在部分中文 Windows 输出里会把“连接特定 DNS 后缀”等行误拆成单独适配器。
    这里优先按“xxx适配器 xxx:” / "xxx adapter xxx:" 作为块标题切分。
    """
    lines = output.splitlines()
    blocks: list[list[str]] = []
    current: list[str] = []

    def is_adapter_header(line: str) -> bool:
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped.endswith(":"):
            return False
        return ("适配器" in stripped) or ("adapter" in lower)

    for line in lines:
        if is_adapter_header(line):
            if current:
                blocks.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append(current)

    parsed = ["\n".join(b).strip() for b in blocks if "\n".join(b).strip()]
    if parsed:
        return parsed
    return [b for b in re.split(r"\r?\n\s*\r?\n", output) if b.strip()]


def get_local_mac(local_ip: Optional[str] = None, mac_override: Optional[str] = None) -> str:
    """获取本机 MAC 地址（格式 AABBCCDDEEFF）。优先匹配当前 IP 所在网卡，避免误取有线/虚拟网卡。"""
    specified = normalize_mac(mac_override)
    if specified:
        return specified
    if mac_override:
        log.warning(f"指定的 MAC 非法，已忽略：{mac_override!r}；合法格式示例：AA-BB-CC-DD-EE-FF")

    local_ip = local_ip or get_local_ip()

    # Windows 优先：从 ipconfig /all 中找“包含当前 IPv4 地址”的适配器块。
    try:
        output = _run_text_command(["ipconfig", "/all"], timeout=5)
        blocks = _ipconfig_blocks(output)

        # 第一优先级：当前 IP 所在适配器。
        if local_ip and local_ip != "0.0.0.0":
            for block in blocks:
                if local_ip in block:
                    mac = _extract_mac_from_ipconfig_block(block)
                    if mac:
                        return mac

        # 第二优先级：有 IPv4、未断开、看起来像 WLAN/以太网的适配器。
        adapter_keywords = (
            "无线局域网适配器", "Wireless LAN adapter", "WLAN", "Wi-Fi", "以太网适配器", "Ethernet adapter"
        )
        disconnected_keywords = ("媒体已断开", "Media disconnected", "已断开")
        for block in blocks:
            if any(k in block for k in adapter_keywords) and not any(k in block for k in disconnected_keywords):
                if re.search(r"IPv4[^:\r\n]*:\s*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", block):
                    mac = _extract_mac_from_ipconfig_block(block)
                    if mac:
                        return mac
    except Exception as exc:
        log.debug(f"ipconfig 获取 MAC 失败，转入 uuid.getnode 回退：{exc}")

    # 回退：uuid.getnode。若返回随机本地管理地址，不采用。
    try:
        mac_int = uuid.getnode()
        mac_hex = f"{mac_int:012x}"
        # 第一字节最低第二位为 1 通常表示本地管理地址，可能不是硬件 MAC。
        first_octet = int(mac_hex[:2], 16)
        if not (first_octet & 0b10):
            return mac_hex.upper()
    except Exception as exc:
        log.debug(f"uuid.getnode 获取 MAC 失败：{exc}")

    return "000000000000"


def check_server_alive(session: Optional[requests.Session] = None) -> bool:
    """检测认证服务器是否可达。"""
    client = session or requests
    try:
        resp = client.get(PORTAL_BASE, timeout=3, headers=HEADERS)
        return 200 <= resp.status_code < 500
    except requests.RequestException:
        return False


# ========== 加解密与响应解析 ==========
def encrypt_params(plaintext: str, key: bytes = AES_KEY) -> str:
    """AES-ECB/PKCS7 加密 + Base64 编码。"""
    validate_aes_key(key)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ct).decode("ascii")


def decrypt_params(encrypted_b64: str, key: bytes = AES_KEY) -> str:
    """解密 Base64 密文。仅用于调试本人请求。"""
    validate_aes_key(key)
    try:
        ct = base64.b64decode(encrypted_b64, validate=True)
    except Exception as exc:
        raise ValueError("输入不是合法 Base64 密文") from exc

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt.decode("utf-8")


def _aes_en(data: dict[str, Any]) -> dict[str, str]:
    plaintext = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    return {"params": encrypt_params(plaintext, AES_KEY)}


def _parse_jsonp(text: str, callback: Optional[str] = None) -> dict[str, Any]:
    """解析 callback({...}) / callback([...]); 兼容空白、分号和 callback 名变化。"""
    text = (text or "").strip()
    callbacks = [callback] if callback else []

    # 先按指定 callback 解析。
    for cb in callbacks:
        if not cb:
            continue
        pattern = rf"^\s*{re.escape(cb)}\s*\((.*)\)\s*;?\s*$"
        m = re.search(pattern, text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(1))
            except json.JSONDecodeError:
                return {"raw": text}

    # 再做通用 JSONP 解析。
    m = re.search(r"^[A-Za-z_$][\w$]*\s*\((.*)\)\s*;?\s*$", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            return {"raw": text}

    # 最后尝试纯 JSON。
    try:
        return json.loads(text)
    except Exception:
        return {"raw": text[:2000]}


# ========== 参数构造 ==========
def fetch_rcn(session: Optional[requests.Session] = None, ip_override: Optional[str] = None) -> str:
    """从 loadConfig 获取服务器端 rcn。失败时使用随机值，以保持原脚本容错逻辑。"""
    client = session or requests
    local_ip = get_local_ip(ip_override)
    ip_b64 = base64.b64encode(local_ip.encode("utf-8")).decode("ascii")

    try:
        resp = client.get(
            LOAD_CONFIG_SERVER,
            params={
                "callback": "dr1001",
                "program_index": "",
                "wlan_vlan_id": "1",
                "wlan_user_ip": ip_b64,
                "wlan_user_ipv6": "",
                "wlan_user_ssid": "",
                "wlan_user_areaid": "",
                "wlan_ac_ip": "",
                "wlan_ap_mac": "",
                "gw_id": "",
                "jsVersion": JS_VERSION,
                "v": random_v(),
                "lang": "zh",
            },
            timeout=DEFAULT_TIMEOUT,
            headers=HEADERS,
        )
        result = _parse_jsonp(resp.text, "dr1001")
        rcn = result.get("data", {}).get("rcn", "") if isinstance(result.get("data"), dict) else ""
        if rcn:
            log.debug(f"获取服务器 rcn 成功: {rcn}")
            return str(rcn)
        log.warning("loadConfig 未返回 rcn，使用随机值")
        return random_rcn()
    except requests.RequestException as exc:
        log.warning(f"获取 rcn 请求失败：{exc}，使用随机值")
        return random_rcn()


def build_login_params(
    user_account: str,
    password: str,
    isp_code: str = "0",
    rcn: Optional[str] = None,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> dict[str, Any]:
    """构造登录明文参数。"""
    isp_code = validate_isp(isp_code)
    local_ip = get_local_ip(ip_override)
    mac = get_local_mac(local_ip=local_ip, mac_override=mac_override)

    if rcn is None:
        rcn = fetch_rcn(session=session, ip_override=ip_override)

    return {
        "login_method": 1,
        "user_account": f",{isp_code},{user_account}",
        "user_password": password,
        "wlan_user_ip": local_ip,
        "wlan_user_ipv6": "",
        "wlan_user_mac": mac,
        "wlan_ac_ip": "",
        "wlan_ac_name": "",
        "jsVersion": JS_VERSION,
        "login_t": "0",
        "js_status": "0",
        "is_page": "1",
        "is_page_new": int(random_v()),
        "terminal_type": 1,
        "lang": "zh-cn",
        "rcn": rcn,
    }


def build_login_query(
    user_account: str,
    password: str,
    isp_code: str = "0",
    rcn: Optional[str] = None,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> dict[str, str]:
    params = build_login_params(
        user_account,
        password,
        isp_code,
        rcn=rcn,
        mac_override=mac_override,
        ip_override=ip_override,
        session=session,
    )
    plaintext = json.dumps(params, separators=(",", ":"), ensure_ascii=False)
    encrypted = encrypt_params(plaintext, AES_KEY)
    return {
        "callback": "dr1006",
        "params": encrypted,
        "jsVersion": JS_VERSION,
        "v": random_v(),
        "lang": "zh",
    }


def build_login_url(
    user_account: str,
    password: str,
    isp_code: str = "0",
    rcn: Optional[str] = None,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
    session: Optional[requests.Session] = None,
) -> str:
    query = build_login_query(
        user_account,
        password,
        isp_code,
        rcn=rcn,
        mac_override=mac_override,
        ip_override=ip_override,
        session=session,
    )
    return AUTH_SERVER + "?" + urllib.parse.urlencode(query)


def fetch_ac_portal_info(session: Optional[requests.Session] = None) -> dict[str, str]:
    """
    从 Portal 的 a79.htm 获取 AC 侧记录的 usermac/acname。

    说明：旧版实测有效注销脚本使用 a79.htm 重定向中的 usermac/acname 参与注销。
    在部分 Dr.COM 环境中，本机 ipconfig 识别到的 MAC 与 AC 侧记录可能存在格式或来源差异，
    注销时优先使用 AC 侧记录更接近浏览器行为。
    """
    client = session or requests
    info = {"mac": "", "ac_name": ""}
    try:
        resp = client.get(
            urllib.parse.urljoin(PORTAL_BASE, "a79.htm"),
            timeout=5,
            headers=HEADERS,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        log.debug(f"读取 a79.htm 失败：{exc}")
        return info

    text = ""
    try:
        text = resp.text or ""
    except Exception:
        text = ""

    location = resp.headers.get("Location", "") or ""
    combined = location + "\n" + text

    mac_match = re.search(r"usermac=([^&\"\s]+)", combined, re.I)
    if mac_match:
        mac = normalize_mac(urllib.parse.unquote(mac_match.group(1)))
        if mac:
            info["mac"] = mac

    ac_match = re.search(r"acname=([^&\"\s]+)", combined, re.I)
    if ac_match:
        info["ac_name"] = urllib.parse.unquote(ac_match.group(1))

    return info


def build_logout_query(
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
    session: Optional[requests.Session] = None,
    prefer_ac_info: bool = True,
) -> dict[str, str]:
    """构造注销参数。默认优先使用 a79.htm 中 AC 记录的 usermac/acname，兼容旧版有效注销逻辑。"""
    local_ip = get_local_ip(ip_override)
    local_mac = get_local_mac(local_ip=local_ip, mac_override=mac_override)
    ac_info = fetch_ac_portal_info(session=session) if prefer_ac_info else {"mac": "", "ac_name": ""}

    mac = ac_info.get("mac") or local_mac
    ac_name = ac_info.get("ac_name") or ""
    if ac_info.get("mac"):
        log.debug(f"注销使用 AC 侧 usermac={ac_info['mac']}，本机识别 MAC={local_mac}")
    if ac_name:
        log.debug(f"注销使用 AC 名称：{ac_name}")

    params = {
        "login_method": 1,
        "user_account": "drcom",
        "user_password": "123",
        "ac_logout": 1,
        "register_mode": 1,
        "wlan_user_ip": local_ip,
        "wlan_user_ipv6": "",
        "wlan_vlan_id": 1,
        "wlan_user_mac": mac,
        "wlan_ac_ip": "",
        "wlan_ac_name": ac_name,
        "jsVersion": JS_VERSION,
    }
    plaintext = json.dumps(params, separators=(",", ":"), ensure_ascii=False)
    encrypted = encrypt_params(plaintext, AES_KEY)
    return {
        "callback": "dr1002",
        "params": encrypted,
        "jsVersion": JS_VERSION,
        # 旧版有效脚本固定为 6521；这里保留随机也通常可行，但注销兼容模式用固定值更贴近浏览器请求。
        "v": "6521",
        "lang": "zh",
    }


def build_logout_url(
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
    session: Optional[requests.Session] = None,
    prefer_ac_info: bool = True,
) -> str:
    return LOGOUT_SERVER + "?" + urllib.parse.urlencode(
        build_logout_query(mac_override, ip_override, session=session, prefer_ac_info=prefer_ac_info)
    )


# ========== 状态 / 登录 / 注销 ==========
# 三个核心动作的安全边界：
#   - status：只查询当前设备在线状态，不提交账号密码；
#   - login ：提交账号密码完成认证，日志中必须隐藏账号中间部分，不打印密码；
#   - logout：不使用用户密码，而是使用 Dr.COM 约定的注销参数，并通过阶段复核确认是否真正离线。
def check_status(
    session: Optional[requests.Session] = None,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
) -> dict[str, Any]:
    """查询当前在线状态。返回 result=1 在线，result=0 不在线，result=-1 查询异常。"""
    client = session or requests
    local_ip = get_local_ip(ip_override)
    ip_int = safe_ip_to_int(local_ip)
    if ip_int is None:
        return {"result": -1, "msg": f"无法将本机 IP 转换为整数：{local_ip}"}

    mac = get_local_mac(local_ip=local_ip, mac_override=mac_override)
    if mac == "000000000000":
        log.warning("未能识别有效 MAC；如状态/登录失败，请使用 --mac 手工指定")

    data = {
        "user_account": "",
        "user_password": "",
        "wlan_user_mac": mac,
        "wlan_user_ip": str(ip_int),
        "curr_user_ip": str(ip_int),
        "jsVersion": JS_VERSION,
    }

    try:
        resp = client.get(
            STATUS_SERVER,
            params={
                **_aes_en(data),
                "callback": "dr1003",
                "jsVersion": JS_VERSION,
                "v": random_v(),
                "lang": "zh",
            },
            timeout=DEFAULT_TIMEOUT,
            headers=HEADERS,
        )
        result = _parse_jsonp(resp.text, "dr1003")
        if "result" not in result:
            result = _parse_jsonp(resp.text)  # 兼容 callback 名变化。
        return result
    except requests.RequestException as exc:
        log.error(f"状态查询失败：{exc}")
        return {"result": -1, "msg": str(exc)}


def format_error(result: dict[str, Any]) -> str:
    """将服务器响应转换为中文提示。"""
    if is_success(result):
        return "登录成功"

    ret_code = str(result.get("ret_code", ""))
    msg = result.get("msg", "") or result.get("message", "")

    if ret_code in ERROR_MSG:
        return f"[{ret_code}] {ERROR_MSG[ret_code]}"
    if msg:
        return str(msg)
    return f"未知错误，响应：{json.dumps(result, ensure_ascii=False)}"


def do_login(
    user_account: str,
    password: str,
    isp_code: str = "0",
    max_retry: int = 3,
    retry_delay: int = 5,
    force: bool = False,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
) -> dict[str, Any]:
    """执行登录请求，支持在线检查与失败重试。"""
    isp_code = validate_isp(isp_code)
    with requests.Session() as session:
        session.trust_env = False  # 避免 HTTP_PROXY/HTTPS_PROXY 环境变量把 Portal 请求送进代理
        local_ip = get_local_ip(ip_override)
        mac = get_local_mac(local_ip=local_ip, mac_override=mac_override)
        log.info(f"本机 IP: {local_ip}, MAC: {mac}")

        if local_ip == "0.0.0.0":
            log.error("无法获取本机 IP，请检查网络连接；必要时使用 --ip 手工指定")
            return {"result": -1, "msg": "无法获取本机IP"}

        if mac == "000000000000":
            log.warning("无法获取有效 MAC；如服务器绑定 MAC，建议使用 --mac AA-BB-CC-DD-EE-FF")

        if not check_server_alive(session):
            log.error("认证服务器不可达，请确认已连接校园网或认证服务器地址是否正确")
            return {"result": -1, "msg": "认证服务器不可达"}

        if not force:
            status = check_status(session=session, mac_override=mac_override, ip_override=ip_override)
            if is_success(status):
                uid = status.get("uid") or ""
                if not uid and isinstance(status.get("list"), list) and status["list"]:
                    uid = status["list"][0].get("user_account", "未知")
                log.info(f"当前已在线，账号: {uid or '未知'}；无需重复登录（使用 --force 可强制登录）")
                return {"result": 1, "msg": "已在线", "uid": uid}
        else:
            log.info("--force 模式：跳过在线检查，直接登录")

        last_result: dict[str, Any] = {"result": -1, "msg": "未执行请求"}
        for attempt in range(1, max_retry + 1):
            log.info(f"正在登录... 账号: {mask_account(user_account)}, 运营商: {isp_code}-{ISP_CODES[isp_code]}（第 {attempt}/{max_retry} 次）")
            rcn = fetch_rcn(session=session, ip_override=ip_override)
            query = build_login_query(
                user_account,
                password,
                isp_code,
                rcn=rcn,
                mac_override=mac_override,
                ip_override=ip_override,
                session=session,
            )

            try:
                resp = session.get(AUTH_SERVER, params=query, timeout=DEFAULT_TIMEOUT, headers=HEADERS)
                result = _parse_jsonp(resp.text, "dr1006")
                if "result" not in result:
                    result = _parse_jsonp(resp.text)
                last_result = result
            except requests.RequestException as exc:
                log.error(f"登录请求失败：{exc}")
                last_result = {"result": -1, "msg": str(exc)}
                if attempt < max_retry:
                    time.sleep(retry_delay)
                continue

            log.info(f"服务器响应: {json.dumps(result, ensure_ascii=False)}")
            if is_success(result):
                log.info("登录成功")
                return result

            ret_code = str(result.get("ret_code", ""))
            # 明确不可通过重试解决的错误：账号、欠费、不存在、禁用。
            if ret_code in {"1", "3", "7", "13"}:
                log.error(format_error(result))
                return result

            if attempt < max_retry:
                log.info(f"{retry_delay} 秒后重试...")
                time.sleep(retry_delay)

        log.error(f"达到最大重试次数，登录失败：{format_error(last_result)}")
        return last_result


def do_logout(
    max_retry: int = 2,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
    browser_fallback: bool = True,
    simple_rounds: int = 3,
    browser_mode: str = "auto",
    browser_rounds: int = 3,
    visible_fallback: bool = True,
) -> dict[str, Any]:
    """
    执行注销（兼容旧版有效逻辑 + headless/visible 浏览器分层兜底）。

    browser_mode:
      - auto: 先无界面 headless Edge/Chrome，失败或仍在线时再可见浏览器兜底；推荐，兼顾少打扰与成功率。
      - headless: 只尝试无界面浏览器；不保证在所有 Dr.COM 环境有效。
      - visible: 直接使用系统默认可见浏览器；最接近已验证有效旧脚本。
      - off: 不使用浏览器；当前环境不推荐。
    """
    browser_mode = str(browser_mode or "auto").lower()
    if browser_mode not in {"auto", "headless", "visible", "off"}:
        raise SystemExit("logout_browser_mode 只允许 auto/headless/visible/off")

    def _status_label(status: dict[str, Any]) -> str:
        if is_success(status):
            uid = status.get("uid", "")
            if not uid and isinstance(status.get("list"), list) and status["list"]:
                uid = status["list"][0].get("user_account", "")
            return "在线" + (f"，账号: {uid}" if uid else "")
        if is_offline(status):
            return "不在线"
        return "异常/未知：" + json.dumps(status, ensure_ascii=False)

    def _audit_status(
        session: requests.Session,
        stage: str,
        mac_override: Optional[str],
        ip_override: Optional[str],
        sleep_before_check: float = 1.0,
    ) -> tuple[dict[str, Any], bool]:
        if sleep_before_check > 0:
            time.sleep(sleep_before_check)
        status = check_status(session=session, mac_override=mac_override, ip_override=ip_override)
        label = _status_label(status)
        log.info(f"阶段复核 | {stage} | {label}")
        return status, is_offline(status)

    with requests.Session() as session:
        session.trust_env = False
        local_ip = get_local_ip(ip_override)
        local_mac = get_local_mac(local_ip=local_ip, mac_override=mac_override)
        ac_info = fetch_ac_portal_info(session=session)
        logout_mac = ac_info.get("mac") or local_mac
        ac_name = ac_info.get("ac_name") or ""

        log.info("========== 注销审计开始 ==========")
        log.info(
            f"注销环境 | adapter_prefer={ADAPTER_PREFER}, browser_fallback={browser_fallback}, "
            f"browser_mode={browser_mode}, visible_fallback={visible_fallback}, "
            f"encrypted_rounds={max_retry}, simple_rounds={simple_rounds}, browser_rounds={browser_rounds}"
        )
        log.info(f"注销身份 | 本机 IP: {local_ip}, 本机 MAC: {local_mac}, AC 侧 MAC: {ac_info.get('mac') or '未获取'}, 最终注销 MAC: {logout_mac}")
        log.info(f"注销身份 | AC 名称: {ac_name or '未获取/为空'}")

        _initial, _ = _audit_status(session, "0-注销前状态", mac_override, ip_override, sleep_before_check=0)

        full_url = build_logout_url(
            mac_override=mac_override,
            ip_override=ip_override,
            session=session,
            prefer_ac_info=True,
        )
        simple_url = LOGOUT_SERVER
        last_result: dict[str, Any] = {"result": -1, "msg": "未解析到注销响应"}
        effective_method = "未确认"

        encrypted_rounds = max(1, int(max_retry or 1))
        log.info(f"阶段执行 | 1-加密参数 logout | 开始，共 {encrypted_rounds} 次")
        for attempt in range(1, encrypted_rounds + 1):
            try:
                resp = session.get(full_url, timeout=DEFAULT_TIMEOUT, headers=HEADERS)
                result = _parse_jsonp(resp.text, "dr1002")
                if "result" not in result:
                    result = _parse_jsonp(resp.text)
                last_result = result
                log.info(f"阶段响应 | 1-加密参数 logout | 第 {attempt}/{encrypted_rounds} 次 | HTTP {resp.status_code} | {json.dumps(result, ensure_ascii=False)}")
            except requests.RequestException as exc:
                last_result = {"result": -1, "msg": str(exc)}
                log.error(f"阶段响应 | 1-加密参数 logout | 第 {attempt}/{encrypted_rounds} 次失败 | {exc}")
            time.sleep(0.5)

        verify, offline = _audit_status(session, "1-加密参数 logout 后", mac_override, ip_override)
        if offline:
            effective_method = "1-加密参数 logout"
            log.info(f"注销生效方式 | {effective_method}")
            log.info("========== 注销审计结束 ==========")
            return {**last_result, "effective_method": effective_method, "verify_status": verify}

        simple_total = max(0, int(simple_rounds))
        log.info(f"阶段执行 | 2-简单 logout | 开始，共 {simple_total} 次")
        for i in range(simple_total):
            try:
                resp = session.get(simple_url, timeout=DEFAULT_TIMEOUT, headers=HEADERS)
                log.info(f"阶段响应 | 2-简单 logout | 第 {i + 1}/{simple_total} 次 | HTTP {resp.status_code}")
            except requests.RequestException as exc:
                log.warning(f"阶段响应 | 2-简单 logout | 第 {i + 1}/{simple_total} 次失败 | {exc}")
            time.sleep(0.5)

        verify, offline = _audit_status(session, "2-简单 logout 后", mac_override, ip_override)
        if offline:
            effective_method = "2-简单 logout"
            log.info(f"注销生效方式 | {effective_method}")
            log.info("========== 注销审计结束 ==========")
            return {**last_result, "effective_method": effective_method, "verify_status": verify}

        if browser_fallback and browser_mode != "off":
            if browser_mode in {"auto", "headless"}:
                log.info(f"阶段执行 | 3A-headless 浏览器 logout | 开始，共最多 {browser_rounds} 次；无界面尝试")
                for i in range(max(1, int(browser_rounds))):
                    ok = open_url_headless(simple_url)
                    log.info(f"阶段响应 | 3A-headless 浏览器 logout | 第 {i + 1}/{browser_rounds} 次 | 启动结果={ok}")
                    verify, offline = _audit_status(
                        session,
                        f"3A-headless 浏览器 logout 第 {i + 1} 次后",
                        mac_override,
                        ip_override,
                        sleep_before_check=2.0,
                    )
                    if offline:
                        effective_method = f"3A-headless 浏览器 logout 第 {i + 1} 次"
                        log.info(f"注销生效方式 | {effective_method}")
                        log.info("========== 注销审计结束 ==========")
                        return {**last_result, "effective_method": effective_method, "verify_status": verify}
                if browser_mode == "headless" and not visible_fallback:
                    log.warning("headless 模式未确认离线，且 visible_fallback=False，不再打开可见浏览器。")

            should_visible = browser_mode == "visible" or (browser_mode == "auto" and visible_fallback) or (browser_mode == "headless" and visible_fallback)
            if should_visible:
                log.info(f"阶段执行 | 3B-可见浏览器 logout | 开始，共最多 {browser_rounds} 次；这是当前环境已验证有效兜底")
                for i in range(max(1, int(browser_rounds))):
                    ok = open_url_visible(simple_url)
                    log.info(f"阶段响应 | 3B-可见浏览器 logout | 已打开浏览器注销地址 第 {i + 1}/{browser_rounds} 次 | 启动结果={ok}")
                    verify, offline = _audit_status(
                        session,
                        f"3B-可见浏览器 logout 第 {i + 1} 次后",
                        mac_override,
                        ip_override,
                        sleep_before_check=2.0,
                    )
                    if offline:
                        effective_method = f"3B-可见浏览器 logout 第 {i + 1} 次"
                        log.info(f"注销生效方式 | {effective_method}")
                        log.info("========== 注销审计结束 ==========")
                        return {**last_result, "effective_method": effective_method, "verify_status": verify}
        else:
            log.warning("阶段跳过 | 3-浏览器 logout | 浏览器兜底已关闭；当前环境不推荐。")

        verify, offline = _audit_status(session, "4-最终复核", mac_override, ip_override, sleep_before_check=2.0)
        if offline:
            effective_method = "4-最终复核时已离线（具体生效阶段不确定）"
            log.info(f"注销生效方式 | {effective_method}")
            log.info("========== 注销审计结束 ==========")
            return {**last_result, "effective_method": effective_method, "verify_status": verify}

        if is_success(verify):
            uid = verify.get("uid", "")
            if not uid and isinstance(verify.get("list"), list) and verify["list"]:
                uid = verify["list"][0].get("user_account", "")
            log.warning(
                "注销审计结论 | 全部注销请求已发送，但最终仍在线"
                + (f"，账号: {uid}" if uid else "")
                + "。如果需要保证注销成功，请使用 logout_browser_mode=auto 或 visible。"
            )
        else:
            log.warning(f"注销审计结论 | 最终状态查询异常：{json.dumps(verify, ensure_ascii=False)}")

        log.info("========== 注销审计结束 ==========")
        return {**(last_result or {}), "effective_method": effective_method, "verify_status": verify}

def do_status(mac_override: Optional[str] = None, ip_override: Optional[str] = None) -> dict[str, Any]:
    """显示当前在线状态。"""
    with requests.Session() as session:
        session.trust_env = False  # 避免 HTTP_PROXY/HTTPS_PROXY 环境变量把 Portal 请求送进代理
        local_ip = get_local_ip(ip_override)
        mac = get_local_mac(local_ip=local_ip, mac_override=mac_override)
        log.info(f"本机 IP: {local_ip}, MAC: {mac}")

        if not check_server_alive(session):
            log.error("认证服务器不可达，请检查是否已连接校园网")
            return {"result": -1, "msg": "认证服务器不可达"}

        status = check_status(session=session, mac_override=mac_override, ip_override=ip_override)
        if is_success(status):
            uid = status.get("uid", "未知")
            if uid == "未知" and isinstance(status.get("list"), list) and status["list"]:
                uid = status["list"][0].get("user_account", "未知")
            log.info(f"状态: 在线  账号: {uid}")
        elif is_offline(status):
            log.info("状态: 不在线")
        else:
            log.warning(f"状态查询异常: {json.dumps(status, ensure_ascii=False)}")
        return status


def do_daemon(
    user_account: str,
    password: str,
    isp_code: str,
    interval: int = 30,
    max_retry: int = 3,
    retry_delay: int = 5,
    mac_override: Optional[str] = None,
    ip_override: Optional[str] = None,
) -> None:
    """守护模式：定期检查在线状态，掉线自动重连。"""
    isp_code = validate_isp(isp_code)
    log.info("=== 守护模式启动 ===")
    log.info(f"账号: {mask_account(user_account)}, 运营商: {isp_code}-{ISP_CODES[isp_code]}, 检查间隔: {interval} 秒")
    log.info("按 Ctrl+C 退出")

    fail_count = 0
    while True:
        try:
            with requests.Session() as session:
                session.trust_env = False  # 避免 HTTP_PROXY/HTTPS_PROXY 环境变量把 Portal 请求送进代理
                if not check_server_alive(session):
                    log.warning("认证服务器不可达，等待网络恢复...")
                    time.sleep(interval)
                    continue

                status = check_status(session=session, mac_override=mac_override, ip_override=ip_override)

            if is_success(status):
                uid = status.get("uid", "")
                if fail_count > 0:
                    log.info(f"连接已恢复，账号: {uid or '未知'}")
                fail_count = 0
                log.debug(f"在线: {uid or '未知'}")
            elif is_offline(status):
                log.warning("检测到掉线，正在重新登录...")
                result = do_login(
                    user_account,
                    password,
                    isp_code,
                    max_retry=max_retry,
                    retry_delay=retry_delay,
                    force=True,
                    mac_override=mac_override,
                    ip_override=ip_override,
                )
                if is_success(result):
                    log.info("重新登录成功")
                    fail_count = 0
                else:
                    fail_count += 1
                    log.error(f"重新登录失败（连续 {fail_count} 次）: {format_error(result)}")
            else:
                fail_count += 1
                log.warning(f"状态查询异常（连续 {fail_count} 次）: {json.dumps(status, ensure_ascii=False)}")

            wait = interval * min(fail_count + 1, 5) if fail_count > 0 else interval
            time.sleep(wait)

        except KeyboardInterrupt:
            log.info("守护模式已停止")
            break
        except Exception as exc:
            fail_count += 1
            log.error(f"守护循环异常：{exc}")
            time.sleep(interval * min(fail_count + 1, 5))


# ========== 主入口 ==========
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HUNNU / Dr.COM 校园网自动登录",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
运营商编码：
  0 = 校园网/学校默认（推荐，HUNNU 当前环境优先使用）
  1 = 移动
  2 = 联通运营商出口（只有学校要求时再用）
  3 = 电信

config.json 最小示例（推荐先用这个，适合公开脚本 + 本地私有配置）：
  {
    "user_account": "",
    "user_password": "",
    "isp_code": "0",
    "daemon_interval": 60,
    "max_retry": 3,
    "retry_delay": 5,
    "log_file": null
  }

config.json 高级示例（多账号/多电脑）：
  {
    "active_profile": "main",
    "profiles": {
      "main": {"user_account": "你的学号", "user_password": "你的密码", "isp_code": "0"},
      "unicom": {"user_account": "你的学号", "user_password": "你的密码", "isp_code": "2"}
    },
    "school_ssids": ["HUNNU", "HUNNU-5G"],
    "strict_school_ssid": false,
    "adapter_prefer": "auto",
    "logout_browser": true,
    "logout_browser_mode": "visible",
    "log_dir": "logs"
  }

示例：
  python campus_login_hunnu_public_v9.py --login
  python campus_login_hunnu_public_v9.py --status -v
  python campus_login_hunnu_public_v9.py --logout -v
  python campus_login_hunnu_public_v9.py --logout --login -v
  python campus_login_hunnu_public_v9.py --daemon --interval 30
  python campus_login_hunnu_public_v9.py --profile unicom --login
  python campus_login_hunnu_public_v9.py --list-adapters
  python campus_login_hunnu_public_v9.py --diagnose
  python campus_login_hunnu_public_v9.py --export-logs
  python campus_login_hunnu_public_v9.py --dry-run    # 注意：输出含加密敏感参数，禁止外传
        """,
    )
    parser.add_argument("-u", "--user", help="学号/账号")
    parser.add_argument("-p", "--password", help="密码")
    parser.add_argument("-i", "--isp", help="运营商编码 (0=校园网,1=移动,2=联通,3=电信)")
    parser.add_argument("--profile", help="选择 config.json 中的 profiles 配置档，便于多账号/多设备切换")
    parser.add_argument("--mac", help="手工指定 MAC，格式如 AA-BB-CC-DD-EE-FF；用于自动识别失败时")
    parser.add_argument("--ip", help="手工指定本机 IPv4；用于多网卡或自动识别失败时")
    parser.add_argument("--adapter", choices=["auto", "wifi", "ethernet"], help="多网卡选择偏好：auto/wifi/ethernet；有线优先用 ethernet")
    parser.add_argument("--list-adapters", action="store_true", help="列出 Windows 适配器、IPv4、MAC，便于确认脚本选错了哪块网卡")
    parser.add_argument("--status", action="store_true", help="查看当前在线状态")
    parser.add_argument("--logout", action="store_true", help="注销当前登录")
    parser.add_argument("--logout-browser", action="store_true", help="注销时额外用浏览器打开 /logout；v5 默认已开启，保留此参数用于显式指定")
    parser.add_argument("--no-logout-browser", action="store_true", help="注销时不打开浏览器，仅发送脚本 HTTP 注销请求；不推荐，因为当前环境实测无效")
    parser.add_argument("--logout-simple-rounds", type=int, default=None, help="注销时不带参数 /logout 的重复次数；默认读取配置或 3")
    parser.add_argument("--logout-browser-mode", choices=["auto", "headless", "visible", "off"], help="浏览器注销模式：auto=headless优先失败再可见；headless=无界面；visible=可见浏览器；off=关闭")
    parser.add_argument("--logout-browser-rounds", type=int, default=None, help="浏览器兜底打开次数；默认读取配置或 3")
    parser.add_argument("--no-visible-browser-fallback", action="store_true", help="headless/auto 失败时不再打开可见浏览器；不保证注销成功")
    parser.add_argument("--login", action="store_true", help="注销后重新登录（配合 --logout 使用）")
    parser.add_argument("--daemon", action="store_true", help="守护模式，掉线自动重连")
    parser.add_argument("--interval", type=int, default=None, help="守护模式检查间隔秒数；默认读取配置或 60")
    parser.add_argument("--max-retry", type=int, default=None, help="最大重试次数；默认读取配置或 3")
    parser.add_argument("--retry-delay", type=int, default=None, help="重试间隔秒数；默认读取配置或 5")
    parser.add_argument("--force", action="store_true", help="强制登录，跳过在线检查")
    parser.add_argument("--dry-run", action="store_true", help="仅构造 URL，不发送请求；注意 URL 含加密后的账号密码")
    parser.add_argument("--decrypt", metavar="BASE64", help="解密指定 Base64 密文（仅调试本人请求）")
    parser.add_argument("--config", metavar="FILE", help="配置文件路径")
    parser.add_argument("--log-file", metavar="FILE", help="日志文件路径")
    parser.add_argument("--log-dir", metavar="DIR", help="日志目录；未指定 log_file 时自动写入该目录")
    parser.add_argument("--diagnose", action="store_true", help="执行网络/SSID/网卡/状态诊断，并导出脱敏日志包")
    parser.add_argument("--export-logs", action="store_true", help="只导出脱敏日志与诊断 ZIP 包，不执行登录/注销")
    parser.add_argument("-v", "--verbose", action="store_true", help="输出 DEBUG 日志")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    cfg = apply_profile_config(cfg, args.profile)

    log_dir = Path(args.log_dir or cfg.get("log_dir") or "logs").expanduser()
    log_dir.mkdir(parents=True, exist_ok=True)
    auto_log_file = log_dir / f"campus_login_{datetime.datetime.now().strftime('%Y%m%d')}.log"
    log_file = args.log_file or cfg.get("log_file") or str(auto_log_file)
    setup_logging(log_file=log_file, verbose=args.verbose)

    if cfg.get("_loaded_config_file"):
        log.info(f"已加载配置文件: {cfg['_loaded_config_file']}")
    if cfg.get("_active_profile"):
        log.info(f"当前配置档 profile: {cfg['_active_profile']}")

    user = args.user or cfg.get("user_account", "")
    password = args.password or cfg.get("user_password", "")
    isp = validate_isp(args.isp or cfg.get("isp_code", "0"))
    mac = args.mac or cfg.get("mac")
    ip = args.ip or cfg.get("ip")

    global ADAPTER_PREFER
    ADAPTER_PREFER = validate_adapter_prefer(args.adapter or cfg.get("adapter_prefer", "auto"))
    log.debug(f"网卡选择偏好 adapter_prefer={ADAPTER_PREFER}")
    log_network_context(cfg)

    interval = int_from_cli_or_cfg(args.interval, cfg, "daemon_interval", 60)
    max_retry = int_from_cli_or_cfg(args.max_retry, cfg, "max_retry", 3)
    retry_delay = int_from_cli_or_cfg(args.retry_delay, cfg, "retry_delay", 5)
    logout_simple_rounds = int_from_cli_or_cfg(args.logout_simple_rounds, cfg, "logout_simple_rounds", 3)
    logout_browser_rounds = int_from_cli_or_cfg(args.logout_browser_rounds, cfg, "logout_browser_rounds", 3)
    cfg_logout_browser = cfg.get("logout_browser", True)
    logout_browser = parse_bool(cfg_logout_browser, True) or bool(args.logout_browser)
    if args.no_logout_browser:
        logout_browser = False
    logout_browser_mode = str(args.logout_browser_mode or cfg.get("logout_browser_mode", "auto")).strip().lower()
    visible_fallback = parse_bool(cfg.get("visible_browser_fallback", True), True)
    if args.no_visible_browser_fallback:
        visible_fallback = False

    if args.decrypt:
        try:
            print(decrypt_params(args.decrypt, AES_KEY))
            return 0
        except Exception as exc:
            log.error(f"解密失败：{exc}")
            return 2

    if args.export_logs:
        bundle = export_debug_bundle(cfg, log_file=log_file, out_dir=str(log_dir))
        log.info(f"已导出脱敏日志包: {bundle}")
        print(bundle)
        return 0

    if args.diagnose:
        log.info("========== 诊断开始 ==========")
        log.info(f"Python: {sys.version}")
        log.info(f"Platform: {platform.platform()}")
        log.info(f"当前 SSID: {get_current_ssid() or '未检测到/可能有线'}")
        adapters = list_windows_adapters()
        for idx, item in enumerate(adapters, 1):
            log.info(f"适配器[{idx}] name={item['name']} type={item['type']} excluded={item['excluded']} ipv4={item['ipv4']} mac={item['mac']}")
        do_status(mac_override=mac, ip_override=ip)
        bundle = export_debug_bundle(cfg, log_file=log_file, out_dir=str(log_dir))
        log.info(f"已导出脱敏诊断包: {bundle}")
        log.info("========== 诊断结束 ==========")
        print(bundle)
        return 0

    if args.list_adapters:
        adapters = list_windows_adapters()
        if not adapters:
            return 1
        print("\nWindows 适配器识别结果：")
        for idx, item in enumerate(adapters, 1):
            flag = "跳过" if item["excluded"] else "可用"
            ips = ", ".join(item["ipv4"]) if item["ipv4"] else "无"
            print(f"[{idx}] {item['name']} | type={item['type']} | {flag}")
            print(f"    IPv4: {ips}")
            print(f"    MAC : {item['mac'] or '无'}")
        print("\n使用建议：有线网卡请加 --adapter ethernet；无线网卡请加 --adapter wifi；仍不准时用 --ip 和 --mac 强制指定。")
        return 0

    if args.status:
        do_status(mac_override=mac, ip_override=ip)
        return 0

    if args.login and not args.logout:
        if not user or not password:
            log.error("登录需要账号和密码：-u 学号 -p 密码，或在 config.json / 环境变量/profile 中配置")
            return 1
        result = do_login(
            user,
            password,
            isp,
            max_retry=max_retry,
            retry_delay=retry_delay,
            force=args.force,
            mac_override=mac,
            ip_override=ip,
        )
        return 0 if is_success(result) else 1

    if args.logout:
        do_logout(
            max_retry=max_retry,
            mac_override=mac,
            ip_override=ip,
            browser_fallback=logout_browser,
            simple_rounds=logout_simple_rounds,
            browser_mode=logout_browser_mode,
            browser_rounds=logout_browser_rounds,
            visible_fallback=visible_fallback,
        )
        if args.login:
            if not user or not password:
                log.error("重新登录需要账号和密码：-u 学号 -p 密码，或在 config.json / 环境变量中配置")
                return 1
            log.info("--- 开始重新登录 ---")
            time.sleep(2)
            result = do_login(
                user,
                password,
                isp,
                max_retry=max_retry,
                retry_delay=retry_delay,
                force=True,
                mac_override=mac,
                ip_override=ip,
            )
            return 0 if is_success(result) else 1
        return 0

    if not user or not password:
        log.error("请指定账号和密码：-u 学号 -p 密码，或在 config.json / 环境变量中配置")
        return 1

    if args.dry_run:
        # dry-run 便于研究请求结构，但 URL 中的 params 可以被本脚本 AES_KEY 解密，
        # 因此它等同于敏感信息，禁止提交到 Git、截图或发给他人。
        log.warning("dry-run 输出的完整 URL 含加密登录信息，请勿外传")
        url = build_login_url(user, password, isp, mac_override=mac, ip_override=ip)
        print(url)
        return 0

    if args.daemon:
        do_daemon(
            user,
            password,
            isp,
            interval=interval,
            max_retry=max_retry,
            retry_delay=retry_delay,
            mac_override=mac,
            ip_override=ip,
        )
        return 0

    result = do_login(
        user,
        password,
        isp,
        max_retry=max_retry,
        retry_delay=retry_delay,
        force=args.force,
        mac_override=mac,
        ip_override=ip,
    )
    return 0 if is_success(result) else 1


if __name__ == "__main__":
    raise SystemExit(main())
