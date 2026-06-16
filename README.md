# HUNNU / Dr.COM 校园网自动登录脚本

> 面向湖南师范大学 HUNNU / HUNNU-5G / 校园有线网络的 Dr.COM Portal 登录、注销、状态查询、守护重连与诊断导出脚本。

本项目用于**本人账号、本人设备、被授权校园网环境**。请勿用于未授权网络、他人账号或绕过学校网络管理制度。

## 1. 功能概览

- 登录校园网 Portal。
- 查询当前在线状态。
- 注销当前设备会话。
- 掉线守护重连。
- 自动排除 Clash / Mihomo TUN、TAP、虚拟机、蓝牙等非真实校园网网卡。
- 支持 HUNNU、HUNNU-5G SSID 检测。
- 支持有线网卡、无线网卡、多网卡自动选择。
- 支持单账号最小配置，也支持 profiles 多账号切换。
- 支持详细日志和脱敏诊断包导出，便于分析 bug。
- 默认采用实测稳定的“可见浏览器注销”策略。

## 2. 当前学校环境建议

根据实测，学校默认环境优先使用：

```json
"isp_code": "0"
```

即“校园网/学校默认”。即使状态查询结果显示账号后缀类似 `@unicom`，登录时通常仍然先使用 `0`。只有学校明确要求走联通运营商出口时，再尝试：

```json
"isp_code": "2"
```

学校 Wi-Fi 名称：

```json
["HUNNU", "HUNNU-5G"]
```

如果当前使用有线网络，不建议开启严格 SSID 检查。

## 3. 安装依赖

建议 Python 3.9 及以上：

```powershell
pip install -r requirements.txt
```

或直接安装：

```powershell
pip install requests cryptography
```

## 4. 最小配置

复制配置模板：

```powershell
copy config.example.json config.json
```

然后编辑 `config.json`：

```json
{
  "user_account": "你的学号",
  "user_password": "你的密码",
  "isp_code": "0",
  "daemon_interval": 60,
  "max_retry": 3,
  "retry_delay": 5,
  "log_file": null
}
```

字段说明：

| 字段 | 说明 | 推荐值 |
|---|---|---|
| `user_account` | 学号/账号 | 本地填写，禁止上传 Git |
| `user_password` | 密码 | 本地填写，禁止上传 Git |
| `isp_code` | 运营商编码 | 学校默认先用 `0` |
| `daemon_interval` | 守护模式检查间隔 | `60` 秒 |
| `max_retry` | 最大重试次数 | `3` |
| `retry_delay` | 重试间隔 | `5` 秒 |
| `log_file` | 指定单个日志文件 | 可为 `null` |

## 5. 高级配置：多账号 profiles

复制：

```powershell
copy config.advanced.example.json config.json
```

示例：

```json
{
  "active_profile": "main",
  "profiles": {
    "main": {
      "user_account": "你的学号",
      "user_password": "你的密码",
      "isp_code": "0"
    },
    "unicom": {
      "user_account": "你的学号或运营商账号",
      "user_password": "你的密码",
      "isp_code": "2"
    }
  },
  "school_ssids": ["HUNNU", "HUNNU-5G"],
  "strict_school_ssid": false,
  "adapter_prefer": "auto",
  "logout_browser": true,
  "logout_browser_mode": "visible",
  "log_dir": "logs"
}
```

使用指定 profile：

```powershell
python campus_login.py --profile main --login
python campus_login.py --profile unicom --login
```

## 6. 常用命令

查看状态：

```powershell
python campus_login.py --status -v
```

登录：

```powershell
python campus_login.py --login -v
```

强制登录：

```powershell
python campus_login.py --login --force -v
```

注销：

```powershell
python campus_login.py --logout -v
```

注销后重新登录：

```powershell
python campus_login.py --logout --login -v
```

守护模式：

```powershell
python campus_login.py --daemon
```

列出网卡：

```powershell
python campus_login.py --list-adapters
```

导出诊断包：

```powershell
python campus_login.py --diagnose
```

## 7. 有线 / 无线 / Clash TUN 说明

如果开启 Clash / Mihomo TUN，系统可能出现 `198.18.0.1` 这样的虚拟地址。该地址不能提交给校园网 Portal。脚本会自动排除：

- `198.18.0.0/15`
- Clash / Mihomo / TUN / TAP / Wintun
- VMware / VirtualBox / Hyper-V / vEthernet
- 蓝牙网卡
- 已断开连接的无线虚拟网卡

如自动识别仍不准确，可以手工指定：

```powershell
python campus_login.py --status --ip 10.x.x.x --mac AA-BB-CC-DD-EE-FF
```

或指定网卡偏好：

```powershell
python campus_login.py --status --adapter ethernet
python campus_login.py --status --adapter wifi
```

## 8. 注销策略说明

当前学校环境实测：

- 加密参数 logout 可能返回 `Radius注销成功`，但不一定真正下线。
- 简单 HTTP `/logout` 不一定真正下线。
- Headless 无界面浏览器在当前环境下不一定有效。
- 可见浏览器打开 `/logout` 通常最稳定。

因此默认配置推荐：

```json
"logout_browser": true,
"logout_browser_mode": "visible",
"logout_browser_rounds": 3
```

如果想测试无界面：

```powershell
python campus_login.py --logout --logout-browser-mode headless --no-visible-browser-fallback -v
```

但不保证成功。

## 9. 日志与诊断包

脚本支持两种日志方式：

1. `log_file`: 指定单个日志文件。
2. `log_dir`: 自动按日期写入日志目录。

推荐：

```json
"log_dir": "logs",
"log_file": null
```

导出诊断包：

```powershell
python campus_login.py --diagnose
```

诊断包通常包含：

- `summary.json`
- `config.redacted.json`
- `adapters.json`
- `ipconfig_all.txt`
- `route_print.txt`
- `netsh_wlan_interfaces.txt`
- 脱敏后的日志文件

导出的配置和日志会尽量脱敏，但上传前仍建议人工复查。

## 10. Git 上传注意事项

禁止上传：

- `config.json`
- `logs/`
- `debug_bundles/`
- `*.log`
- 任何真实账号、真实密码、手机号、Cookie、Token
- `--dry-run` 输出的 URL

可以上传：

- `campus_login.py`
- `config.example.json`
- `config.advanced.example.json`
- `README.md`
- `requirements.txt`
- `.gitignore`
- `SECURITY_GIT_CHECK.md`

上传前检查：

```powershell
findstr /S /I "password user_password 你的真实学号 你的真实密码" *.*
```

或使用 Git 检查即将提交的文件：

```powershell
git status
git diff --cached
```

## 11. 手机端说明

Windows 电脑是主要适配目标。

手机端分情况：

- iPhone：通常不能直接运行此 Python 脚本，建议使用浏览器认证。
- Android：可尝试 Termux，但网卡、MAC、浏览器注销行为可能与 Windows 不同，不保证完全兼容。
- 手机连接 HUNNU / HUNNU-5G 时建议关闭“随机 MAC / 私有地址”，否则学校认证可能把它识别为不同设备。

## 12. 免责声明

本项目仅供学习、个人设备自动化和授权校园网环境使用。使用者需遵守学校网络管理规定。作者不对滥用、账号泄露、违反学校制度等后果负责。
