# 校园网连接守护

校园网连接守护是在 **[demo133/campusnet](https://github.com/demo133/campusnet)** 基础上修改的 Windows 桌面应用。原作者为 **[demo133](https://github.com/demo133)** 和 campusnet contributors，本仓库保留原项目的 MIT 许可证和版权声明。

本版本主要调整了校园网认证、Windows 登录自启、托盘菜单、重连策略和窗口交互，并提供中文安装包。完整署名和组件说明见 [AUTHORS.md](AUTHORS.md)。

## 下载与安装

**[下载 Windows 安装包](https://github.com/A3697/campusnet-guardian/raw/refs/heads/main/downloads/CampusNetGuardian-20261104.3-Setup.exe)** · [SHA-256 校验值](downloads/SHA256.txt)

- 版本：`0.1.2+desktop.20261104.3`
- 系统：Windows 10 / 11，64 位
- 默认安装目录：`D:\campusnet`
- 安装包内置运行环境，不需要另行安装 Python。

本版本针对作者学校的登录进行了适配，尚未验证其他学校的门户。

1. 双击安装包，按中文向导完成安装。安装目录可以修改。
2. 打开应用，填写自己的上网账号和密码，选择运营商。
3. 插好校园网线，或连接校园 Wi-Fi，然后点击“保存并连接”。
4. 如需开机后自动登录校园网，保留“登录 Windows 后自动运行”选项。

安装包不包含个人账号、密码或运行日志。已有版本可以安装到原目录，原有账号和重连设置会保留。安装前请先保存正在编辑的设置。

## 主要功能

- 登录 Windows 后启动托盘和后台，立即检查校园网会话并尝试认证。
- 定时检查网络，掉线后等待一段时间再尝试重连。
- 暂停或恢复自动重连，按小时和分钟分别设置自动重连时段，支持多个时段和跨午夜时段。
- 手动重新认证、检测网络、查看运行日志。
- 主窗口、账号设置和重连策略页面支持滚动；滚轮经过数字输入框时不会改变数值。
- 关闭窗口后保留托盘图标，再次打开快捷方式会回到同一个窗口。

默认每 5 分钟检查一次，发现掉线后等待 60 秒再确认并登录。这些设置可以在“重连策略”中调整。暂停和时段限制也适用于登录 Windows 时的自动认证。

密码默认显示在界面中，可取消“显示密码”隐藏。密码保存在当前 Windows 用户的凭据管理器中。

## 配置与卸载

配置和日志位于安装目录的 `profile` 文件夹：

| 文件 | 内容 |
| --- | --- |
| `config.json` | 账号、门户、运营商和重连设置 |
| `policy_state.json` | 暂停和恢复状态 |
| `watch.log` | 后台检查及认证记录 |

可以在 Windows“已安装的应用”中卸载，也可以运行安装目录中的 `unins000.exe`。卸载会关闭该目录中的应用和后台，删除程序文件、快捷方式及属于该目录的自启项。

卸载默认保留 `profile` 文件夹和 Windows 凭据，重新安装后可以继续使用原配置。

## 验证情况

本版本的主程序已通过 326 项自动化测试；另有 1 项仅适用于 POSIX 文件权限的测试在 Windows 上跳过。安装包另行验证了首次安装、中文及带空格的路径、界面启动、覆盖安装、配置保留、快捷方式、自启项登记和卸载。

本次打包使用已经验收的主程序，未修改认证代码。本次安装包验收未重新注销真实校园网，也未进行 Windows 重启测试。安装包尚未使用商业代码签名证书签名。

## 从源码构建

使用 Windows x64、Python 3.14 和 PowerShell 7，在仓库根目录执行：

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean CampusNetGuardian.spec
```

主程序生成在 `dist\校园网连接守护.exe`。

安装包使用 [Inno Setup 7](https://jrsoftware.org/isdl.php) 构建。安装编译器后，执行：

```powershell
.\packaging\build-installer.ps1 -Compiler 'C:\Program Files\Inno Setup 7\ISCC.exe'
```

安装包生成在 `packaging\output`。构建脚本只使用仓库中的空白账号模板，不会复制电脑上的个人配置。

运行测试：

```powershell
.\.venv\Scripts\python.exe -m pip install pytest==9.2.0
.\.venv\Scripts\python.exe -m pytest -q
```

## 原项目与许可证

- 原作者：[demo133](https://github.com/demo133)
- 原项目：[demo133/campusnet](https://github.com/demo133/campusnet)
- 本分支：[A3697/campusnet-guardian](https://github.com/A3697/campusnet-guardian)
- 应用代码：[MIT License](LICENSE)

托盘组件 pystray 采用 LGPL-3.0；它的源码与应用源码一同附在安装目录的“源码与构建.zip”中。各组件的完整许可证位于 `packaging/payload/licenses`。原项目及原作者不对本定制版本提供保证。
