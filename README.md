<div align="center">

<img src="ICON_256.PNG" width="120" height="120" alt="ClamSentinel Logo">

# ClamSentinel · 哨兵杀毒

**飞牛 fnOS（ARM）上的原生轻量病毒扫描中心 · 不依赖 Docker**

[![Stars](https://img.shields.io/github/stars/gulugulupao/clamsentinel?color=yellow)](https://github.com/gulugulupao/clamsentinel/stargazers)
[![Downloads](https://img.shields.io/github/downloads/gulugulupao/clamsentinel/total?color=green)](https://github.com/gulugulupao/clamsentinel/releases)

[![License](https://img.shields.io/badge/License-MIT%20%2B%20Protection-green.svg)](LICENSE.txt)
![Platform](https://img.shields.io/badge/Platform-fnOS%20ARM%20(RK35XX%2FA311D%2FS905X4)-blue.svg)
![Version](https://img.shields.io/badge/Version-V1.5-orange.svg)
![Engine](https://img.shields.io/badge/Engine-ClamAV%201.4.3-brightgreen.svg)

**作者：[gulugulupao](https://github.com/gulugulupao) · 微信公众号：很多问题的小明同学**

</div>

---

## 📑 目录

- [项目简介](#intro)
- [功能特性](#features)
- [系统要求](#requirements)
- [安装](#install)
- [使用说明](#usage)
- [仓库结构](#structure)
- [技术架构](#architecture)
- [常见问题](#faq)
- [免责声明](#disclaimer)
- [许可证](#license)

---

<a id="intro"></a>

## 📌 项目简介

**ClamSentinel** 是一款运行在飞牛 fnOS（ARM 版）上的病毒扫描应用，为 **RK35XX（RK3566 / RK3568 / RK3399 等）与晶晨 A311D** 设备深度调优。

1. **ClamAV 权威病毒库**：复用国际主流开源杀毒引擎 ClamAV 的病毒库，安全可靠，由思科 Talos 团队持续维护。
2. **智能睡眠机制**：Sentinel 守护进程空闲时自动停止 Web 与 clamd 进程，实测可释放约 **1.05GB 内存**（仅保留约 30MB），随叫随醒。
3. **RK35XX / A311D / 2GB 专项调优**：为小运存设备深度优化，内存占用控制到极低。
4. **免 Docker 独立部署**：不依赖容器环境，减少一层开销，资源占用更干净。

> ✅ **已实测适配芯片**：瑞芯微 RK35XX 系列（RK3566 / RK3568 / RK3399）与晶晨 A311D（网心云 OES 等设备）。

<a id="features"></a>

## ✨ 功能特性

- 🗂️ **多根扫描**：扫描目录 / 整个数据卷 / 用户家目录 / 团队空间 / 外接存储
- 🔬 **单文件或整目录扫描**：Web 界面浏览目录，随时发起扫描
- ⏸️ **暂停 / 继续**：扫描中随时暂停，不丢失已完成进度
- 🛡️ **威胁隔离**：检出文件可一键隔离，支持恢复或彻底删除
- 🔄 **病毒库自动更新**：后台 freshclam 每 2 小时自动检查更新；首次下载失败会自动退避重试（20s→900s，最多 8 次）
- 🛡️ **就绪判定收紧**：必须 `main.cvd` + `daily.cvd` 齐全才判定"病毒库已就绪"，避免只下了部分库就误报可用
- 💤 **智能休眠**：10 分钟无活动自动停 web+clamd，释放约 1.05GB 内存
- 📊 **扫描记录统计**：历史扫描状态清晰可查

<a id="requirements"></a>

## 🖥️ 系统要求

| 项目 | 要求 |
| --- | --- |
| 系统 | 飞牛 fnOS ARM 版（0.9.25+，推荐 1.2.x）|
| 芯片 | 瑞芯微 **RK35XX**（RK3566 / RK3568 / RK3399 等）、晶晨 **A311D**、其他 ARM64 设备 |
| 内存 | 2GB 及以上（2GB 经专项调优可用）|
| 存储 | 约 300MB（运行时 + 病毒库）|

<a id="install"></a>

## 📦 安装

### 方式一：fnOS 应用中心手动安装（推荐）

1. 从 **GitHub Releases** 或公众号获取 fpk 安装包（本仓库源码不含运行时/引擎二进制，无法直接编译运行）
2. 飞牛 OS → **应用中心 → 手动安装** → 选择 fpk 文件
3. 浏览器访问 `http://NAS-IP:8080`
4. 首次进入完成初始化（创建并设置管理员账号）

### 方式二：获取预编译 fpk

预编译安装包体积约 60MB（内置 Node.js 18 运行时 + ClamAV 1.4.3 引擎 + 病毒库），**仅通过作者官方渠道发布**：

- GitHub [Releases](https://github.com/gulugulupao/clamsentinel/releases)
- 微信公众号：**很多问题的小明同学**

<a id="usage"></a>

## 🔧 使用说明

| 功能 | 说明 |
| --- | --- |
| Web 管理界面 | `http://NAS-IP:8080`（默认端口）|
| 登录 | 用户名默认 `admin`，密码为初始化时自定义的 8-16 位密码 |
| 修改密码 | 登录后 → 系统设置 → 修改密码 |
| 数据目录 | `/vol1/@appdata/clamsentinel/` |
| 卸载 | 应用中心卸载即可 |

> ⚠️ 首次安装后请尽快修改默认密码。

<a id="structure"></a>

## 📁 仓库结构

```
clamsentinel/
├── app/                    # 应用主体
│   ├── sentinel.js         # 哨兵守护进程（内存管理核心）
│   ├── web/                # Web 后端 + 前端（原生 JS，无框架）
│   │   ├── server.js
│   │   └── public/         # 前端页面
│   └── ui/                 # fnOS 桌面图标资源
├── cmd/                    # fnOS 生命周期脚本
│   ├── main                # start / stop / status / reset-password
│   ├── install_init        # 安装初始化
│   └── uninstall_callback  # 卸载清理
├── config/                 # fnOS 权限与资源声明
├── wizard/                 # 安装向导
├── manifest                # fpk 元数据
├── ICON.PNG / ICON_256.PNG # 应用图标
└── LICENSE.txt             # 许可证
```

<a id="architecture"></a>

## ⚙️ 技术架构

```
┌──────────────────────────────────────────────────────┐
│                   ClamSentinel                        │
│                                                      │
│  ┌─────────────┐      ┌──────────────────────────┐  │
│  │  sentinel.js │──────│  web/server.js (:8082)   │  │
│  │  (:8080)    │ 按需  │  管理界面 / API          │  │
│  │  守护/唤醒   │ 唤醒  └───────────┬──────────────┘  │
│  └─────────────┘              │ 按需启动            │
│        │ 空闲 10 分钟          ▼                    │
│        │ 停 web+clamd     ┌──────────────────┐      │
│        │ 释放 ~1GB RAM    │  clamd (:3310)    │      │
│        └──────────────────│  病毒扫描引擎     │      │
│                           └──────────────────┘      │
└──────────────────────────────────────────────────────┘
```

<a id="faq"></a>

## 🛠️ 常见问题

**Q: 为什么安装会卡在 45%？**
A: fpk 内置约 160MB 运行时，fnOS 应用中心解压需要几分钟，请耐心等待（正常 1-3 分钟）。

**Q: 提示"设置目录权限失败 (10234)"？**
A: 这是 fnOS 1.2 系在某类设备上的已知兼容问题，与具体应用无关；可等待 fnOS 更新或参考社区方案。

**Q: 杀毒能力如何？**
A: 病毒库与签名规则完全来自 ClamAV（思科 Talos 维护），与全球主流杀软同源。

**Q: 病毒库多久更新一次？**
A: 后台每 2 小时自动检查更新（freshclam），无需手动操作。

<a id="disclaimer"></a>

## 📝 免责声明

ClamSentinel 应用属于社区提供的额外辅助安全方案，**与飞牛官方无关，不属于官方安全体系，亦非任何硬件厂商的官方产品**。

本应用不提供任何形式的明示或默示担保；其病毒扫描能力完全取决于 ClamAV（思科 Talos 团队维护）的病毒库与签名规则、以及用户自行配置的可疑文件处理方式。在飞牛 OS 上安装并使用本应用时，出现的任何性能、表现、兼容性及其他问题，均应由用户自行承担；如本应用与您的硬件/系统环境存在不兼容或冲突，请及时卸载以恢复原状。

### 技术支持范围

- ✅ 本应用**仅在作者官方渠道**发布：本 GitHub 仓库（源码 + Releases）与微信公众号「很多问题的小明同学」
- ✅ 作者仅对本仓库发布的最新版本提供社区级支持（GitHub Issues）
- ❌ 作者**不对**第三方转载、整合、修改后的版本提供任何支持
- ❌ 作者**不承诺**本应用与任何特定 fnOS 版本、特定硬件 100% 兼容；不同固件/设备环境可能存在差异，请以实际测试为准
- ❌ 请勿将本应用用于处理重要程度超过其可承受范围的场景；关键数据请始终保留独立备份

<a id="license"></a>

## 📄 许可证

本仓库源码采用 **MIT License + 附加保护条款** 授权，详见 [LICENSE.txt](LICENSE.txt)。

- ✅ 允许：学习、研究、个人使用、修改后以学习交流为目的发布
- ❌ 禁止：商业用途、去除署名、以原项目名义发布修改版

> ClamAV 引擎受 GPLv2 许可约束，仅以二进制形式随 fpk 分发，不包含在本仓库源码内。

---

<div align="center">

**⭐ 如果这个项目对你有帮助，欢迎 Star 支持！**

问题反馈：GitHub [Issues](https://github.com/gulugulupao/clamsentinel/issues) · 微信公众号：**很多问题的小明同学**

</div>
