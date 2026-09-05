# 安全政策（Security Policy）

感谢你关注 **ClamSentinel** 的安全可靠。本文件说明如何报告安全漏洞，以及维护者的响应承诺。

## 支持的版本

| 版本 | 技术支持 |
| --- | --- |
| V1.x（最新 Release） | ✅ 受支持 |
| 更早版本 | ❌ 不再支持，请升级 |

建议始终使用最新 Release 发布的安装包与病毒库。飞牛 fnOS 应用中心历史安装的旧版，安全性不受保障。

## 报告安全漏洞

如果你发现安全相关的问题，请 **不要** 通过公开 Issue / Discussions / 群聊直接透露细节，以免被利用。

推荐渠道（按优先级）：

1. **GitHub Security Advisory（首选）**
   在本仓库 `Issues → New Issue → 创建一个安全咨询（Security advisory）`，或：
   `https://github.com/gulugulupao/clamsentinel/security/advisories/new`
   通过该渠道的漏洞披露将对漏洞细节保密，且可作为 CVE 的申请来源。

2. **邮件（备选）**
   如无法使用上述渠道，可通过作者在 README 公布的联系方式反馈，注明「安全漏洞 / Security」。

**请在报告时尽量提供：**

- 受影响的版本（fpk Release 版本 / 源码 commit）
- 漏洞类型与可能的影响范围
- 最小复现步骤或 PoC（可在私有渠道提供）
- 你的环境：飞牛 fnOS 版本、设备芯片、内存、ClamAV 病毒库版本

## 响应承诺

- 我会在收到报告后的 **7 天内** 确认并评估。
- 确认有效后，我会在 **合理时间内** 提供修复，并同步更新 README / Release 说明。
- 在修复落地前，敏感细节不会公开。

## 安全使用建议

- 仅从官方渠道（本 GitHub Releases / 作者公众号）下载 fpk 安装包，核对不会来历不明的安装包。
- 首次进入后立即设置管理员密码，并定期更换安装密钥。
- 保持 ClamAV 病毒库自动更新开启，扫描结果异常时及时隔离并清除威胁。
- ClamSentinel 为社区辅助安全方案，不等同于官方安全体系，请结合实际场景评估风险。