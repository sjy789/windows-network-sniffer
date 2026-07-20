# NetScope — Windows 网络嗅探器

NetScope 是一个面向计算机网络课程设计的 Windows 桌面网络分析工具。它使用
Npcap 与 Scapy 获取实时或离线数据包，并由项目代码从原始字节手工解析协议字段，
通过 PyQt6 图形界面呈现数据包、协议结构、流量趋势、双向会话和异常事件。

项目重点不是复刻 Wireshark 的全部能力，而是完整展示网络嗅探器从
**网卡发现 → 数据捕获 → 协议解析 → 分片重组 → 会话分析 → 可视化与导出**
的核心实现过程。

> 仅可在本人设备、明确授权设备或隔离实验网络中使用。

## 项目亮点

- **核心字段手工解析**：Scapy 负责抓包和文件读写，Ethernet、ARP、IPv4、IPv6、
  ICMP、ICMPv6、TCP、UDP 等字段由项目代码直接从原始字节解析。
- **IPv4 分片重组**：支持乱序、重复片、缺片超时、重叠冲突检测、缓存限制和完整重组。
- **IPv6 深度解析**：支持扩展首部链、ICMPv6、邻居发现、MLD/MLDv2 和 IPv6 TCP/UDP。
- **实时与离线统一分析**：既能监听 Npcap 网卡，也能后台加载 PCAP/PCAPNG 文件，
  两种来源复用同一套解析、统计、会话与异常检测流水线。
- **会话与载荷观察**：按双向端点聚合 TCP/UDP 会话，整理 TCP Sequence Number，
  文本自动识别 UTF-8/GB18030，二进制或加密载荷自动切换为 Hex/ASCII。
- **被动异常检测**：检测端口扫描、SYN 洪泛、DNS 异常、ARP 地址冲突、异常分片和 TCP Reset。
- **NetScope 可视化界面**：提供实时抓包、流量态势、会话分析、异常检测、协议树和原始数据视图。

## 功能总览

| 模块 | 已实现能力 |
|---|---|
| 网卡管理 | 枚举 Npcap 可捕获接口，筛选无效 Windows 组件，支持物理、虚拟与回环网卡 |
| 实时捕获 | `AsyncSniffer` 后台抓包、有界队列、批量刷新、停止超时与异常恢复 |
| 离线分析 | 后台读取 PCAP/PCAPNG、进度显示、取消加载、原始 IPv4/IPv6 与 Ethernet 链路类型 |
| 链路层 | Ethernet II、双层 802.1Q/802.1ad VLAN、ARP、DLT_NULL 回环 |
| IPv4 | 固定/可变首部、Options、长度校验、分片识别与完整重组 |
| IPv6 | 固定首部、Hop-by-Hop、Routing、Fragment、Destination Options、AH、ESP |
| ICMP/ICMPv6 | Echo、常见错误、Router/Neighbor Discovery、MLD/MLDv2、ND 选项 |
| TCP/UDP | 端口、序列号、确认号、标志、窗口、Options、长度与载荷 |
| 应用层元数据 | DNS 查询、HTTP 首部、TLS 握手/SNI/ALPN、DHCP 选项；QUIC 常见端口识别 |
| 数据查看 | 摘要表、协议字段树、Hex/ASCII、协议颜色标签、滚动历史 |
| 过滤 | BPF 抓取过滤；协议、IP、方向、端口组合显示过滤 |
| 流量态势 | 60 秒包速率/字节速率曲线、协议分布、活跃会话和告警数量 |
| 会话分析 | TCP/UDP 双向会话、方向包数/字节数、持续时间、TCP 状态、Follow TCP Stream |
| 异常检测 | 端口扫描、SYN 洪泛、DNS 查询突增/长域名、ARP 冲突、异常分片、TCP Reset |
| 保存与导出 | 保存真实捕获包为 PCAP，导出 UTF-8-BOM CSV，并防止 CSV 公式注入 |

## 系统架构

```text
              ┌──────────────────────────────┐
              │ 实时 Npcap / 离线 PCAP·PCAPNG │
              └──────────────┬───────────────┘
                             ▼
                   原始帧、链路类型、时间戳
                             │
           ┌─────────────────┴─────────────────┐
           ▼                                   ▼
   Ethernet / ARP / IPv4               IPv6 / Extension Headers
   ICMP / TCP / UDP                    ICMPv6 / TCP / UDP
           │                                   │
           └───────────┬───────────────────────┘
                       ▼
          IPv4 分片缓存与重组 / 应用层元数据解析
                       │
                       ▼
                PacketRecord 统一模型
                       │
       ┌───────────────┼───────────────┬──────────────┐
       ▼               ▼               ▼              ▼
   数据包列表       流量态势        会话/TCP 流     异常检测
       │                                               │
       └───────────────► PCAP / CSV ◄─────────────────┘
```

关键模块：

| 文件 | 职责 |
|---|---|
| `sniffer/interfaces.py` | Npcap 网卡枚举、筛选和显示信息 |
| `sniffer/capture.py` | 实时抓包线程、队列、统计与重组接入 |
| `sniffer/offline.py` | PCAP/PCAPNG 后台流式加载 |
| `sniffer/parser.py` | Ethernet、IPv4/IPv6、ICMP(v6)、TCP/UDP 手工解析 |
| `sniffer/reassembly.py` | IPv4 分片缓存、异常检测与重组 |
| `sniffer/application.py` | DNS、HTTP、TLS、DHCP 元数据解析 |
| `sniffer/analytics.py` | 流量时间序列、双向会话和 TCP 载荷整理 |
| `sniffer/anomaly.py` | 被动异常检测规则与告警模型 |
| `sniffer/filtering.py` | 显示过滤语法 |
| `sniffer/storage.py` | PCAP 保存和 CSV 导出 |
| `sniffer/gui.py`、`theme.py` | NetScope 主界面、交互与视觉主题 |

Scapy 不承担上述核心协议字段解析，也不调用其内置 IP defragment 功能。

## 环境要求

- Windows 10/11 x64
- Python 3.11 或更高版本
- Npcap 1.8 或更高版本
- Scapy 2.7.0
- PyQt6 6.11.0
- pytest 9.1.1（测试）
- Wireshark（可选，用于验收对照）

安装 Npcap 时建议不要启用“仅管理员访问”，否则抓包时需要以管理员身份运行。
项目不要求 WinPcap 兼容模式，也不使用原始 802.11 Monitor Mode。

## 安装与启动

```powershell
git clone https://github.com/sjy789/windows-network-sniffer.git
cd windows-network-sniffer

py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

已创建虚拟环境时，直接执行：

```powershell
.\.venv\Scripts\python.exe main.py
```

也可以安装为命令行入口：

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\network-sniffer.exe
```

## 快速演示

### 实时抓包

1. 在“监听网卡”中选择实际承载流量的接口。
2. 可选填写 BPF，例如 `icmp or icmp6`、`tcp`、`udp port 53` 或 `ip or ip6`。
3. 点击“开始”，再执行以下受控流量：

```powershell
ping -4 1.1.1.1
ping -6 ipv6.google.com
nslookup example.com
curl.exe https://example.com
```

4. 在左侧依次查看“实时抓包”“流量态势”“会话分析”和“异常检测”。
5. 停止后可保存 PCAP 或导出 CSV。

如果开启 VPN/代理隧道，流量可能经过 `xray_tun` 等虚拟接口，而不是物理 WLAN。
应选择实际承载目标流量的接口。

### 离线抓包

1. 停止实时抓包。
2. 点击“打开 PCAP”。
3. 选择 `.pcap` 或 `.pcapng` 文件。
4. 数据会在后台分批进入数据包列表、流量统计、会话分析和异常检测。
5. 大文件加载期间可取消；关闭窗口时会先安全停止读取线程。

### 查看明文 TCP 流

TLS 和 SSH 载荷已加密，显示 Hex/ASCII 属于正常现象。若要演示可读 TCP 流，
可在本机启动明文 HTTP 服务：

```powershell
# 终端 1
.\.venv\Scripts\python.exe -m http.server 8080 --bind 127.0.0.1

# 终端 2
curl.exe http://127.0.0.1:8080/
```

在 NetScope 中选择 Npcap Loopback Adapter，使用 `tcp port 8080` 抓取过滤，
然后进入“会话分析”查看双向 HTTP 文本。

## 显示过滤语法

过滤词之间为 AND 关系，且不区分大小写。

| 示例 | 含义 |
|---|---|
| `tcp`、`udp`、`arp`、`icmp`、`icmpv6` | 按协议过滤 |
| `ipv4`、`ipv6`、`ip6` | 按 IP 版本过滤 |
| `dns`、`http`、`https`、`tls`、`dhcp`、`quic` | 按应用层标识过滤 |
| `ip:192.0.2.1`、`ip:2001:db8::1` | 源或目标 IP |
| `src:192.0.2.1`、`src:2001:db8::1` | 源 IP |
| `dst:198.51.100.2`、`dst:2001:db8::2` | 目标 IP |
| `port:443` | 源或目标端口 |
| `sport:12345`、`dport:53` | 指定方向端口 |
| `tcp dport:443` | TCP 且目标端口为 443 |

## 协议实现说明

### IPv4 分片

分片按 `(源 IP, 目标 IP, 协议号, Identification)` 归组，Fragment Offset
换算为真实字节偏移。只有首片、末片和连续覆盖都满足时才完成重组。

- 支持乱序和完全相同的重复片。
- 不一致重叠会标记异常并丢弃整组。
- 缺片默认 30 秒超时。
- 默认最多缓存 1024 组、64 MiB。
- 重组后更新 Total Length、清除 MF/offset 并重算 IPv4 首部校验和。
- 重组虚拟记录用于分析和展示，不会重复写入 PCAP，也不会重复计入真实流量。

### IPv6 与 ICMPv6

- 扩展首部链最多遍历 16 层，避免异常报文消耗无限资源。
- 支持 Hop-by-Hop、Destination Options、Routing、Fragment、AH 和 ESP。
- 支持 Echo、常见错误、Router/Neighbor Discovery、MLD/MLDv2 和常用 ND 选项。
- 非首个 IPv6 分片不会被误解析为 TCP/UDP。
- 当前展示 IPv6 Fragment Header，但不执行 IPv6 分片重组。

### 会话与加密边界

- TCP/UDP 记录按双向端点归并为会话。
- TCP 有效载荷按 Sequence Number 排序，并处理重叠段。
- UTF-8/GB18030 明文按文本展示；二进制、压缩或加密载荷按 Hex/ASCII 展示。
- 不执行 TLS 解密，也不声称恢复加密后的 HTTP 正文或 SSH 内容。

## 测试与验收

运行全部自动化测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

最近验证结果：

```text
112 passed
pip check: No broken requirements found
compileall: passed
```

测试覆盖协议字段、IPv6 扩展首部、ICMPv6、截断/畸形包、IPv4 分片、
过滤器、网卡筛选、后台队列、离线 PCAP/PCAPNG、保存导出、流量统计、
会话整理、异常检测和 PyQt6 离屏 GUI。

建议答辩时与 Wireshark 对照：源/目标地址、协议、端口、长度、IPv4 分片字段、
IPv6 Next Header、ICMPv6 类型和 TLS SNI。

## 五人开发与汇报分工

以下按仓库账号列出；提交材料时可替换为真实姓名和学号。

| 成员 | 主要开发与汇报内容 | 现场展示 | 额外材料职责 |
|---|---|---|---|
| `sjy789 / shijiayu` | 总体架构、基础协议解析、IPv4 分片重组、NetScope GUI 与系统集成 | 介绍系统目标、架构和主界面，演示实时抓包与 IPv4 分片 | **PPT 统稿与制作**：统一视觉、架构图、演示截图和汇报节奏 |
| `Narcissismm / YangHaoWen` | 流量态势、会话/TCP 流、应用层元数据、异常检测与跨模块缺陷修复 | 演示流量曲线、会话分析、明文/加密载荷差异和异常告警 | **项目设计报告统稿**：整合需求、设计、算法、测试、结论与参考资料 |
| `hopeworld0218 / zmxhs7` | IPv6、扩展首部链、ICMPv6、邻居发现和 IPv6 过滤 | 对照 Wireshark 演示 IPv6/ICMPv6 字段与扩展首部 | 提供 IPv6 章节、测试样本和对照截图 |
| `coisini612 / coisini-612` | 离线 PCAP/PCAPNG、后台加载、取消与进度、离线链路类型 | 演示打开 PCAP、后台加载、取消以及离线数据进入统一分析流水线 | 提供离线分析章节、测试数据和演示 PCAP |
| `fanta20240317 / fei-fei` | 捕获可靠性、线程停止、网卡与队列边界、保存导出和测试保障 | 演示异常 BPF、开始/停止恢复、PCAP/CSV 导出与自动化测试 | 汇总测试表、运行环境和风险/限制清单 |

### 建议汇报顺序（总计约 15–18 分钟）

1. **成员 1：项目背景与总体架构，3 分钟**
   说明选题目标、技术路线、模块关系和 NetScope 主界面。
2. **成员 5：实时捕获与工程可靠性，2–3 分钟**
   说明 Npcap、后台线程、有界队列、过滤、停止和保存机制。
3. **成员 3：IPv6 与协议解析，3 分钟**
   讲解手工解析、扩展首部和 ICMPv6，并与 Wireshark 对照。
4. **成员 4：离线分析，2–3 分钟**
   演示 PCAP/PCAPNG 导入、后台分批处理和统一分析流水线。
5. **成员 2：高级分析与总结，4 分钟**
   演示流量态势、会话/TCP 流、应用层元数据和异常检测，最后总结测试与限制。

PPT 制作者负责控制页面结构与总时长；报告统稿者负责确保 PPT、README、设计报告
中的架构、测试数量、功能边界和术语完全一致。每位成员至少准备一个可独立运行的演示场景，
并为网络不可用准备对应 PCAP 文件。

## 安全边界与已知限制

- 只承诺捕获所选接口上的本机收发流量；交换网络的混杂模式不代表能看到整个局域网。
- 不包含 ARP 欺骗、中间人、数据包注入、主动扫描或凭据提取功能。
- 不执行 TLS/SSH 解密；加密或压缩载荷只显示 Hex/ASCII。
- IPv6 分片当前只解析 Fragment Header，不进行完整重组。
- TCP 流整理用于观察有效载荷，不是完整的 TCP 状态机或应用文件恢复器。
- PCAP、CSV 和原始数据视图可能包含隐私信息，演示应使用自建流量并妥善清理文件。
- Windows 出站校验和可能由网卡硬件稍后填写，抓包中的未完成校验和不一定代表错误。

更多资料：

- [方案决策记录](docs/DECISIONS.md)
- [验证记录](docs/VERIFICATION.md)
