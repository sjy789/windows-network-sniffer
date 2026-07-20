# NetScope — Windows 网络嗅探器

NetScope 是一个面向计算机网络课程设计的 Windows 桌面网络分析工具。它通过
Npcap 实时抓包，并使用 Scapy 接入抓包及读写 PCAP/PCAPNG 文件。协议字段由项目代码
从原始字节手工解析，再通过 PyQt6 图形界面呈现数据包、协议结构、流量趋势、双向会话和异常事件。

项目重点在于完整展示网络嗅探器从
**网卡发现 → 数据捕获 → 协议解析 → 分片重组 → 会话分析 → 可视化与导出**
的核心实现过程。

> 仅可在本人设备、明确授权设备或隔离实验网络中使用。

## 项目亮点

- **从原始字节理解数据包**：Scapy 主要负责抓包和文件读写，协议字段则由项目代码
  直接从原始字节中提取，完整呈现各层协议的解析过程，并识别截断、长度异常等问题。
- **完整处理 IPv4 分片**：程序会缓存属于同一数据报的分片，在首片、末片和中间数据连续时
  完成重组。乱序、重复、缺失和相互冲突的分片都有明确的处理结果，同时设置超时和容量限制。
- **逐层解析 IPv6 报文**：解析器从 IPv6 基本首部开始，沿扩展首部链继续读取后续内容。
  常见的 ICMPv6 控制报文、邻居发现和组播监听信息也会转换为可读字段。
- **统一处理实时与离线流量**：实时抓取的数据和 PCAP/PCAPNG 文件中的数据会进入同一条
  处理流程，因此两种来源可以使用相同的协议解析、流量统计、会话整理和异常检测能力。
- **从单个数据包延伸到会话观察**：TCP 和 UDP 数据包会按通信双方归并，便于查看流量方向
  和持续时间。TCP 有效载荷按序整理后，可读文本直接显示，加密或二进制内容则使用 Hex/ASCII。
- **通过被动分析发现异常**：程序根据已捕获流量在短时间内呈现的行为特征生成告警，
  可识别端口扫描、SYN 洪泛、DNS 异常、ARP 地址冲突和异常分片等情况。
- **用图形界面串联分析过程**：界面把抓包控制、数据包详情、流量变化、双向会话和异常告警
  放在同一应用中，能够从总体趋势逐步查看到具体协议字段和原始字节。

## 功能总览

| 模块 | 已实现能力 |
|---|---|
| 网卡管理 | 自动列出 Npcap 可捕获的接口，并过滤无效的 Windows 系统组件。物理网卡、虚拟网卡和回环接口均可用于监听。 |
| 实时捕获 | 使用 `AsyncSniffer` 在后台持续抓包，通过有界队列分批送入界面。停止超时或捕获异常时会恢复操作状态并给出提示。 |
| 离线分析 | 在后台读取 PCAP 或 PCAPNG 文件，并显示加载进度。大文件读取可以取消，Ethernet、原始 IPv4/IPv6 和回环链路数据会进入同一套分析流程。 |
| 链路层解析 | 从原始字节解析 Ethernet II、ARP 和 DLT_NULL 回环报文，也能处理两层嵌套的 802.1Q/802.1ad VLAN 标签。 |
| IPv4 解析 | 解析固定首部、可变 Options 和长度信息，识别异常或截断报文。遇到分片时会进行缓存、完整性判断和重组。 |
| IPv6 解析 | 解析 IPv6 基本首部并按顺序遍历扩展首部链，支持 Hop-by-Hop、Routing、Fragment、Destination Options、AH 和 ESP。 |
| ICMP/ICMPv6 | 展示 Echo 和常见错误报文的关键字段，并进一步解析 IPv6 邻居发现、路由器发现、MLD/MLDv2 及常用 ND 选项。 |
| TCP/UDP 解析 | 解析端口、长度和有效载荷；TCP 还会展示序列号、确认号、标志、窗口及 Options 等连接信息。 |
| 应用层元数据 | 从常见端口的明文载荷中提取 DNS 查询、HTTP 首部、TLS 握手、SNI、ALPN 和 DHCP 选项。QUIC 仅按常见端口进行标识。 |
| 数据查看 | 数据包先以摘要表呈现，选中后可查看分层协议字段和 Hex/ASCII 原始内容。协议颜色和容量受限的滚动历史便于持续观察。 |
| 数据过滤 | 抓包前可使用 BPF 减少进入程序的数据，抓包后可按协议、IP、方向和端口组合筛选当前显示内容。 |
| 流量态势 | 汇总最近 60 秒的包速率和字节速率，同时展示协议分布、活跃会话数与告警数量，便于观察流量变化。 |
| 会话分析 | 按双向端点归并 TCP/UDP 数据包，统计双方的包数、字节数和持续时间。TCP 会话还可查看基本状态及按序整理后的有效载荷。 |
| 异常检测 | 通过被动规则识别端口扫描、SYN 洪泛、异常 DNS 活动、ARP 地址冲突、IPv4 分片异常和 TCP Reset，并在界面中生成分级告警。 |
| 保存与导出 | 可将仍保留的真实捕获包保存为 PCAP，也可把数据包摘要导出为 UTF-8-BOM CSV。导出时会处理可能触发公式执行的单元格内容。 |

## 架构与项目结构

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

```text
.
├── main.py                 # 源码运行入口
├── run.bat                 # Windows 快速启动脚本
├── pyproject.toml          # 项目元数据、依赖和命令行入口
├── requirements.txt        # 固定版本依赖
├── sniffer/                # 抓包、解析、分析与界面实现
├── tests/                  # 自动化测试
└── docs/                   # 设计决策、验证记录和演示抓包
```

`sniffer/` 中的主要模块：

| 文件 | 职责 |
|---|---|
| `sniffer/app.py` | 应用启动、字体加载与未捕获异常处理 |
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
| `sniffer/models.py` | 数据包、协议层、网卡和重组结果等公共模型 |
| `sniffer/dashboard.py` | 流量曲线和指标卡组件 |
| `sniffer/formatting.py` | Hex/ASCII 和载荷摘要格式化 |
| `sniffer/gui.py`、`sniffer/theme.py` | 主界面、交互、图标与视觉主题 |

Scapy 在项目中用于抓包接入和文件读写；核心协议字段解析与 IPv4 分片重组均由项目代码完成。

## 环境要求

- Windows 10/11 x64
- Python 3.11 或更高版本
- Npcap（用于实时抓包；离线分析 PCAP/PCAPNG 时可不安装）
- Scapy 2.7.0
- PyQt6 6.11.0
- pytest 9.1.1（测试）
- Wireshark（可选，用于验收对照）

安装 Npcap 时建议不要启用“仅管理员访问”，否则抓包时需要以管理员身份运行。
安装 Npcap 时无需启用 WinPcap 兼容模式；程序不处理原始 802.11 无线帧。

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

也可以双击 `run.bat`；脚本会使用项目内 `.venv` 启动程序。

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

TLS 和 SSH 载荷经过加密，因此会显示为 Hex/ASCII。若要演示可读 TCP 流，
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

### 会话与加密边界

- TCP/UDP 记录按双向端点归并为会话。
- TCP 有效载荷按 Sequence Number 排序，并处理重叠段。
- UTF-8/GB18030 明文按文本展示；二进制、压缩或加密载荷按 Hex/ASCII 展示。

## 测试

运行全部自动化测试：

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

当前测试结果为 `128 passed`，覆盖协议解析、IPv4 分片重组、IPv6/ICMPv6、显示过滤、实时与离线抓包流程、会话分析、异常检测、文件导出和 PyQt6 界面。

## 五人开发分工

| 成员 | 主要开发与汇报内容 |
|---|---|
| `sjy789 / shijiayu` | 负责确定项目的整体架构，实现 Ethernet、ARP、IPv4、ICMP、TCP 和 UDP 等基础协议的字段解析，完成 IPv4 分片识别、缓存与重组，以及 NetScope 的 UI 设计与优化。 |
| `Narcissismm / YangHaoWen` | 负责在基础解析结果上实现流量统计、双向会话、TCP 载荷整理、应用层信息与被动异常检测等附加功能；协助修复模块衔接问题。 |
| `hopeworld0218 / mengxi zhang` | 负责完成 IPv6、ICMPv6、扩展首部链、邻居与路由器发现、组播监听报文解析，并补充 IPv6 捕获、显示过滤和测试。 |
| `coisini612 / coisini-612` | 负责离线抓包文件的读取流程，使 PCAP/PCAPNG 能在后台分批加载，并支持进度显示、取消操作和多种链路类型。 |
| `fanta20240317 / fei-fei` | 负责确保项目稳定性，处理网卡、队列和线程停止等边界情况，并完善数据保存、摘要导出及自动化测试。 |

## 使用边界与已知限制

- 程序捕获的是所选接口上可见的本机收发流量。即使开启混杂模式，在交换网络中通常也无法直接看到整个局域网的通信。
- 项目仅进行被动流量分析，不提供 ARP 欺骗、中间人攻击、数据包注入、主动扫描或凭据提取功能。
- 程序不能解密 TLS 或 SSH 流量，加密、压缩及其他不可读载荷会以 Hex/ASCII 形式显示。
- IPv6 Fragment Header 可以正常解析，但目前没有实现 IPv6 分片重组。
- TCP 载荷整理主要用于观察通信内容，不包含完整的 TCP 状态机，也不能用于恢复应用文件。
- PCAP、CSV 和原始数据视图中可能含有地址、域名或载荷等敏感信息。演示时建议使用自行生成的测试流量，并在使用后清理相关文件。
- Windows 可能将出站报文的校验和交给网卡硬件计算，因此抓包中显示的未完成校验和不一定是报文错误。

更多资料：

- [方案决策记录](docs/DECISIONS.md)
- [验证记录](docs/VERIFICATION.md)
