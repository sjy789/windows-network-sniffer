# 网络嗅探器设计与实现

面向 Windows 10/11 的课程项目。程序通过 Npcap 和 Scapy 捕获指定网卡上的
本机收发流量，但核心协议字段、IPv6 扩展首部和 IPv4 分片均由项目代码从原始字节自行解析。
PyQt6 界面提供数据包摘要、分层字段、Hex/ASCII、过滤和保存功能。

## 已实现功能

- 枚举、筛选并选择 Npcap 可捕获网卡，支持物理、虚拟和回环接口。
- 后台实时抓包，捕获线程与 GUI 分离，使用有界队列和批量刷新。
- 手工解析 Ethernet、802.1Q VLAN、ARP、IPv4、IPv6、ICMP、ICMPv6、TCP 和 UDP。
- 深度解析 IPv6 固定首部，以及 Hop-by-Hop、Routing、Fragment、Destination Options、AH 和 ESP 扩展首部。
- 解析 ICMPv6 Echo、错误报文、路由器/邻居发现、MLD/MLDv2 与常见邻居发现选项。
- 正确处理 IPv4/TCP 可变头长及 IPv6 扩展首部链，异常或截断报文不会使程序崩溃。
- 识别 DNS、HTTP、TLS、DHCP、QUIC 等常见端口流量，不解密应用层内容。
- Hex + ASCII 原始数据视图。
- IPv4 分片乱序缓存、重复片识别、缺片超时、重叠冲突检测和完整重组。
- 协议、源/目标 IP、源/目标端口显示过滤，以及可选 BPF 抓取过滤。
- 保存原始捕获为 PCAP，导出摘要为 UTF-8 CSV。
- 捕获数量、队列丢弃、解析异常和成功重组等状态统计。

## 架构

```text
Npcap / Scapy AsyncSniffer
            │
            ▼
     原始帧 + 时间戳
            │
            ▼
  手工 IPv4/IPv6 协议解析 ──► IPv4 分片缓存/重组
            │                 │
            └────────┬────────┘
                     ▼
                有界消息队列
                     │
              Qt 定时批量取出
                     ▼
       摘要表 / 协议树 / Hex-ASCII
                     │
              PCAP / CSV 保存
```

Scapy 不承担核心协议字段解析，也不调用其内置 IP defragment 功能。

## 环境

当前已验证环境：

- Windows 11 x64
- Python 3.13.7
- Npcap 1.88
- Wireshark 4.6.7
- Scapy 2.7.0
- PyQt6 6.11.0
- pytest 9.1.1

Npcap 安装时建议不启用“仅管理员访问”，否则运行程序抓包时需要管理员权限。
本项目不需要 WinPcap 兼容模式和原始 802.11 monitor mode。

## 启动

在项目根目录执行：

```powershell
.\.venv\Scripts\python.exe main.py
```

如果需要重新创建环境：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py
```

## 使用方法

1. 从“监听网卡”选择实际联网的接口，例如 `WLAN`。
2. 可选填写 BPF 抓取过滤，例如 `icmp`、`icmp6`、`tcp`、`udp port 53`。
3. 点击“开始”，执行 Ping、访问网页或进行受控文件传输。
4. 点击摘要表中的数据包查看协议树和 Hex/ASCII 原始数据。
5. 使用显示过滤快速缩小结果范围。
6. 停止后可保存 PCAP，或导出 CSV 摘要。

如果开启了 VPN/代理隧道，Ping 等流量可能经过 `xray_tun` 等虚拟接口，
而不是物理 `WLAN`。此时应选择实际承载目标流量的隧道接口；物理 WLAN
通常只能看到隧道外层的加密连接。

PCAP 只保存网络上真实捕获的包；重组后用于展示的虚拟包不会被重复写入。

### 显示过滤语法

过滤词之间是 AND 关系，不区分大小写：

| 写法 | 含义 |
|---|---|
| `tcp`、`udp`、`arp`、`icmp`、`icmpv6` | 按协议过滤 |
| `ipv4`、`ipv6`（或 `ip6`） | 按 IP 版本过滤 |
| `ip:192.0.2.1`、`ip:2001:db8::1` | 源或目标 IP |
| `src:192.0.2.1` | 源 IP |
| `dst:198.51.100.2` | 目标 IP |
| `port:443` | 源或目标端口 |
| `sport:12345` | 源端口 |
| `dport:53` | 目标端口 |
| `tcp dport:443` | TCP 且目标端口为 443 |

## IPv6 深度解析

解析器从 40 字节 IPv6 固定首部开始，按 `Next Header` 顺序遍历扩展首部链，
最多处理 16 个扩展首部以避免异常报文消耗无限资源。已实现：

- Hop-by-Hop 与 Destination Options：解析 Router Alert、Jumbo Payload、
  Home Address、Pad1/PadN 及未知选项的动作位和可变位。
- Routing：解析通用字段、Type 0 地址列表、Type 2 Home Address 和
  Type 4 Segment Routing Header 段列表。
- Fragment：解析 Identification、M 位和 8 字节单位偏移；非首片不会被误当作
  TCP/UDP 首部。当前仅展示 IPv6 分片字段，不做 IPv6 分片重组。
- AH：解析 SPI、序列号和完整性校验值；ESP 在加密边界停止解析并展示 SPI/序列号。
- ICMPv6：解析 Echo、Destination Unreachable、Packet Too Big、Time Exceeded、
  Parameter Problem、Router/Neighbor Solicitation/Advertisement、Redirect、
  MLD/MLDv2，以及链路层地址、Prefix Information、MTU、Route Information、
  RDNSS 和 DNSSL 等邻居发现选项。
- IPv6 上的 TCP/UDP 继续复用现有传输层解析器；支持 Ethernet、原始 IPv6 和
  Windows/BSD/macOS DLT_NULL 回环地址族。

## IPv4 分片策略

分片以 `(源 IP, 目标 IP, 协议号, Identification)` 归组，Fragment Offset
按 8 字节单位换算为真实偏移。完成条件为：存在首片、存在 `MF=0` 的末片，
且从偏移 0 到末尾没有空洞。

- 乱序：支持。
- 完全相同的重复片：忽略，不重复占用缓存。
- 不一致重叠：标记异常并丢弃整组，避免重组歧义。
- 缺片：默认 30 秒超时清理。
- 缓存限制：默认 1024 组、64 MiB。
- 重组完成：更新 IPv4 Total Length，清除 MF/offset，保留 DF，并重算头校验和。

## 测试

运行全部自动化测试：

```powershell
.\.venv\Scripts\python.exe -m pytest
```

测试覆盖 IPv4/IPv6 协议字段、扩展首部链、ICMPv6、可变头长、截断包、
Hex/ASCII、过滤、乱序/重复/重叠/
超时分片、队列上限、网卡筛选、PCAP/CSV 和离屏 GUI 初始化。

建议现场验收：

- `ping -4`：检查 ICMP Echo Request/Reply。
- `ping -6`：检查 IPv6 固定首部和 ICMPv6 Echo Request/Reply。
- 访问受控 IPv4 网页：检查 DNS、TCP 和 TLS/HTTP 标识。
- 本机或虚拟机 TCP/UDP 文件传输：检查端口、长度和数据视图。
- 使用固定分片测试样本：与 Wireshark 对照 Identification、MF、Offset 和重组结果。

## 安全边界与已知限制

- 只在本人设备、明确授权设备或隔离实验网络中使用。
- 程序是被动分析工具，不包含 ARP 欺骗、中间人、注入或凭据提取功能。
- PCAP 和 Hex/ASCII 可能包含隐私数据，演示应使用自建流量并妥善删除文件。
- IPv6 Fragment Header 已解析，但当前只对 IPv4 分片做完整重组；不做 TCP 流重组和 TLS 解密。
- 交换网络中的混杂模式不等于能看到整个局域网，本项目只承诺本机收发流量。
- Windows 出站校验和可能由网卡硬件稍后填写，抓包中看到的未完成校验和不一定是错误。

关键方案决策见 [docs/DECISIONS.md](docs/DECISIONS.md)。
实际验收记录见 [docs/VERIFICATION.md](docs/VERIFICATION.md)。
