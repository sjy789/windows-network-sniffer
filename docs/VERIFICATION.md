# 项目验证记录

最新自动化验证：2026-07-15，Windows 11 x64、Python 3.12
Windows 实机验证：2026-07-12，Windows 11 x64、Python 3.13.7、Npcap 1.88、Wireshark 4.6.7

## 自动化验证

```text
112 passed
pip check: No broken requirements found.
compileall: passed
```

覆盖范围包括：

- Ethernet、双 VLAN、ARP、IPv4、IPv6、ICMP、ICMPv6、TCP、UDP 字段解析。
- IPv6 Hop-by-Hop、Routing、Fragment、Destination Options、AH、ESP 扩展首部链。
- ICMPv6 Echo、错误报文、邻居/路由器发现、ND 选项和 MLD/MLDv2 字段。
- IPv4/TCP 可变头长和 options。
- 截断、畸形及未知链路层的容错。
- Hex/ASCII 与 payload 可打印摘要。
- 协议、方向、IP 和端口显示过滤。
- 乱序、重复、空洞、重叠、超时和资源上限下的 IPv4 分片重组。
- 网卡筛选、后台队列、停止逻辑、PCAP 和 CSV。
- PyQt6 离屏初始化、控制状态、详情树和 Hex 视图。
- DNS、HTTP、TLS 和 DHCP 应用层元数据解析。
- 流量时间序列、双向会话和乱序 TCP 有效载荷整理。
- IPv6 TCP 会话状态和双向载荷提取，以及原始 IPv6 离线抓包识别。
- IPv4 分片/重组虚拟记录不会重复计入流量与会话统计。
- 端口扫描、长 DNS 查询和 ARP 地址冲突等异常检测规则。
- 离线加载取消与窗口关闭时的线程安全退出。
- 实时批量刷新保持用户当前选中的数据包与详情视图。
- TCP 流自动识别 UTF-8/GB18030 文本，二进制或加密载荷回退为 Hex/ASCII。
- 停止失败后的会话状态、后台线程异常、滚动缓存淘汰计数和混合链路层 PCAP 拒绝逻辑。

## 真实环境验证

| 场景 | 结果 |
|---|---|
| Npcap 网卡枚举 | 成功筛出 6 个可捕获接口，包括 WLAN、虚拟网卡和回环 |
| 无效 BPF | 启动阶段返回友好错误，捕获线程正确停止 |
| WLAN 实时抓包 | 成功捕获并手工解析 IPv4/TCP/TLS 标识，无解析警告 |
| Ping | 在实际承载路由的隧道接口捕获 1 个 Echo Request 和 1 个 Echo Reply |
| 本地网页/文件传输 | 回环接口捕获 16 KiB HTTP/TCP 传输，11 个记录均标识为 HTTP |
| PCAP 保存与回读 | 保存数量与 Scapy 回读数量一致 |
| CSV 导出 | 行数正确，UTF-8 BOM 正确，并防止表格公式注入 |
| IPv4 分片 | 4 个乱序分片生成 1 个完整 UDP 虚拟包，无错误 |
| GUI | 中文字体、包表、协议树和 Hex/ASCII 离屏渲染成功 |

## 验收说明

- 当 VPN/代理隧道启用时，应选择实际承载流量的虚拟接口进行测试。
- BPF `tcp port 443` 可同时捕获 IPv4/IPv6 TCP；若只验收 IPv4，可使用
  `ip and tcp port 443`，只验收 IPv6 可使用 `ip6 and tcp port 443`。
- 重组后的虚拟包用于显示和字段检查，不会重复写入原始 PCAP。
