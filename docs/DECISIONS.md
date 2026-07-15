# 方案决策与变更记录

## 2026-07-10：启动基线

- 平台固定为 Windows 10/11，开发语言为 Python。
- Npcap 提供底层抓包能力，Scapy 只用于接口调用、后台捕获和 PCAP 读写。
- Ethernet、ARP、IPv4、ICMP、TCP、UDP 的核心字段从原始字节自行解析。
- IPv4 分片识别、缓存、重组、超时和异常策略自行实现；不做 TCP 流重组。
- IPv6、DNS 深度解析和 TLS 解密不属于首版必做范围。
- GUI 使用 PyQt6；捕获线程、解析/重组与界面展示解耦，队列有容量上限。
- 显示过滤支持协议、IP、方向与端口；保存支持 PCAP 和 CSV 摘要。
- 只承诺捕获所选网卡上的本机收发流量，不实现主动中间人功能。

## 2026-07-10：环境验证带来的实现调整

- Windows 会暴露大量协议过滤器和不可捕获组件。网卡选择框不直接展示全部
  Windows 接口，而以 Npcap 可打开设备为基准去重、筛选并友好命名。
- 当前开发环境使用 Python 3.13.7、Scapy 2.7.0、PyQt6 6.11.0、
  Wireshark 4.6.7 和 Npcap 1.88。

## 2026-07-12：最终集成调整

- DNS、HTTP、TLS、DHCP 和 QUIC 只依据常见端口进行透明标识；界面明确显示
  “Port-based identification only”，不把端口推断伪装成应用层深度解析。
- IPv4 分片键统一为 `(源 IP, 目标 IP, 协议号, Identification)`。
- 截断分片不进入重组缓存；非末片载荷必须满足 8 字节对齐。
- 每个捕获包都会触发过期分片清理，即使后续流量不再包含分片，也能落实
  30 秒超时策略。
- 显式加载微软雅黑字体，避免部分 Qt/Windows 环境中文显示成方框。
- 当时项目仍未增加 IPv6 深度解析、TCP 流重组或 TLS 解密。

## 2026-07-15：IPv6 深度解析

- Ethernet `0x86DD`、原始 IPv6 和常见 DLT_NULL IPv6 地址族统一进入手写解析器。
- IPv6 固定首部完整展示 Version、Traffic Class、DSCP/ECN、Flow Label、
  Payload Length、Next Header、Hop Limit 和源/目标地址。
- 按 `Next Header` 遍历 Hop-by-Hop、Routing、Fragment、Destination Options、
  AH 和 ESP；最多遍历 16 个扩展首部，并对截断、保留位和异常长度做防御性检查。
- ICMPv6 深度解析覆盖 Echo、错误报文、邻居发现、路由器发现、Redirect、
  MLD/MLDv2，以及常见 ND 选项。
- IPv6 Fragment Header 只做字段解析和非首片保护，不接入现有 IPv4 重组缓存；
  因此不会把非首片数据误判为 TCP/UDP 端口，也不会混用两套分片语义。
- 显示过滤新增 `ipv6`/`ip6` 和 `icmpv6`/`icmp6`，IPv6 地址继续使用统一的
  `ip:`、`src:`、`dst:` 语法。
