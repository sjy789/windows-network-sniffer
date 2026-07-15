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
- 本阶段尚未增加 IPv6 深度解析、TCP 流重组或 TLS 解密。

## 2026-07-13：流量分析与被动检测扩展

- 保留主线 PyQt6 前端布局，以独立页签加入流量态势、双向会话/TCP 流和异常检测。
- 应用层解析只读取明确可验证的元数据：DNS、HTTP、TLS ClientHello/SNI/ALPN 和 DHCP；不解密 TLS 正文。
- TCP 流按双向端点聚合并按 Sequence Number 排序，单流设置内存上限；该功能用于观察，不替代完整 TCP 状态机。
- 异常检测采用有冷却时间的透明阈值规则，仅产生本地提示，不执行阻断、扫描或主动响应。

## 2026-07-13：抓包可靠性修复

- 停止抓包时只在后台线程确认退出后切换为停止状态；停止失败时保留运行状态，防止再次启动并产生两个抓包线程。
- 后台线程异常、致命会话错误和单包解析警告分开记录，GUI 定时同步线程状态并恢复正确的控制按钮。
- 界面继续采用 20,000 条滚动显示缓存，但保存和导出前必须提示已淘汰的记录数量，避免把不完整结果当作完整捕获。
- 经典 PCAP 不混写真正不同的链路层类型；Ethernet、回环和 Raw IP 会话需要分别保存。
  同一 Raw IP 会话内的 IPv4/IPv6 统一使用 DLT_RAW，同一回环会话统一使用 DLT_NULL。
- `https` 显示过滤作为 `tls` 端口提示的别名处理，与解析器实际输出保持一致。

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

## 2026-07-15：最新主线回归修复

- 在线与离线加载都优先保留 Ethernet/Loopback 封装，并补齐原始 IPv6 识别，避免回读时降级为 UNKNOWN。
- PCAP 写出改为按实际 DLT 写入原始帧字节：Ethernet 使用 DLT_EN10MB，回环使用 DLT_NULL，
  混合原始 IPv4/IPv6 使用 DLT_RAW；保留每包时间戳并继续排除重组虚拟包。
- 流量图按固定一秒时间桶推进，空闲时补零，停止时添加零点；延迟到达的窗口内记录仍回填原时间桶。
- TLS ClientHello 的 SNI/ALPN 解析增加长度校验、有界 TCP 分段/乱序重组和序列号回绕处理。
- 顶栏设置与帮助按钮改为实际窗口；列表容量、队列刷新间隔和图表时间窗可持久化配置。
