# AgentSnoop-基于eBPF 的非侵入式多AI Agent异常监测框架

C/libbpf 监控指定的 Linux 进程及其直接子进程，按 Agent 归属输出 JSONL 事件和告警。

## 快速开始

**在已配置好的板卡上**，以 root 身份运行两条命令即可启动双 Agent 演示。首次运行 `make test` 会自动编译探针、监控器和测试客户端。

```sh
cd /root/AgentSnoop
make test
```

**从源码构建**需要支持 BPF 和内核 BTF 的 Linux 环境、Make、支持 BPF 后端的 Clang、C 编译器，以及 libbpf 1.x、libelf、zlib 和 OpenSSL 3 的开发文件。演示还需要 Python 3 和 openssl 命令。进入源码根目录后运行 `make`，再以 root 身份运行 `make test`。板卡已将本项目依赖放在 `.deps/`。

演示会启动两个测试进程和一个本地 TLS 服务。A 重复打开配置 25 次、尝试打开敏感测试路径，并与 TLS 服务交换短消息。B 打开配置一次，两个进程都以可写模式打开同一共享文件。

终端显示摘要。要将一次新演示的**全部事件和内核调用栈**保存为 JSONL，在项目根目录执行以下命令，文件名须尚未存在。

```sh
python3 demo.py trace-01.jsonl
```

## 监测功能

- `agent.bpf.c` 采集 execve、openat（入口和返回）、write、IPv4 connect、kmalloc 和 kfree。CO-RE 读取父进程字段。OpenSSL 演示使用 SSL_write/read 的两对入口和返回探针，仅挂到自带测试客户端，按实际返回长度展示最多 64 字节文本。
- `monitor.c` 加载探针，`rules.c` 在用户态匹配演示用绝对路径。三条规则为敏感路径打开尝试、同一 Agent 在 10 秒窗口内成功打开同一路径 20 次、不同 Agent 在同一窗口内以可写方式成功打开同一路径。
- `stacks.c` 在退出时汇总分配字节及尚未观察到释放的字节，通过栈表和 `/proc/kallsyms` 输出内核函数名。统计范围为观测到的 kmalloc/kfree。

监控已有进程时，在本目录运行 `./agentsnoop --pid PID_A --pid PID_B --sensitive /绝对路径`，用 Ctrl-C 停止并输出分配栈。

实测同一份 BPF 对象（SHA-256 `e553499b189dc77485e143e33727fcc7bc2e871ec7113432fffe50315d1acd9c`）在 ARM64 板卡 Linux 6.1.141 和 x86_64 QEMU Linux 5.8.0-63-generic 上运行双 Agent 演示。5.8 虚拟机使用 BTFHub 中与 Ubuntu 内核版本及构建匹配的外部 BTF。板卡保存了 `run.jsonl` 和 `core-5.8.log` 两份记录。

## 板端运行结果

在 ARM64 板卡（Linux `6.1.141`）执行 `make test`，本轮 Agent A 的 PID 为 `4962`，Agent B 的 PID 为 `4963`。三条文件告警全部触发。

| 功能 | 本轮观测结果 |
|---|---|
| 进程、文件和网络追踪 | A 打开 `config` 并尝试连接 `127.0.0.1:35367`。A 的直接子进程 `4965` 执行 `/bin/cat`，事件归属 A。B 向 fd 3 请求写入 1 字节。 |
| 文件告警 | A 第 20 次成功打开 `config` 时触发 `repeated_open`。尝试打开不存在的 `secret.demo` 时触发 `sensitive_open`（返回值 `-2`）。A 和 B 在同一窗口内以可写模式打开 `shared`，触发 `shared_writable_open`。 |
| TLS 明文 | A 通过 `SSL_write` 发送 `agent-demo/ping`，通过 `SSL_read` 收到 `agent-demo/pong`，各 15 字节。 |
| 内核分配与调用栈 | 观测到 24 次分配、20 次匹配释放。栈 `3029` 包含 `tcp_sendmsg` 和 `__alloc_skb`，该栈累计分配 3072 字节，结束时待释放 0 字节。 |

本轮监控器的原始健康计数如下。

```json
{"type": "health", "ring_drops": 0, "map_drops": 0, "stack_failures": 0, "allocations": 24, "matched_frees": 20}
```
