# AgentSnoop-基于eBPF 的非侵入式多AI Agent异常监测框架

C/libbpf实现监控指定的Linux进程及其直接子进程，按Agent归属输出JSONL事件和告警。

## 快速开始

以 root 身份运行两条命令即可启动双 Agent 演示。首次运行 `make test` 会自动编译探针、监控器和测试客户端。

```sh
cd /root/AgentSnoop
make test
```

**从源码构建的环境要求**
```sh
- **OS**: Ubuntu 22.04+ (内核 ≥ 5.15，需 BTF 支持)
- **工具链**: clang ≥ 12, llvm, bpftool, Go ≥ 1.21, make
- **权限**: root（BPF 程序加载需要 `CAP_BPF` / `CAP_SYS_ADMIN`）
- 给我类似这样的唤醒要求
```
需要支持 BPF 和内核 BTF 的 Linux 环境、Make、支持 BPF 后端的 Clang、C 编译器，以及 libbpf 1.x、libelf、zlib 和 OpenSSL 3 的开发文件。还需要 Python 3 和 openssl 命令。进入源码根目录后运行 `make`，再以 root 身份运行 `make test`。

演示会启动两个测试进程和一个本地 TLS 服务。A 重复打开配置 25 次、尝试打开敏感测试路径，并与 TLS 服务交换短消息。B 打开配置一次，两个进程都以可写模式打开同一共享文件。


```sh
python3 demo.py trace-01.jsonl
```
## 项目结构
```sh
.
├── agent.bpf.o
├── agentsnoop
├── bpf
│   ├── agent.bpf.c
│   └── Makefile
├── common.mk
├── core-5.8.log
├── demo
│   ├── demo-agent.c
│   ├── demo.py
│   └── Makefile
├── demo-agent
├── demo.py -> demo/demo.py
├── include
│   └── events.h
├── Makefile
├── README.md
├── run.jsonl
├── trace-01.jsonl
└── user
    ├── Makefile
    ├── monitor.c
    ├── monitor.h
    ├── rules.c
    ├── stacks.c
    └── tls.c

4 directories, 22 files
```


## 监测功能

- `agent.bpf.c` 采集 execve、openat（入口和返回）、write、IPv4 connect、kmalloc 和 kfree。CO-RE 读取父进程字段。OpenSSL 演示使用 SSL_write/read 的两对入口和返回探针，仅挂到自带测试客户端，按实际返回长度展示最多 64 字节文本。
- `monitor.c` 加载探针，`rules.c` 在用户态匹配演示用绝对路径。三条规则为敏感路径打开尝试、同一 Agent 在 10 秒窗口内成功打开同一路径 20 次、不同 Agent 在同一窗口内以可写方式成功打开同一路径。
- `stacks.c` 在退出时汇总分配字节及尚未观察到释放的字节，通过栈表和 `/proc/kallsyms` 输出内核函数名。统计范围为观测到的 kmalloc/kfree。

监控已有进程时，在本目录运行 `./agentsnoop --pid PID_A --pid PID_B --sensitive /绝对路径`，用 Ctrl-C 停止并输出分配栈。

实测同一份 BPF 对象（SHA-256 `e553499b189dc77485e143e33727fcc7bc2e871ec7113432fffe50315d1acd9c`）在 ARM64 板卡 Linux 6.1.141 和 x86_64 QEMU Linux 5.8.0-63-generic 上运行双 Agent 演示。5.8 虚拟机使用 BTFHub 中与 Ubuntu 内核版本及构建匹配的外部 BTF。板卡保存了 `run.jsonl` 和 `core-5.8.log` 两份记录。

## 板端运行结果

在 ARM64 板卡（Linux `6.1.141`）运行演示脚本 `python3 demo/demo.py`，本轮 Agent A 的 PID 为 `5000`，Agent B 的 PID 为 `5001`。三条文件告警全部触发。

| 功能 | 本轮观测结果 |
|---|---|
| 进程、文件和网络追踪 | A 打开 `config` 并尝试连接 `127.0.0.1:49747`。A 的直接子进程 `5003` 执行 `/bin/cat`，事件归属 A。B 向 fd 3 请求写入 1 字节。 |
| 文件告警 | A 第 20 次成功打开 `config` 时触发 `repeated_open`。尝试打开不存在的 `secret.demo` 时触发 `sensitive_open`（返回值 `-2`）。A 和 B 在同一窗口内以可写模式打开 `shared`，触发 `shared_writable_open`。 |
| TLS 明文 | A 通过 `SSL_write` 发送 `agent-demo/ping`，通过 `SSL_read` 收到 `agent-demo/pong`，各 15 字节。 |
| 内核分配与调用栈 | 观测到 23 次分配、20 次匹配释放。栈 `3029` 包含 `tcp_sendmsg` 和 `__alloc_skb`，该栈累计分配 3072 字节，结束时待释放 0 字节。 |

本轮监控器的原始健康计数如下：

```json
{"type": "health", "ring_drops": 0, "map_drops": 0, "stack_failures": 0, "allocations": 23, "matched_frees": 20}
```
monitor输出如下：
```json
python3 demo/demo.py
Agent A=5000  Agent B=5001
{"type": "event", "event": "openat", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148591030315, "path": "/tmp/agentsnoop-8x7ol_19/config", "flags": 0, "ret": 3}
{"type": "event", "event": "write", "agent": 5001, "pid": 5001, "tid": 5001, "ns": 5148591047290, "fd": 3, "requested": 1}
{"type": "alert", "rule": "repeated_open", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148591137658, "ret": 3, "path": "/tmp/agentsnoop-8x7ol_19/config", "count": 20}
{"type": "alert", "rule": "sensitive_open", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148591173837, "ret": -2, "path": "/tmp/agentsnoop-8x7ol_19/secret.demo"}
{"type": "event", "event": "execve", "agent": 5000, "pid": 5003, "tid": 5003, "ns": 5148591479024, "path": "/bin/cat"}
{"type": "event", "event": "connect", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148599308518, "ip": "127.0.0.1", "port": 49747}
{"type": "event", "event": "ssl_write", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148612461337, "bytes": 15, "message": "agent-demo/ping"}
{"type": "event", "event": "ssl_read", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148613066728, "bytes": 15, "message": "agent-demo/pong"}
{"type": "alert", "rule": "shared_writable_open", "agent": 5000, "pid": 5000, "tid": 5000, "ns": 5148613253536, "ret": 3, "path": "/tmp/agentsnoop-8x7ol_19/shared", "other_agent": 5001}
{"type": "allocation_site", "agent": 5000, "stack_id": 3029, "allocated_bytes": 3072, "outstanding_bytes": 0, "frames": ["__kmalloc_node_track_caller", "__kmalloc_node_track_caller", "kmalloc_reserve", "__alloc_skb", "tcp_stream_alloc_skb", "tcp_sendmsg_locked", "tcp_sendmsg", "inet_sendmsg", "sock_write_iter", "vfs_write", "ksys_write", "__arm64_sys_write", "invoke_syscall", "el0_svc_common.constprop.0", "do_el0_svc", "el0_svc", "el0t_64_sync_handler", "el0t_64_sync"]}
{"type": "health", "ring_drops": 0, "map_drops": 0, "stack_failures": 0, "allocations": 23, "matched_frees": 20}
```