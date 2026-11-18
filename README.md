# AgentSnoop

无 Go 的双 Agent 演示。C/libbpf 监控两个 Linux 进程及其直接子进程，输出 JSONL。板卡上已构建，可以直接运行：

```sh
cd /root/AgentSnoop
make test
```

要保留原始事件和调用栈，运行 `python3 demo.py 新文件.jsonl`。A 重复打开配置 25 次、尝试打开敏感测试路径，并与回环 TLS 服务交换短消息；B 正常打开配置一次，两者都以可写模式打开共享文件。

- `agent.bpf.c` 采集 execve、openat（入口和返回）、write、IPv4 connect、kmalloc 和 kfree。CO-RE 读取父进程字段。OpenSSL 演示使用 SSL_write/read 的两对入口和返回探针，仅挂到自带测试客户端，按实际返回长度展示最多 64 字节文本。
- `monitor.c` 加载探针，`rules.c` 在用户态匹配演示用绝对路径。三条规则为敏感路径打开尝试、同一 Agent 在 10 秒窗口内成功打开同一路径 20 次、不同 Agent 在同一窗口内以可写方式成功打开同一路径。
- `stacks.c` 在退出时汇总分配字节及尚未观察到释放的字节，通过栈表和 `/proc/kallsyms` 输出内核函数名。统计范围为观测到的 kmalloc/kfree。

监控已有进程时，在本目录运行 `./agentsnoop --pid PID_A --pid PID_B --sensitive /绝对路径`，用 Ctrl-C 停止并输出分配栈。构建使用支持 BPF 的 Clang、C 编译器、libbpf 1.x、libelf、zlib 和 OpenSSL 3 开发文件。演示另需 Python 3 和 openssl 命令。板卡的本项目依赖放在 `.deps`，无需替换系统库。

实测同一份 BPF 对象（SHA-256 `e553499b189dc77485e143e33727fcc7bc2e871ec7113432fffe50315d1acd9c`）在 ARM64 板卡 Linux 6.1.141 和 x86_64 QEMU Linux 5.8.0-63-generic 上运行双 Agent 演示。5.8 虚拟机使用 BTFHub 中与 Ubuntu 内核版本及构建匹配的外部 BTF。板卡保存了 `run.jsonl` 和 `core-5.8.log` 两份记录。
