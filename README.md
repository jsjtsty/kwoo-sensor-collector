# kwoo-sensor-collector

跨平台 Rust 后台采集服务：作为 TCP Server 接收 LoRa 网关连接，主动发送 Modbus RTU over TCP 读取请求，校验响应 CRC，将原始帧保存到 SQLite 并通过 HMAC 签名 HTTPS 接口补传。

复制 `config.example.toml` 为 `config.toml` 并填写站点、采集器、上报 URL 和密钥。网关应配置为 TCP Client，目标为运行本程序主机的局域网 IP 和 `12345` 端口。上传接口细节见 [API.md](API.md)。

```bash
cargo run -- config.toml
cargo test
```

Windows 发布后可使用管理员 PowerShell 执行 `install-service.ps1`；卸载执行 `uninstall-service.ps1`。

## GitHub Actions 发布

`.github/workflows/windows.yml` 会在 push 和 Pull Request 时验证 Windows x86/x64 构建。推送版本标签（例如 `v0.1.0`）后，Actions 会自动创建 GitHub Release，并附带两个 ZIP 包：

- `kwoo-sensor-collector-windows-x86.zip`
- `kwoo-sensor-collector-windows-x64.zip`
