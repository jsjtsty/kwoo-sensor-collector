# 上报接口契约

采集端向 `POST /v1/telemetry/raw` 发送 JSON。服务端应使用 HTTPS、按 `event_id` 幂等，并在成功处理后返回 2xx。

请求头为 `X-Key-Id`、`X-Timestamp` 和 `X-Signature`。签名算法为 HMAC-SHA256，规范字符串为：

```text
POST\n/v1/telemetry/raw\n<unix-seconds>\n<lowercase-hex-sha256-of-body>
```

请求体包含 `site_id`、`sent_at` 和 `events`。每个 event 包含 event_id、采集器地址、请求/接收时间、功能码、起始寄存器、数量、request_hex、response_hex、crc_valid。2xx 表示批次可按 event_id 接受；429、5xx 和网络错误会重试。
