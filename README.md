# SOLOTASK01 多租户密码与密钥管理后端

要实现一个多租户密钥管理后端，同时提供 HTTP 服务和命令行入口。技术选型用 Python 加 cryptography，不引入额外运行时依赖。密钥生成走 POST /v1/keys，请求体是 JSON，含 tenant_id、algorithm 与 label 三个字符串字段，algorithm 只接受 AES256 和 RSA2048；成功返回 201，响应含 key_id、algorithm 与 public_key，RSA2048 的 public_key 是 PEM 编码公钥，AES256 的 public_key 为 null。读取走 GET /v1/keys/{key_id}，返回 algorithm、label、created_at 与 public_key。缺少任一必填字段或 algorithm 不受支持时返回 400，错误信息需指出具体是哪个字段。命令行提供 gen 与 show 两个子命令，分别对应上面两个接口，打印单行 JSON 且字段名与 HTTP 响应完全一致。租户之间必须隔离，用另一个 tenant_id 查询同一 key_id 一律返回 404。私钥只保存在服务端，任何响应都不得包含私钥材料。密钥写入磁盘后重启服务仍可查到，created_at 不因重启而改变。

## 当前状态

接口已实现。代码结构：`kms/store.py`（磁盘持久化，按租户分目录）、`kms/service.py`（生成与查询逻辑）、`kms/server.py`（HTTP 服务，仅标准库）、`kms/cli.py`（命令行入口）。

### 安装依赖

```bash
pip install cryptography
```

### 启动 HTTP 服务

```bash
python3 -m kms --data-dir ./kms_data serve --host 127.0.0.1 --port 8080
```

示例：

```bash
curl -X POST http://127.0.0.1:8080/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id": "acme", "algorithm": "RSA2048", "label": "signing"}'
curl 'http://127.0.0.1:8080/v1/keys/<key_id>?tenant_id=acme'
```

### 命令行

```bash
python3 -m kms gen --tenant-id acme --algorithm AES256 --label enc
python3 -m kms show --tenant-id acme --key-id <key_id>
```

输出为单行 JSON，字段名与 HTTP 响应一致。`--data-dir` 可指定数据目录（默认 `./kms_data`）。

### 运行测试

```bash
python3 -m unittest discover -s tests -v
```
