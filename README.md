# SOLOTASK01 多租户密码与密钥管理后端

要实现一个多租户密钥管理后端，同时提供 HTTP 服务和命令行入口。技术选型用 Python 加 cryptography，不引入额外运行时依赖。密钥生成走 POST /v1/keys，请求体是 JSON，含 tenant_id、algorithm 与 label 三个字符串字段，algorithm 只接受 AES256 和 RSA2048；成功返回 201，响应含 key_id、algorithm 与 public_key，RSA2048 的 public_key 是 PEM 编码公钥，AES256 的 public_key 为 null。读取走 GET /v1/keys/{key_id}，返回 algorithm、label、created_at 与 public_key。缺少任一必填字段或 algorithm 不受支持时返回 400，错误信息需指出具体是哪个字段。命令行提供 gen 与 show 两个子命令，分别对应上面两个接口，打印单行 JSON 且字段名与 HTTP 响应完全一致。租户之间必须隔离，用另一个 tenant_id 查询同一 key_id 一律返回 404。私钥只保存在服务端，任何响应都不得包含私钥材料。密钥写入磁盘后重启服务仍可查到，created_at 不因重启而改变。

## 安装

仅需 Python 3.10+ 与 `cryptography`，无其他运行时依赖：

```bash
pip install -r requirements.txt
```

## 启动 HTTP 服务

```bash
python -m keymgr --data-dir ./keymgr_data serve --host 127.0.0.1 --port 8080
```

数据目录也可用环境变量 `KEYMGR_DATA_DIR` 指定。

### 接口

- `POST /v1/keys`，请求体 `{"tenant_id", "algorithm", "label"}`，
  `algorithm` 仅支持 `AES256` / `RSA2048`。成功返回 `201`：
  `{"key_id", "version", "algorithm", "public_key"}`（首版 `version` 为
  `1`；RSA 返回 PEM 公钥，AES 返回 `null`）。
- `GET /v1/keys/{key_id}`，用请求头 `X-Tenant-Id: <tenant>` 标识租户
  （也支持 `?tenant_id=<tenant>` 查询参数）。成功返回 `200`：
  `{"key_id", "version", "label", "created_at", "algorithm", "public_key"}`，
  其中 `version`/时间/算法/公钥均取自当前版本。
- `POST /v1/keys/{key_id}/rotate`，请求体 `{"tenant_id", "algorithm"}`，
  生成新材料并追加一个不可变新版本、推进当前指针；`label` 沿用原 key。
  成功返回 `201`：`{"key_id", "version", "algorithm", "public_key"}`。
- `GET /v1/keys/{key_id}/versions/{version}` 取指定历史版本，
  `GET /v1/keys/{key_id}/current` 取当前版本，均返回 `200`：
  `{"key_id", "version", "created_at", "algorithm", "public_key"}`。
  租户同样可由 `X-Tenant-Id` 头或 `tenant_id` 查询参数给出。
- 缺少必填字段、algorithm 不支持、版本号非正整数、多个租户参数互相冲突
  返回 `400`，错误信息指明具体字段；未知 key、未知版本或跨租户访问统一
  返回 `404`。任何响应均不含私钥材料。

## 命令行

`gen` / `show` / `rotate` / `version` / `current` 与上述接口一一对应，均打印
单行 JSON，字段名与 HTTP 响应完全一致：

```bash
python -m keymgr --data-dir ./keymgr_data gen \
  --tenant-id tenant-a --algorithm RSA2048 --label "my key"
python -m keymgr --data-dir ./keymgr_data show \
  --tenant-id tenant-a --key-id <key_id>
python -m keymgr --data-dir ./keymgr_data rotate \
  --tenant-id tenant-a --key-id <key_id> --algorithm AES256
python -m keymgr --data-dir ./keymgr_data version \
  --tenant-id tenant-a --key-id <key_id> --version 1
python -m keymgr --data-dir ./keymgr_data current \
  --tenant-id tenant-a --key-id <key_id>
```

## 基础测试

```bash
python -m compileall -q keymgr                       # 语法编译检查
python -c "from keymgr.crypto import generate_key; generate_key('AES256'); generate_key('RSA2048')"
curl -s -X POST http://127.0.0.1:8080/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"a","algorithm":"AES256","label":"t"}'
```

## 持久化与安全说明

- 每个密钥以 `<key_id>.json` 原子落盘（权限 `0600`），内含不可变版本数组
  `versions`（每版保存创建时间、算法、公钥、私有材料）与当前指针
  `current_version`；旧版本只读、永不覆盖。重启后历史版本、当前指针、
  `label`、各版 `created_at` 与公钥均可读，且不随重启改变。旧版单版本
  文件格式会在读取时自动迁移为版本 1。
- 轮换在每 key 的互斥锁（进程内锁 + `flock`）下执行读-改-写，版本号严格
  递增、材料重新生成且不复用；并发轮换不会丢版本或留下悬空指针。写入失败
  只丢弃临时文件，旧数据保持不变。
- 私钥仅保存在服务端：RSA 为 PKCS8 PEM、AES 为 base64；响应投影不包含私钥字段。
- `key_id` 为 UUID4，读取时校验格式以杜绝路径穿越；跨租户访问一律 `404`，不泄露密钥是否存在。
