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
  `{"key_id", "algorithm", "public_key"}`（RSA 返回 PEM 公钥，AES 返回 `null`）。
- `GET /v1/keys/{key_id}`，用请求头 `X-Tenant-Id: <tenant>` 标识租户
  （也支持 `?tenant_id=<tenant>` 查询参数）。成功返回 `200`：
  `{"algorithm", "label", "created_at", "public_key"}`（current 版本的材料）。
- `POST /v1/keys/{key_id}/rotate`，请求体 `{"tenant_id", "algorithm"}`，
  `algorithm` 仅支持 `AES256` / `RSA2048`；也接受与 body 一致的
  `X-Tenant-Id` / `?tenant_id=`。每次轮换生成**全新材料**、版本号严格递增
  且不复用，`label` 沿用原 key。成功返回 `201`：
  `{"key_id", "version", "algorithm", "public_key"}`。
- `GET /v1/keys/{key_id}/versions/{version}`：读取指定历史版本，`version`
  必须是正整数。成功返回 `200`：
  `{"key_id", "version", "created_at", "algorithm", "public_key"}`。
- `GET /v1/keys/{key_id}/current`：读取当前版本，字段同上。
- `POST /v1/keys/{key_id}/revoke`：吊销密钥。请求体 JSON 含非空字符串
  `tenant_id`、`reason`、`operator`；`X-Tenant-Id` / `?tenant_id=` 可选，
  但与 body 冲突时返回 400 并指明 `tenant_id`。吊销把 `active` 置为
  `revoked`，保存首次的 `reason`、`operator` 与 UTC `revoked_at`；重复或
  并发吊销幂等，保留首值。成功返回 `200`：
  `{"key_id", "status": "revoked", "reason", "operator", "revoked_at"}`。
- `GET /v1/keys/{key_id}/status`：查询吊销状态，租户来自 `X-Tenant-Id`
  或 `?tenant_id=`（两者同时给出须一致）。返回 `200`：
  `{"key_id", "status", "reason", "operator", "revoked_at"}`；
  `active`（含无状态字段的旧记录）时后三项为 `null`。
- 缺少必填字段、algorithm 不支持、version 非正整数、或
  header/query/body 提供了互相冲突的租户参数，返回 `400`，错误信息指明
  具体字段；未知 key、未知版本及跨租户访问统一返回 `404`。任何响应均不含
  私钥材料。

### 版本与轮换

每个 key 的首个版本为 `1`；每个版本独立保存创建时间、算法、公钥与私有材料，
历史版本只追加、不可覆盖。`current` 指针始终指向最新版本。轮换在
per-key 锁（进程内锁 + `fcntl` 跨进程锁）保护下做读-改-写并原子落盘，
因此并发轮换不会丢版本、不会留下悬空指针；写入失败只丢弃临时文件，
旧数据保持完整。重启后版本历史、当前指针、`label`、各版本时间与公钥均可读。

## 命令行

`gen` / `show` 与上述接口一一对应，均打印单行 JSON，字段名与 HTTP 响应完全一致：

```bash
python -m keymgr --data-dir ./keymgr_data gen \
  --tenant-id tenant-a --algorithm RSA2048 --label "my key"
python -m keymgr --data-dir ./keymgr_data show \
  --tenant-id tenant-a --key-id <key_id>
```

版本与轮换命令同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 轮换：输出 {"key_id","version","algorithm","public_key"}
python -m keymgr --data-dir ./keymgr_data rotate \
  --tenant-id tenant-a --key-id <key_id> --algorithm AES256
# 指定历史版本：输出 {"key_id","version","created_at","algorithm","public_key"}
python -m keymgr --data-dir ./keymgr_data version \
  --tenant-id tenant-a --key-id <key_id> --version 1
# 当前版本：字段同 version
python -m keymgr --data-dir ./keymgr_data current \
  --tenant-id tenant-a --key-id <key_id>
```

吊销与状态查询同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 吊销：输出 {"key_id","status","reason","operator","revoked_at"}
python -m keymgr --data-dir ./keymgr_data revoke \
  --tenant-id tenant-a --key-id <key_id> --reason compromised --operator alice
# 状态：字段同上；active 时 reason/operator/revoked_at 为 null
python -m keymgr --data-dir ./keymgr_data status \
  --tenant-id tenant-a --key-id <key_id>
```

未知 key/版本或跨租户访问以退出码 `4` 报错；非法 algorithm / version
（非正整数）、空 `reason` / `operator` 等参数错误以退出码 `2` 报错，
错误信息指明字段。

## 基础测试

```bash
python -m compileall -q keymgr                       # 语法编译检查
python -c "from keymgr.crypto import generate_key; generate_key('AES256'); generate_key('RSA2048')"
curl -s -X POST http://127.0.0.1:8080/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"a","algorithm":"AES256","label":"t"}'
```

## 持久化与安全说明

- 每个密钥以 `<key_id>.json` 原子落盘（权限 `0600`）：文件内含 append-only
  的 `versions` 数组与 `current_version` 指针。旧版本不可覆盖，重启后历史、
  当前指针、`label`、各版本时间与公钥均可读，时间戳不随重启改变。
- 轮换在 per-key 锁（进程内锁 + `<key_id>.lock` 上的 `fcntl` 排他锁）保护下
  读-改-写，并经 fsync + `os.replace` 原子提交：并发不丢版本、指针不悬空，
  写入失败只清理临时文件而不破坏旧数据。
- 私钥仅保存在服务端：RSA 为 PKCS8 PEM、AES 为 base64；所有响应投影
  （create/get/rotate/version/current）都不包含私钥字段。
- `key_id` 为 UUID4，读取时校验格式以杜绝路径穿越；未知 key、未知版本与
  跨租户访问一律 `404`，不泄露密钥是否存在。
