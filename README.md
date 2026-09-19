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
  但必须与 body 的 `tenant_id` 一致，冲突返回 `400` 且错误指明
  `tenant_id`。吊销把状态从 `active` 置为 `revoked`，并保存首次的
  `reason`、`operator` 与 UTC `revoked_at`。成功返回 `200`：
  `{"key_id", "status", "reason", "operator", "revoked_at"}`。
  重复或并发吊销幂等：保留首次的值。
- `GET /v1/keys/{key_id}/status`：查询吊销状态，租户来自 `X-Tenant-Id`
  或 `?tenant_id=`（两者同时给出必须一致）。返回 `200`：
  `{"key_id", "status", "reason", "operator", "revoked_at"}`；
  `active`（含无状态字段的旧记录）时后三项为 `null`。
- `POST /v1/keys/{key_id}/export`：加密导出整把密钥。请求体 JSON 含非空
  字符串 `tenant_id`、`passphrase`；可附与 body 一致的 `X-Tenant-Id` /
  `?tenant_id=`（冲突返回 `400` 且指明 `tenant_id`）。成功返回 `200`：
  `{"format":"keymgr-export-v1","bundle": <不透明 base64>}`。bundle 以
  passphrase 经 scrypt 派生密钥后用 AES-256-GCM 认证加密，内含 `label`、
  全部版本（算法、时间、公钥、私有材料）、`current_version` 与吊销字段；
  私钥与口令只存在于加密包内，响应与审计投影均不泄露。未知 key / 跨租户
  统一 `404`。
- `POST /v1/keys/import`：从加密包导入。请求体 JSON 含非空字符串
  `tenant_id`、`passphrase`、`bundle`；同样接受与 body 一致的
  `X-Tenant-Id` / `?tenant_id=`。解密失败、密文被篡改、`format`/版本错误
  或缺字段返回 `400` 且错误指出具体字段（`passphrase` / `bundle` /
  `versions[i].xxx` 等），全程不落盘、不留半成品。成功返回 `201`：
  `{"key_id", "algorithm", "public_key"}`，并保留原 `key_id`、全部版本号、
  `current`、`label` 与吊销状态。该租户已有同一 `key_id` 返回 `409` 且原
  记录不变；`key_id` 已被其他租户占用时返回 `404`，跨租户不泄露存在性。
- `GET /v1/audit`：查询本租户的审计事件。租户由**单一** `X-Tenant-Id`
  头或**单一** `?tenant_id=` 参数提供；缺失、重复、为空或两者冲突均返回
  `400` 且错误信息指出 `tenant_id`。可选筛选：`key_id`（非 UUID4 返回
  `400`）、`action`（`create` / `read` / `rotate` / `revoke` / `import` /
  `export` / `tenant_conflict` 七值之一）、`limit`（默认 `100`，范围
  `1–1000`）、`cursor`（上一页返回的不透明游标）。返回
  `{"events", "next_cursor"}`，事件按 `timestamp`、`event_id` 升序；
  `next_cursor` 为 `null` 表示到末页。未知但合法的 `key_id` 返回空列表。
  游标绑定租户、筛选条件与快照：失效、被篡改或改变筛选/租户均返回 `400`
  且错误指出 `cursor`；分页保证不重不漏。审计查询本身不记账。
- 缺少必填字段、algorithm 不支持、version 非正整数、导入包口令/格式错误、或
  header/query/body 提供了互相冲突的租户参数，返回 `400`，错误信息指明
  具体字段；未知 key、未知版本及跨租户访问统一返回 `404`；同租户重复导入
  返回 `409`。任何响应均不含私钥材料。

### 版本与轮换

每个 key 的首个版本为 `1`；每个版本独立保存创建时间、算法、公钥与私有材料，
历史版本只追加、不可覆盖。`current` 指针始终指向最新版本。轮换在
per-key 锁（进程内锁 + `fcntl` 跨进程锁）保护下做读-改-写并原子落盘，
因此并发轮换不会丢版本、不会留下悬空指针；写入失败只丢弃临时文件，
旧数据保持完整。重启后版本历史、当前指针、`label`、各版本时间与公钥均可读。

## 审计

密钥的生成、读取（含当前版本、历史版本、状态查询）、轮换、吊销、导入与导出
都会写入持久化审计账。每条事件字段为 `event_id`、`tenant_id`、`action`、
`key_id`、`outcome`、`timestamp`（UTC）；`action` 为 `create` / `read` /
`rotate` / `revoke` / `import` / `export`，`outcome` 为 `success` /
`rejected`。

- 租户已确定且 `key_id` 合法时，事件同时记录两个标识，且仅该请求租户可见。
  未知或跨租户的访问（含导出、跨租户导入冲突）记为 `outcome=rejected`，
  只对请求租户可见，不泄露密钥归属。导入在解密成功前尚不知 `key_id`，
  这类拒绝事件的 `key_id` 为 `null`；未知但合法的 `key_id` 在审计查询中
  返回空。
- 租户缺失、为空、标识非法（`key_id` 非 UUID4）或头/查询/体提供的租户互相
  不一致时，记一条 `action=tenant_conflict`、`outcome=rejected` 的事件，
  其 `tenant_id` 与 `key_id` 均为 `null`，任何租户都查不到它。
- 审计账只追加，存于数据目录的 `audit.log`（每行一个 JSON）。变更（生成 /
  轮换 / 吊销 / 导入）与其事件在同一逻辑事务提交：先把事件作为待提交标记
  随密钥文件原子落盘，再 durable 追加账本，最后清除标记；账本写失败则回滚
  密钥文件并对 HTTP 返回 `500`、CLI 以退出码 `1` 失败，绝不允许单边落盘。
  导出只读，其审计事件随成功响应直接追加账本。进程在两步之间崩溃时，下次
  启动依据待提交标记幂等补记账本（按 `event_id` 去重）。
- 事件与查询投影均不含任何私钥材料。`GET /v1/audit` 自身不产生审计事件。


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
  --tenant-id tenant-a --key-id <key_id> --reason "compromised" --operator alice
# 状态：字段同 revoke；active 时 reason/operator/revoked_at 为 null
python -m keymgr --data-dir ./keymgr_data status \
  --tenant-id tenant-a --key-id <key_id>
```

加密导入 / 导出同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 导出：输出 {"format","bundle"}，bundle 为不透明 base64
python -m keymgr --data-dir ./keymgr_data export \
  --tenant-id tenant-a --key-id <key_id> --passphrase 'hunter2'
# 导入：输出 {"key_id","algorithm","public_key"}（201 的创建响应字段）
python -m keymgr --data-dir ./keymgr_data import \
  --tenant-id tenant-b --passphrase 'hunter2' --bundle '<bundle>'
```

导出、导入分别写 `action=export` / `action=import` 的审计事件。

审计查询同样打印单行 JSON，字段与 `GET /v1/audit` 响应一致
（`{"events","next_cursor"}`）：

```bash
# 查询本租户事件；--key-id / --action / --limit / --cursor 均可选
python -m keymgr --data-dir ./keymgr_data audit \
  --tenant-id tenant-a --action rotate --limit 100
# 用上一页输出里的 next_cursor 继续翻页（其为空串/null 时即末页）
python -m keymgr --data-dir ./keymgr_data audit \
  --tenant-id tenant-a --cursor '<next_cursor>'
```

非法的 `--key-id` / `--action` / `--limit` 或失效篡改的 `--cursor` 以
退出码 `2` 报错，错误信息指出具体字段。导出/导入的口令缺失、口令错误或
bundle 格式、版本、字段错误同样以退出码 `2` 报错。

未知 key/版本或跨租户访问以退出码 `4` 报错；非法 algorithm / version
（非正整数）、非法 `--key-id` / `--action` / `--limit` 或失效篡改的
`--cursor` 以退出码 `2` 报错，错误信息指明字段；同租户重复导入已存在的
`key_id` 以退出码 `3` 报错（对应 HTTP `409`，原记录不变）；审计账写失败
以退出码 `1` 失败（对应 HTTP `500`）。

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
  （create/get/rotate/version/current/revoke/status）都不包含私钥字段。
- 吊销状态（`status`、`reason`、`operator`、`revoked_at`）随密钥记录
  原子落盘，重启后保持不变；重复或并发吊销幂等，始终保留首次的值。
  无状态字段的旧记录按 `active` 处理。
- `key_id` 为 UUID4，读取时校验格式以杜绝路径穿越；未知 key、未知版本与
  跨租户访问一律 `404`，不泄露密钥是否存在。
- 导出包 `keymgr-export-v1` 为不透明的单层 base64 令牌：内部 JSON 信封记录
  `scrypt`（随机盐、固定成本参数）派生的 AES-256-GCM 密钥与随机 nonce，
  密文以 `format` 作为附加认证数据。口令错误或任何篡改都在 GCM 认证处失败，
  不会解出半截明文；KDF 参数只接受本服务发出的固定集合，拒绝伪造信封请求
  任意内存。解密后的载荷逐字段校验（`label`、连续 `1..N` 的版本、算法、
  公钥/私有材料、`current_version`、吊销字段），缺字段或版本错误以 `400`
  指出具体字段。导入沿用每 key 锁 + 原子落盘 + outbox 事务，账本失败回滚、
  崩溃幂等补记，重启后导入的全部版本与状态均可读。
- 审计账为数据目录下的 `audit.log`（每行一个 JSON，只追加），追加由进程内锁
  + `audit.log.lock` 上的 `fcntl` 排他锁串行化并 fsync，`seq` 单调不乱序。
  生成 / 轮换 / 吊销采用“密钥文件携带待提交事件 → 追加账本 → 清除标记”的
  outbox 事务：账本写失败回滚密钥文件，HTTP 返回 `500`、CLI 退出 `1`，
  变更与事件绝不单边落盘；崩溃后启动按标记幂等补记（按 `event_id` 去重）。
- 审计游标是 HMAC 签名的不透明令牌，密钥存于数据目录 `audit.secret`
  （权限 `0600`），绑定租户、筛选、`limit` 与该可见结果集的快照指纹；
  篡改、改租户/筛选或可见事件集变化都会令游标失效（`400` / 退出 `2`），
  其他租户的活动不影响本租户游标。事件按 `timestamp`、`event_id` 升序，
  分页不重不漏。审计事件与响应投影均不含私钥材料。
