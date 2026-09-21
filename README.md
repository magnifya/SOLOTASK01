# SOLOTASK01 多租户密钥管理后端

多租户密钥管理服务，同时提供 HTTP API 与命令行（CLI）。密钥由可插拔提供者（默认本地软件提供者）持有，明文私钥从不出现在密钥文件、响应或审计投影中；变更操作支持幂等与崩溃恢复。技术栈仅 Python 3.10+ 与 [`cryptography`](https://pypi.org/project/cryptography/)，无其他运行时依赖。

## 安装

```bash
pip install -r requirements.txt   # cryptography>=3.4, Python 3.10+
```

## 启动

```bash
python -m keymgr --data-dir ./keymgr_data serve --host 127.0.0.1 --port 8080
```

数据目录也可用环境变量 `KEYMGR_DATA_DIR` 指定；提供者用 `KEYMGR_PROVIDER` 选择（缺省或 `local` 为内置本地提供者，其它值须为 `module:factory`，首次使用时惰性加载，失败一律 503、绝不回退本地）。

## 基础测试

```bash
python -m compileall -q keymgr
python -c "from keymgr.crypto import generate_key; generate_key('AES256'); generate_key('RSA2048')"
curl -s -X POST http://127.0.0.1:8080/v1/keys -H 'X-Operator-Id: alice' \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"a","algorithm":"AES256","label":"t"}'
```

## 通用约定

- 除 `serve` 外，每个请求/命令必须提供单一非空操作者：HTTP 头 `X-Operator-Id`，CLI 全局 `--operator`（必填、非空）；缺失/为空/重复为 400（CLI 退出 2）。
- 租户来源：`X-Tenant-Id` 头（单一）或 `?tenant_id=`（单一）；body 内 `tenant_id` 与之必须一致。两者冲突、重复、缺失、为空均 400 且错误指明 `tenant_id`，并记一条任何租户都不可见的 `tenant_conflict` 事件（幂等三端点**绑定前**除外，见下）。
- `key_id` 为小写规范 UUID4，非法为 400（非 404），防止路径穿越与存在性探测。
- 错误响应一律 `{"error": ...}`；幂等变更的错误体只含 `error` 与 `operation_id`。任何响应、审计投影均不含私钥、句柄或材料。
- 状态码：参数错误 `400`；策略拒绝 `403`；未知/跨租户对象 `404`；同租户冲突 `409`；提供者故障 `503`；账本/持久化失败 `500`。
- CLI 退出码：成功 `0`；参数错误 `2`；策略拒绝或同租户冲突 `3`；未知/跨租户 `4`；账本失败、提供者不可用、锁等待超时 `1`。CLI 一律打印单行 JSON，字段名与 HTTP 响应一致（错误打印到 stderr）。

## HTTP 接口

算法仅 `AES256`、`RSA2048`。

| 方法与路径 | 请求体 / 参数 | 成功响应 |
| --- | --- | --- |
| `POST /v1/keys` | `{tenant_id, algorithm, label}` | `201 {key_id, algorithm, public_key}`（AES 的 public_key 为 null，RSA 为 PEM） |
| `GET /v1/keys/{key_id}` | 头或 query 给租户 | `200 {algorithm, label, created_at, public_key}` |
| `POST /v1/keys/{key_id}/rotate` | `{tenant_id, algorithm}`，需 `Idempotency-Key` | `201 {key_id, version, algorithm, public_key, operation_id}` |
| `GET /v1/keys/{key_id}/versions/{v}` | v 为正整数 | `200 {key_id, version, created_at, algorithm, public_key}` |
| `GET /v1/keys/{key_id}/current` | 同上 | 字段同 versions |
| `POST /v1/keys/{key_id}/revoke` | 非空 `{tenant_id, reason, operator}` | `200 {key_id, status, reason, operator, revoked_at}`，重复吊销幂等保留首次值 |
| `GET /v1/keys/{key_id}/status` | 头或 query 给租户 | 同 revoke；active 时后三项为 null |
| `POST /v1/keys/{key_id}/export` | 非空 `{tenant_id, passphrase}` | `200 {format:"keymgr-export-v1", bundle}` |
| `POST /v1/keys/import` | 非空 `{tenant_id, passphrase, bundle}`，需 `Idempotency-Key` | `201 {key_id, algorithm, public_key, operation_id}`，保留原 key_id/全部版本/吊销状态 |
| `POST /v1/backup` | 非空 `{tenant_id, passphrase}` | `200 {format:"tenant-backup-v1", bundle}` |
| `POST /v1/restore` | 非空 `{tenant_id, passphrase, bundle}`，需 `Idempotency-Key` | `201 {tenant_id, key_ids, policy_restored, operation_id}`；空包成功时 `key_ids=[]`、`policy_restored=false` |
| `GET /v1/audit` | 见“审计” | `200 {events, next_cursor}` |
| `GET/PUT/DELETE /v1/policy` | 见“策略” | 见下 |
| `GET /v1/operations/{operation_id}` | 单一租户来源 + 操作者 | `200 {operation_id, tenant_id, status, http_status, response}`；pending 时后两项为 null |

未知 key/版本、跨租户访问统一 `404`，不泄露存在性。导入时该租户已有同 `key_id` 为 `409`（原记录不变），该 id 被其他租户占用为 `404`。恢复校验顺序：参数/解密/格式 `400` → 授权 `403`（import 动作）→ 包内 `tenant_id` 不符 `404` → 冲突检查：同租户已有任一 `key_id` 或已有策略文档为 `409`（绝不覆盖/删除既有策略），`key_id` 被他人占用为 `404`。

## 策略

- `GET /v1/policy`：单一头或单一参数给租户；不存在 `404`，成功 `200 {tenant_id, rules}` 并记 `policy_read`。
- `PUT /v1/policy`：`{tenant_id, rules}`，头/参数可选但须与 body 一致；成功 `200 {tenant_id, rules}` 并记 `policy_update`。
- `DELETE /v1/policy`：单一头或参数；幂等（不存在也算成功），`200 {tenant_id, deleted:true}` 并记 `policy_delete`。
- `rules` 元素为 `{subject, actions, effect}`：`subject` 为区分大小写的非空字符串；`actions` 为非空数组，取值 `create/read/rotate/revoke/import/export/audit`，单规则内重复去重；`effect` 为 `allow`/`deny`；未知字段、类型错误、同 subject+effect+无序动作集重复均 `400`；`rules:[]` 合法（全拒绝）。
- 执行（policy 管理端点免检）：无策略=全允许；有策略时匹配规则中 deny 优先于 allow，无匹配=拒绝。拒绝返回 `403`，并记原动作名、`outcome=rejected`、当时已知 `key_id`（create、解密前 import、audit 查询为 null）。参数校验（400）先于授权，授权先于存在性判断。

## 幂等变更（rotate / import / restore）

- 必须携带**单一** `Idempotency-Key` 头（CLI 必填 `--idempotency-key`），值为 1–128 个 ASCII 字符且仅限 `[A-Za-z0-9._~-]`。
- **先校验头，再解析请求体与执行业务**：头缺失/为空/重复/非法，以及请求体解析失败或任何绑定前参数/解密错误（租户、字段、algorithm、passphrase、bundle 等），一律 `400`（CLI `2`）且**零副作用**——不写审计、不建操作记录、不写密钥、不铸造提供者句柄，且不占用该键（口令错误后用同键改正仍可成功）。
- 键全局唯一地绑定一次操作（记录其租户、操作者、路径、键排序紧凑 JSON 规范化体、状态、HTTP 状态、响应体），存于 `operations/<operation_id>.json`（0600）与 `operations/index.json`，由进程内锁 + `operations.lock` 的 fcntl 排他锁串行化。
- 相同绑定重试：直接重放首次的状态码、响应体与审计事件（同一 `operation_id`，业务绝不执行第二次）。成功与错误响应都带 `operation_id`；错误体只含 `error` 与 `operation_id`。
- 同键不同绑定（租户/操作者/路径/体不同）：`409`（CLI `3`），错误体给出**已有** operation_id，不执行新请求。
- 终态：成功 `201/succeeded`；策略拒绝 `403`、未知或跨租户 `404`、同租户冲突 `409/conflict`（CLI `3`）、提供者故障 `503`、账本失败 `500`（后四类状态记 `failed`）。
- 每个终态至多写一条审计事件，`event_id == operation_id`：成功事件随 outbox 提交，拒绝（403/404/409）事件记原动作、请求租户、准确 key_id（restore 始终为 null）、`outcome=rejected`。
- 并发同键仅一个请求执行，其余等待首个终态；等待超 5 秒返回 `503 timed_out`（CLI `1`），等待方不写任何内容。
- `GET /v1/operations/{id}`（CLI `operation`）：操作须同时属于该租户与操作者，未知/非法/跨租户/跨操作者一律 `404`。
- **崩溃一致性**：进程可能在绑定、outbox、写账或清理任一步崩溃。重启（服务启动或任意 CLI 调用）先完成 key/restore 的 outbox 恢复，再按 `operation_id`（即事件 id）收尾：事件已耐久则判定已提交，重建原 201 响应与审计投影并置终态；事件未入帐则判定未提交，回滚半成品文件、提供者句柄与标记并置 `failed(500)`。重试只重放原状态，不会误判或重复记账；HTTP 与 CLI 共用同一套操作记录。

## 审计

- 事件字段：`{event_id, tenant_id, action, key_id, outcome, timestamp}`；action ∈ `create/read/rotate/revoke/import/export/audit/tenant_conflict/policy_read/policy_update/policy_delete`，outcome ∈ `success/rejected`。租户备份记 `export`、恢复记 `import`，二者 key_id 均为 null。
- `GET /v1/audit`（CLI `audit`）：单一头或参数给租户；可选 `key_id`（须 UUID4）、`action`（上述 11 值）、`limit`（默认 100，1–1000）、`cursor`。事件按 `(timestamp, event_id)` 升序，分页不重不漏；游标为 HMAC 签名的不透明令牌，绑定租户、筛选、limit 与可见集快照，篡改/改条件/快照变化均 400。审计查询成功不记账，仅被策略拒绝时记 `audit/rejected/key_id=null`。

## CLI

`python -m keymgr --data-dir DIR <command> ...`。除 `serve` 外均需 `--operator`。子命令：`gen`、`show`、`version`、`current`、`rotate`、`revoke`、`status`、`export`、`import`、`backup`、`restore`、`audit`、`operation`、`policy show|set|delete`。`rotate/import/restore` 另需 `--idempotency-key`；`policy set` 需 `--rules '<json array>'`。输出为与 HTTP 同字段的单行 JSON。示例：

```bash
python -m keymgr --data-dir D gen  --tenant-id a --algorithm AES256 --label k --operator alice
python -m keymgr --data-dir D rotate --tenant-id a --key-id <id> --algorithm AES256 \
    --operator alice --idempotency-key rot-1
python -m keymgr --data-dir D import --tenant-id b --passphrase pw --bundle '<b64>' \
    --operator alice --idempotency-key imp-1
python -m keymgr --data-dir D restore --tenant-id b --passphrase pw --bundle '<b64>' \
    --operator alice --idempotency-key res-1
python -m keymgr --data-dir D operation --tenant-id b --operator alice --operation-id <id>
```

## 包格式与提供者

- 单 key 包 `keymgr-export-v1` 与租户包 `tenant-backup-v1` 均为不透明单层 base64：随机盐 scrypt（固定成本参数）派生 AES-256-GCM 密钥，随机 nonce，`format` 作为 AAD；两类包不可互换。口令错误或篡改在 GCM 认证处失败（400），KDF 只接受本服务的固定参数集。载荷逐字段校验，错误指出 `passphrase`/`bundle`/`versions[i].*`/`keys[i].*` 等具体字段。
- 每个版本含 `provider:{provider_id, handle, encrypted_material}` 来源块；旧 `keymgr-export-v1` 包无此块时按本地提供者处理。导入/恢复对来源块逐字段校验（格式错误 400、不落盘、不留半成品），材料不符算法为 400（只指名字段、不含材料）。记录属于未激活提供者、或来源块与当前提供者不符时为 503，不静默切换。
- 本地提供者用数据加密密钥 `local.dek`（0600）做 AES-256-GCM 包装，句柄与包装材料登记于 `local-registry.json`（0600，仅含包装材料）。**服务启动时**在本地提供者活动前提下，把提供者层之前的旧记录（裸 `private_material`、空句柄）逐记录校验并一次性原子包装登记；任一记录校验/写盘失败则该文件原样保留并释放新铸句柄，不影响其它记录与启动；配置了外部提供者或不存在旧记录时启动不加载任何提供者，普通读取也不会加载或改写提供者。
- 一次 generate/rotate/import 先向提供者换三元组再走 outbox；账本失败（500）回滚密钥文件并尽力 `delete(handle)` 清理新建对象（不掩盖账本错误）。

## 持久化与安全限制

- 每密钥一个 `<key_id>.json`（0600，fsync + `os.replace` 原子落盘），`versions` 只追加、`current_version` 指向最新；轮换在 per-key 进程内锁 + `<key_id>.lock` fcntl 锁下读改写，并发不丢版本、不留悬空指针。吊销状态随记录原子落盘，重启不变。
- 变更（生成/轮换/吊销/导入/恢复）与其审计事件在同一逻辑 outbox 事务：文件先携带待提交事件落盘 → durable 追加 `audit.log`（每行一 JSON，由进程内锁 + `audit.log.lock` 串行化并 fsync，按 event_id 幂等去重、`seq` 单调）→ 清标记。账本失败回滚文件与句柄并返回 500/CLI 1；崩溃后启动按标记幂等补记或回滚，不重不漏。策略 PUT/DELETE 用同一 outbox（DELETE 经 `*.json.del` 墓碑）。
- 租户恢复是多文件 outbox 事务：所有 key 文件与至多一个策略文件先携带同一待提交事件与写集清单（`"_restore": true`）落盘，再只追加一条 `action=import、key_id=null` 事件，最后统一清标记；账本失败删除本次全部新建文件与句柄（既有文件绝不被覆盖），崩溃后启动按 event_id 分组幂等提交或整体回滚。空包用 `restore-empty-<sha256(tenant_id)>.json` 标记保证至多提交一次。
- 游标 HMAC 密钥存于 `audit.secret`（0600）。所有租户隔离均在服务端强制；任何响应、事件、查询投影都不包含私钥材料。
