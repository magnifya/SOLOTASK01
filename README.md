# SOLOTASK01 多租户密钥管理后端

一个多租户密钥管理服务，同时提供 HTTP API 与命令行入口。支持 AES256 / RSA2048
密钥的生成、版本化轮换、吊销、加密导出/导入、租户级加密备份/恢复、按租户的
操作者策略、只追加的审计账，以及可插拔的 KMS/HSM 提供者。轮换/导入/恢复是
幂等变更：同一 `Idempotency-Key` 的重试只重放原结果，进程在任一步骤崩溃后
重启都能据 `operation_id` 判定是否已耐久并一致收尾。私钥只保存在服务端，
任何响应与审计投影都不含私钥、句柄或包装材料。

## 依赖与安装

Python 3.10+，仅一个运行时依赖：

```bash
pip install -r requirements.txt   # cryptography>=3.4
```

## 启动

```bash
python -m keymgr --data-dir ./keymgr_data serve --host 127.0.0.1 --port 8080
```

数据目录也可用环境变量 `KEYMGR_DATA_DIR` 指定（CLI 默认 `keymgr_data`）。
提供者由 `KEYMGR_PROVIDER` 选择（缺省或 `local` 为内置本地提供者，其它值为
`module:factory`，首次使用时才惰性加载，绝不回退本地）。

## 基础测试

```bash
python -m compileall -q keymgr
python3 -c "from keymgr.crypto import generate_key; generate_key('AES256'); generate_key('RSA2048')"
curl -s -X POST http://127.0.0.1:8080/v1/keys \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"a","algorithm":"AES256","label":"t"}'
```

## 通用约定

- 除 `serve` 外每个请求都需单一非空头 `X-Operator-Id: <operator>`（CLI 为
  必填 `--operator`）；缺失/为空/重复均 `400`（CLI 退出 `2`）。操作者既是
  审计主体也是策略 `subject`。
- 租户来源：单一 `X-Tenant-Id` 头或单一 `?tenant_id=` 参数；允许 body 携带
  `tenant_id` 的端点，头/参数/体必须一致。缺失、重复、冲突均 `400` 且错误指
  `tenant_id`，并记一条任何租户都不可见的 `tenant_conflict` 事件（幂等端点在
  幂等键绑定**之前**的参数/解析错误例外：不写任何审计、操作、密钥或句柄）。
- 错误 HTTP 状态与 CLI 退出码：`400→2`、`403→3`、`409→3`、`404→4`、
  `500/503→1`；成功 `0`。普通错误体仅 `{"error": ...}`；幂等变更的错误体仅
  `{"error", "operation_id"}`，成功体额外含 `operation_id`。
- `key_id` 为小写 UUID4，非法值是 `400`；未知对象与跨租户访问统一 `404`，
  不泄露存在性。

## HTTP 接口

- `POST /v1/keys`，body `{tenant_id, algorithm, label}`，`algorithm` 仅
  `AES256`/`RSA2048`。`201` → `{key_id, algorithm, public_key}`（AES 的
  `public_key` 为 null，RSA 为 PEM）。
- `GET /v1/keys/{key_id}` → `{algorithm, label, created_at, public_key}`。
- `POST /v1/keys/{key_id}/rotate`，body `{tenant_id, algorithm}`，需
  `Idempotency-Key`。`201` → `{key_id, version, algorithm, public_key,
  operation_id}`，版本严格递增、只追加。
- `POST /v1/keys/batch-rotate`，body
  `{tenant_id, items:[{key_id, algorithm}, ...]}`，需 `Idempotency-Key`。
  `items` 限 1–100 项，`key_id` 必须是互不重复的小写 UUID4，`algorithm`
  仅 `AES256`/`RSA2048`；任一不合法均为绑定前 `400`，零副作用。按
  `rotate` 授权（`403` 拒绝）；任一 `key_id` 未知或属其它租户一律 `404`，
  整批零变更。整批原子，`201` →
  `{items:[{key_id, version, algorithm, public_key}, ...], operation_id}`，
  `items` 严格按请求序；每个 key 沿用单键 rotate 语义（版本严格递增）。
- `GET /v1/keys/{key_id}/versions/{version}` 与
  `GET /v1/keys/{key_id}/current` →
  `{key_id, version, created_at, algorithm, public_key}`；version 须为正整数。
- `POST /v1/keys/{key_id}/revoke`，body `{tenant_id, reason, operator}` →
  `{key_id, status, reason, operator, revoked_at}`；重复/并发吊销幂等，保留
  首次值。
- `GET /v1/keys/{key_id}/status`：字段同 revoke；active 时后三项为 null。
- `POST /v1/keys/{key_id}/export`，body `{tenant_id, passphrase}` →
  `{format:"keymgr-export-v1", bundle}`，bundle 为不透明 base64（scrypt +
  AES-256-GCM，`format` 作为 AAD）。
- `POST /v1/keys/import`，body `{tenant_id, passphrase, bundle}`，需
  `Idempotency-Key`。`201` → `{key_id, algorithm, public_key, operation_id}`，
  保留原 key_id、全部版本、label、current 与吊销状态。同租户已有 key_id 为
  `409`，key_id 被其它租户占用为 `404`；口令/篡改/格式错误为 `400` 且不占用
  幂等键。
- `POST /v1/backup`，body `{tenant_id, passphrase}` →
  `{format:"tenant-backup-v1", bundle}`；载荷
  `{format, tenant_id, keys, policy}`，空租户为 `keys:[]、policy:null`。
- `POST /v1/restore`，body `{tenant_id, passphrase, bundle}`，需
  `Idempotency-Key`。校验顺序：参数/解密/格式 `400` → 授权 `403` → 包内
  tenant 不符 `404` → 同租户 key_id/策略冲突 `409`（绝不覆盖既有策略）→
  多文件原子恢复 `201` → `{tenant_id, key_ids, policy_restored,
  operation_id}`。空包同样成功（`key_ids:[]`、`policy_restored:false`）。
- `GET /v1/policy` / `PUT /v1/policy` / `DELETE /v1/policy`：读/替换/删除
  租户策略，见下。
- `GET /v1/audit`：本租户审计查询，见下。
- `GET /v1/operations/{operation_id}`：查询幂等操作，见下。

## 幂等操作

- rotate/batch-rotate/import/restore（CLI：`rotate`/`batch-rotate`/
  `import`/`restore`）必须携带**单一** `Idempotency-Key` 头（CLI 必填
  `--idempotency-key`），值为 1–128 个 `[A-Za-z0-9._~-]` 字符。缺失、为
  空、重复、非法一律 `400`（CLI `2`），且该校验先于请求体读取与一切
  业务：不写审计、操作记录、密钥或提供者句柄。
- 键全局唯一，绑定记录 `operation_id`(UUID4)、租户、操作者、路径、规范化体
  （键排序紧凑 JSON）、状态、HTTP 状态与响应；存于 `operations/<id>.json`
  (0600) 与 `operations/index.json`，进程内锁 + `operations.lock` 的 fcntl
  排他锁串行化。
- 相同绑定重试：直接重放首次状态码、响应体与审计事件（同一
  `operation_id`，业务不执行第二次）。同键不同绑定：`409`（CLI `3`），错误
  体给出已有 `operation_id`。绑定前的导入/恢复解密无副作用：口令错误 `400`
  不占用该键。
- 状态：`pending`/`succeeded`/`failed`/`conflict`/`timed_out`。成功为 `201`
  succeeded；同租户冲突为 `409` conflict；`403/404/400` 与提供者/账本失败为
  failed（保留原状态码）。并发同键仅一个执行，其余等待；等待超 5 秒返回
  `503` timed_out（CLI `1`），等待方不写任何东西。
- `operation_id` 即该变更审计事件的 `event_id`，因此每个终态至多一条事件，
  HTTP 与 CLI 共用同一套记录，可跨入口用相同键重放或按 id 查询。
- **崩溃一致性**：进程可在绑定、outbox 落盘、账本追加或清理任一步骤崩溃。
  重启（或任一 CLI 入口）在 key/restore outbox 恢复之后，按同一
  `operation_id` 判定：事件已入帐即已提交，据耐久事实重建原 `201`/`403`/
  `404`/`409` 响应与审计投影并置终态（拒绝终态的状态码随事件持久化，严格
  重放）；事件未入帐则置 failed(`500`)，半成品文件、提供者句柄与标记由
  outbox/provision 恢复回滚。不重复记账（账本按 event_id 去重），不误判。
- `GET /v1/operations/{operation_id}`：需单一操作者与单一租户来源；操作须
  同时属于该租户与操作者，否则一律 `404`。`200` →
  `{operation_id, tenant_id, status, http_status, response}`，pending 时后两
  项为 null。CLI：`operation --tenant-id --operator --operation-id`。

## 策略

- `GET/PUT/DELETE /v1/policy`，租户由单一头或单一参数提供（PUT 也可由 body
  的 `tenant_id` 提供，来源须一致）。GET → `{tenant_id, rules}`（无策略
  `404`）；PUT body `{tenant_id, rules}` 整体替换；DELETE 幂等，→
  `{tenant_id, deleted:true}`。
- 规则元素 `{subject, actions, effect}`：`subject` 为区分大小写的非空字符串；
  `actions` 为非空数组，取值
  `create/read/rotate/revoke/import/export/audit`，单条内重复去重；`effect`
  为 `allow`/`deny`；未知字段、类型错误、同 subject+effect+无序动作集的重复
  规则均 `400`；`rules:[]` 合法（全拒绝）。
- 执行：管理动作 policy_* 免检；租户无策略时全部允许；有策略时匹配规则中
  deny 优先于 allow，无匹配则拒绝 → `403`，并记一条原动作名、
  `outcome=rejected`、携带当时已知 `key_id` 的事件（create/解密前的 import/
  audit 查询为 null）。参数校验先于授权，授权先于存在性判断。

## 审计

- 事件字段 `{event_id, tenant_id, action, key_id, outcome, timestamp}`；
  `action` 为 `create/read/rotate/batch_rotate/revoke/import/export/audit/
  tenant_conflict/policy_read/policy_update/policy_delete`，`outcome` 为
  `success/rejected`。批量轮换每个已绑定终态至多一条 `batch_rotate`
  事件（`event_id` 与 `operation_id` 同值，`key_id` 恒为 null），可按
  `action=batch_rotate` 筛选；绑定前的 `400` 与等待超时不写任何事件。
  备份记 `export`、恢复记 `import`，两者 `key_id` 均为 null；恢复的所有
  事件（含成功）`key_id` 为 null。
- `GET /v1/audit`：单一租户来源；可选 `key_id`(UUID4)、`action`、
  `limit`(1–1000，默认 100)、`cursor`。→ `{events, next_cursor}`，按
  (timestamp, event_id) 升序；游标为 HMAC 签名令牌，绑定租户/筛选/快照，
  被篡改或条件变化为 `400`。查询成功不记账，被策略拒绝才记一条
  `audit/rejected`（key_id null）。
- 账本为数据目录 `audit.log`（每行一个 JSON，只追加，进程内锁 +
  `audit.log.lock` fcntl 串行并 fsync，seq 单调）。变更走 outbox 事务：密钥
  /策略文件先携带待提交事件原子落盘 → 耐久追加账本（提交点）→ 清标记；账本
  失败回滚文件并删除本次新建句柄，返回 `500`（CLI `1`）；崩溃后启动按标记/
  event_id 幂等补记或回滚，不重不漏。恢复是多文件 outbox（标记带
  `"_restore":true` 与写集清单），只追加一条 `import` 事件。

## 命令行

所有子命令除 `serve` 外都需 `--operator`，租户命令需 `--tenant-id`；输出为
单行 JSON，字段与对应 HTTP 响应一致。

```bash
# 密钥
python -m keymgr gen      --tenant-id t --algorithm RSA2048 --label k --operator alice
python -m keymgr show     --tenant-id t --key-id <id> --operator alice
python -m keymgr current  --tenant-id t --key-id <id> --operator alice
python -m keymgr version  --tenant-id t --key-id <id> --version 1 --operator alice
python -m keymgr rotate   --tenant-id t --key-id <id> --algorithm AES256 \
                          --operator alice --idempotency-key rotate-0001
python -m keymgr batch-rotate --tenant-id t --operator alice \
                          --idempotency-key batch-0001 \
                          --items '[{"key_id":"<id1>","algorithm":"AES256"},{"key_id":"<id2>","algorithm":"RSA2048"}]'
python -m keymgr revoke   --tenant-id t --key-id <id> --reason r --operator alice
python -m keymgr status   --tenant-id t --key-id <id> --operator alice
# 导出/导入、备份/恢复
python -m keymgr export   --tenant-id t --key-id <id> --passphrase pw --operator alice
python -m keymgr import   --tenant-id t --passphrase pw --bundle <b> \
                          --operator alice --idempotency-key import-0001
python -m keymgr backup   --tenant-id t --passphrase pw --operator alice
python -m keymgr restore  --tenant-id t --passphrase pw --bundle <b> \
                          --operator alice --idempotency-key restore-0001
# 审计 / 操作 / 策略
python -m keymgr audit    --tenant-id t --action rotate --limit 100 --operator alice
python -m keymgr operation --tenant-id t --operator alice --operation-id <id>
python -m keymgr policy --operator admin set|show|delete --tenant-id t [--rules '<json>']
```

## KMS/HSM 提供者

- 工厂返回对象须有非空 `provider_id`、`capabilities`
  （algorithms 含 AES256/RSA2048；operations 含
  generate/rotate/import_material/export_material/delete）及这五个方法。
  generate/rotate/import_material → `{handle, public_key, encrypted_material}`；
  export_material(handle) → `{public_key, encrypted_material}`；delete(handle)
  幂等。模块缺失/工厂失败/契约不符/后端异常一律 `503`（CLI `1`），固定文案
  "key management provider is unavailable"，绝不回退；导入材料不符算法（AES
  非 32 字节、RSA 公私钥不匹配等）为 `400`，错误只指名字段。
- 本地提供者用 `local.dek`(0600) 以 AES-256-GCM 包装材料，句柄与包装材料登
  记在 `local-registry.json`(0600)；密钥文件每个版本只存
  `{provider_id, handle, encrypted_material}` 三元组，导出包/备份包版本额外
  带 `provider` 来源块，旧 `keymgr-export-v1` 包无来源块时按本地处理。
- 轮换/导出/导入/恢复必须命中记录登记的 provider：记录属于未激活提供者，或
  导入/恢复来源块与当前提供者不符，均 `503`，不静默切换。
- 启动时安全扫描旧记录：仅当本地提供者活动时，把裸 `private_material`/空句
  柄的旧版本校验并包装为本地对象，先包装后原子重写，失败保持原文件字节不
  变（新建句柄随即释放，不影响启动）；配置了外部提供者时启动与普通读取既不
  加载提供者也不改写旧记录（此类记录在导出/轮换时 `503`）。

## 持久化与限制

- 每个密钥为数据目录下 `<key_id>.json`（0600，fsync + 原子 rename），含
  append-only `versions` 与 `current_version`；轮换在 per-key 进程内锁 +
  `<key_id>.lock` fcntl 锁下读改写，并发不丢版本、不悬指针。
- 批量轮换与单键轮换/导入/恢复按 `key_id` 序共用同一套 per-key 锁（先取全
  部锁再铸句柄）：批量内多个 key 及与并发的单键操作之间跨进程串行，固定获
  锁顺序避免死锁；5 秒内拿不到任一把锁即 `503 timed_out`，等待方不写任何
  密钥、事件或句柄。
- 批量轮换是多文件 outbox：每个参与文件先携带同一 `_batch_rotate` 标记
  （共享事件 + 每键新版本清单，可含 provision journal 引用）落盘，再追加唯
  一一条 `batch_rotate` 事件（提交点），随后清标记；提交前任一步失败/崩溃
  都把各文件回滚到旧版本并删除全部新铸句柄。启动恢复时事件已入帐则保留版
  本清标记；未入帐则**先**确认删除整批句柄（无 journal 的旧批次改从标记文
  件的新版本列句柄）——提供者不可达或任一句柄删除无法确认时整组文件、标记
  与 journal 全部保留，下次启动重试——全部删除确认后才截断新版本。
- 旧 restore 无 journal 的未提交组：从携带 `_restore` 标记的密钥文件列出全
  部句柄并在删除任何文件前严格删除；提供者不可达或任一 delete 失败则保留整
  组密钥文件、策略文档与标记，启动重试，全部句柄确认删除后才移除密钥与策略
  标记。
- 导入/恢复在提供者调用前先建按 event_id 命名的 provision journal，每铸一个
  句柄即耐久登记；提交后句柄归记录所有并删除 journal，未提交（冲突、提供者
  故障、账本失败、崩溃）则幂等删除全部已铸句柄，不留孤儿后端对象。
- 私钥与口令只存在于口令加密的包内或经提供者包装后的记录中；游标 HMAC 密钥
  存于 `audit.secret`(0600)。材料不会出现在任何响应、审计投影或错误信息中。
