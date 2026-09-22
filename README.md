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
  `items` 限 1–100 项，`key_id` 为不重复小写 UUID4，`algorithm` 仅
  AES256/RSA2048；任一非法 `400` 且在幂等键绑定**之前**零副作用（不写审计、
  操作、密钥或句柄）。按 `rotate` 授权：策略拒绝 `403`；任一 `key_id` 未知
  或属于其它租户则整批 `404`（不泄露跨租户存在性），皆零变更。`201` →
  `{items:[{key_id, version, algorithm, public_key}, ...], operation_id}`，
  items 严格按请求序；各 key 沿用单键 rotate 语义，整批原子提交（共享一把
  per-key 锁顺序、单一 provision/snapshot 记账、单条提交事件）。
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

- rotate/import/restore/batch-rotate（CLI：
  `rotate`/`import`/`restore`/`batch-rotate`）必须携带**单一**
  `Idempotency-Key` 头（CLI 必填 `--idempotency-key`），值为 1–128 个
  `[A-Za-z0-9._~-]` 字符。缺失、为空、重复、非法一律 `400`（CLI `2`），且该
  校验先于请求体读取与一切业务：不写审计、操作记录、密钥或提供者句柄。
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
- 多/单轮换互斥：批量轮换与单键 rotate 都按 `key_id` 排序获取 per-key
  进程内锁 + `<key_id>.lock` fcntl 排他锁（整批共享一个 5 秒截止时刻）。对同一
  key 的并发变更要么全在批量之前、要么全在之后；等待同一被占 key 超过 5 秒的
  批量返回 `503` timed_out 且零副作用（此时尚无 journal、事件或句柄）。
- `operation_id` 即该变更审计事件的 `event_id`，因此每个终态至多一条事件，
  HTTP 与 CLI 共用同一套记录，可跨入口用相同键重放或按 id 查询。
- **崩溃一致性**：进程可在绑定、outbox 落盘、账本追加或清理任一步骤崩溃。
  重启（或任一 CLI 入口）在 key/restore outbox 恢复之后，按同一
  `operation_id` 判定：事件已入帐即已提交，据耐久事实重建原 `201`/`403`/
  `404`/`409` 响应与审计投影并置终态（拒绝终态的状态码随事件持久化，严格
  重放）；事件未入帐则置 failed(`500`)，半成品文件、提供者句柄与标记由
  outbox/provision 恢复回滚。不重复记账（账本按 event_id 去重），不误判。
- **operation 工件镜像**：rotate/import/restore/batch-rotate 在幂等键绑定
  记录耐久**之后**、首次调用提供者**之前**，原子创建
  `operation-artifacts/<operation_id>.json`（0600、temp 文件 fsync 后 rename；
  非幂等入口与未绑定请求不创建该目录）。镜像是一次尝试全部耐久工件的交叉
  索引，记录租户、操作者、路径、规范化请求体、`kind`/审计动作、完整写集
  （rotate/import 为该 key_id，batch 为全部 key_id，restore 为全部新建
  key_id 及是否含策略）、阶段（`bound`→`provisioning`→`staged`→
  `committed`/`rolled_back`）、`provisions/<id>.json` 引用（batch 另引用
  `batch-rotations/<id>.json`，空 restore 另记录其 `restore-empty-*`
  标记）以及每铸一个句柄即登记的新句柄 `provider_id`/`handle`；镜像与 journal
  条目同步落盘，二者永不矛盾。请求到达终态后：事件确认且 action/tenant/
  operation 一致、写集文件拥有全部新句柄且 journal/snapshot 已清，才删镜像
  并保留新版本；事件未入账时，先由 outbox 恢复幂等删除全部新句柄并恢复可信
  旧写集，证据清零才删镜像。账本不可读、提交不确定（同 id 事件 action/tenant
  不符）、镜像缺失/损坏、镜像与 `operations/<id>.json` 绑定不一致、引用缺失/
  不一致或 batch snapshot 损坏时，**保留整组证据**（镜像、标记、journal、
  snapshot 与句柄），不猜测回滚也不暴露未提交 current：该 operation 保持
  `pending`，请求/重启返回 `500`/`503` 等待下次重试。无镜像的旧 journal 与旧
  restore 标记沿用原有恢复规则，镜像从不强制存在。
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
  `success/rejected`。备份记 `export`、恢复记 `import`，两者 `key_id` 均为
  null；恢复的所有事件（含成功）`key_id` 为 null；批量轮换整批至多一条
  `batch_rotate` 事件，成功与拒绝终态的 `key_id` 均为 null，可按
  `action=batch_rotate` 筛选。
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
  `"_restore":true` 与写集清单），只追加一条 `import` 事件；批量轮换是多
  key outbox（标记带 `"_batch_rotate":true`、写集 key_ids 与 provision/
  snapshot 引用），只追加一条 `batch_rotate` 事件（`key_id` null）。

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
- 导入/恢复/批量轮换在提供者调用前先建按 event_id 命名的 provision journal
  （首行耐久记录 operation_id、租户与动作，每铸一个句柄即以 0600 原子重写登记
  provider_id 与句柄）；提交后句柄归记录所有并删除 journal，未提交（冲突、
  提供者故障、账本失败、崩溃）则幂等删除全部已铸句柄，不留孤儿后端对象。恢复
  依据 journal 头校验账本中同 id 事件确属本次操作（动作、租户一致）才判定已
  提交；不一致即保留全部现场等待处理。批量
  轮换另在 `batch-rotations/<event_id>.json` 耐久记录每个 key 轮换前的整文件
  字节（snapshot），未提交时据此把整组文件还原；snapshot 缺失则整组保留等待下
  次启动，绝不猜测改写。
- 旧 restore 记录可能没有 provision journal：未提交回滚时以 `_restore` 标记
  的密钥文件列出整组句柄；提供者不可达或任一句柄删除失败时，保留整组密钥文件、
  策略文件与标记，下一次启动重试，全部句柄确认删除后才移除整组文件。
- 私钥与口令只存在于口令加密的包内或经提供者包装后的记录中；游标 HMAC 密钥
  存于 `audit.secret`(0600)。材料不会出现在任何响应、审计投影或错误信息中。
- rotate/import/restore/batch-rotate 另有 0600 的 operation 工件镜像
  `operation-artifacts/<operation_id>.json`：绑定后、调用提供者前创建，交叉
  关联 `operations/<id>.json`、`provisions/<id>.json`、restore 标记（含空
  restore 标记）或 batch snapshot，记录租户/操作者/路径/规范请求/动作/写集/
  阶段及新句柄；确认提交并核对句柄归属后随 journal/snapshot 一并清理，未提交
  时待全部新句柄删除、旧写集恢复后清理，任何证据缺失或不一致则整组保留（详见
  “幂等操作”一节）。
