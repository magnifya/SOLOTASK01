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

### 操作者标识

除 `serve` 外，每个 HTTP 请求都必须携带**单一非空**请求头
`X-Operator-Id: <operator>`（CLI 对应全局的 `--operator`，每个子命令都必填）；
缺失、为空或重复均返回 `400`（CLI 退出 `2`）。该标识既用于审计，也作为租户
策略中的 `subject` 参与鉴权。

### 租户策略

- `GET /v1/policy`：读取一个租户的策略。租户由**单一** `X-Tenant-Id` 头或
  **单一** `?tenant_id=` 参数提供；两者同时给出、重复、缺失或为空均为 `400`
  且错误指明 `tenant_id`（这类参数错误同时记一条不可见的 `tenant_conflict`
  事件）。策略不存在返回 `404`。成功返回 `200`：
  `{"tenant_id", "rules"}`，并记一条 `policy_read` 事件。
- `PUT /v1/policy`：新建或整体替换策略。请求体 JSON 必须含非空字符串
  `tenant_id` 与数组 `rules`；`X-Tenant-Id` 头 / `?tenant_id=` 可选但必须与
  body 的 `tenant_id` 一致，冲突为 `400`。成功返回 `200`：
  `{"tenant_id", "rules"}`，并记一条 `policy_update` 事件。
- `DELETE /v1/policy`：删除策略。租户来源与 `GET` 相同（单一头或单一参数）。
  成功（含策略本不存在的幂等删除）返回 `200`：
  `{"tenant_id", "deleted": true}`，并记一条 `policy_delete` 事件。
- `rules` 的每个元素含 `subject`、`actions`、`effect`：
  - `subject` 为非空字符串且**区分大小写**；
  - `actions` 为非空数组，元素只能是
    `create` / `read` / `rotate` / `revoke` / `import` / `export` / `audit`，
    元素须非空，单条规则内重复的动作会去重；
  - `effect` 只能是 `allow` 或 `deny`；
  - 出现未知字段、字段类型错误、或存在同 `subject` + 同 `effect` +
    无序 `actions` 集合相同的重复规则，均为 `400`。`rules: []` 合法，表示
    该租户的所有动作都被拒绝。
- **执行规则**（作用于 create/read/rotate/revoke/import/export/audit 七个动作，
  管理端点 policy_* 免检）：租户没有策略时一律允许；有策略时，匹配当前
  `X-Operator-Id` 与动作的规则里 **deny 优先于 allow**，没有任何规则匹配则
  拒绝。被策略拒绝返回 `403`，并记原动作名（如 `read`）、`outcome=rejected`
  与当时已知的 `key_id`（create/import 解密前/audit 查询为 `null`）。参数校验
  （`400`）先于授权，授权先于存在性判断；未知 key / 跨租户访问仍为 `404`。

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
- `POST /v1/backup`：租户级加密备份。请求体 JSON 含非空字符串 `tenant_id`、
  `passphrase`；可附与 body 一致的 `X-Tenant-Id` / `?tenant_id=`
  （冲突返回 `400` 且指明 `tenant_id`）。受 `export` 动作授权。成功返回
  `200`：`{"format":"tenant-backup-v1","bundle": <不透明 base64>}`，
  bundle 与单 key 导出同一套 scrypt + AES-256-GCM 信封（格式标签不同，
  两类包不可互换），解密载荷为
  `{format, tenant_id, keys, policy}`：`keys` 的每个元素为
  `{key_id, label, current_version, status, reason, operator, revoked_at,
  versions:[版本对象]}`；`policy` 为 `null` 或 `{"rules":[...]}`。
  空租户备份为 `keys: []`、`policy: null`。私钥只存在于加密包内，响应与
  审计投影均不泄露。
- `POST /v1/restore`：租户级加密恢复。请求体 JSON 含非空字符串 `tenant_id`、
  `passphrase`、`bundle`；同样接受与 body 一致的 `X-Tenant-Id` /
  `?tenant_id=`。校验顺序：参数/解密/格式错误为 `400`（指出
  `passphrase` / `bundle` / `keys[i].xxx` 等字段，全程不落盘）→ 受
  `import` 动作授权（`403`）→ 包内 `tenant_id` 与请求租户不一致为
  `404`（不泄露包归属）。之后做冲突检查：该租户已有同一 `key_id`、或
  已有策略文档（即使包内 `policy` 为 `null`，恢复也绝不覆盖或删除既有
  策略）返回 `409` 且一切不变；`key_id` 被其他租户占用返回 `404`。
  无冲突时多个 key 文件与策略文件在同一逻辑事务内原子恢复，成功返回
  `201`：`{"tenant_id", "key_ids", "policy_restored"}`；空包（`keys: []`、
  `policy: null`）同样成功，`key_ids` 为 `[]`、`policy_restored` 为
  `false`。
- `GET /v1/audit`：查询本租户的审计事件。租户由**单一** `X-Tenant-Id`
  头或**单一** `?tenant_id=` 参数提供；缺失、重复、为空或两者冲突均返回
  `400` 且错误信息指出 `tenant_id`。可选筛选：`key_id`（非 UUID4 返回
  `400`）、`action`（`create` / `read` / `rotate` / `revoke` / `import` /
  `export` / `audit` / `tenant_conflict` / `policy_read` / `policy_update` /
  `policy_delete` 十一值之一）、`limit`（默认 `100`，范围
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
（含租户级备份）都会写入持久化审计账。每条事件字段为 `event_id`、`tenant_id`、
`action`、`key_id`、`outcome`、`timestamp`（UTC）；`action` 为 `create` /
`read` / `rotate` / `revoke` / `import` / `export` / `audit` /
`tenant_conflict` / `policy_read` / `policy_update` / `policy_delete`，
`outcome` 为 `success` / `rejected`。
租户级备份记 `action=export`、租户级恢复记 `action=import`，两者的
`key_id` 均为 `null`；参数级的租户缺失/冲突仍记不可见的
`action=tenant_conflict`。

- 租户已确定且 `key_id` 合法时，事件同时记录两个标识，且仅该请求租户可见。
  未知或跨租户的访问（含导出、跨租户导入冲突、恢复包内租户不一致）记为
  `outcome=rejected`，只对请求租户可见，不泄露密钥归属。导入（含租户级
  恢复）在解密成功前尚不知 `key_id`，这类拒绝事件的 `key_id` 为 `null`；
  租户级恢复的全部审计事件（含成功）`key_id` 均为 `null`；未知但合法的
  `key_id` 在审计查询中返回空。
- 被租户策略拒绝的动作记一条**原动作名**（不是策略动作）、
  `outcome=rejected`、携带当时已知 `key_id` 的事件（如对未知 key 的
  `read` 拒绝会带上该 key_id；create、成功解密前的 import、audit 查询为
  `null`）。审计查询本身**成功时不记账**，仅在被策略拒绝时记一条
  `action=audit`、`outcome=rejected`、`key_id=null` 的事件。
- 策略管理记 `policy_read` / `policy_update` / `policy_delete` 三种
  `success` 事件（`key_id` 为 `null`），仅该租户可见；这些管理动作本身
  不受租户策略约束。
- 租户缺失、为空、标识非法（`key_id` 非 UUID4）或头/查询/体提供的租户互相
  不一致时，记一条 `action=tenant_conflict`、`outcome=rejected` 的事件，
  其 `tenant_id` 与 `key_id` 均为 `null`，任何租户都查不到它。
- 审计账只追加，存于数据目录的 `audit.log`（每行一个 JSON）。变更（生成 /
  轮换 / 吊销 / 导入）与其事件在同一逻辑事务提交：先把事件作为待提交标记
  随密钥文件原子落盘，再 durable 追加账本，最后清除标记；账本写失败则回滚
  密钥文件并对 HTTP 返回 `500`、CLI 以退出码 `1` 失败，绝不允许单边落盘。
  导出只读，其审计事件随成功响应直接追加账本。进程在两步之间崩溃时，下次
  启动依据待提交标记幂等补记账本（按 `event_id` 去重）。
- 策略文档同样走 outbox 事务：`PUT` 先把策略文件（数据目录
  `policies/<sha256(tenant_id)>.json`，权限 `0600`）连同待提交事件原子
  落盘再追加账本；`DELETE` 用 `*.json.del` 墓碑标记包裹“删文件 → 记账本”
  两步，崩溃后下次启动据墓碑幂等收尾（原文件仍在则回滚删除，否则补记并清理）。
- 租户级恢复是跨多个 key 文件与至多一个策略文件的**多文件 outbox 事务**：
  所有文件先携带同一个待提交事件与写集清单（marker 内带 `"_restore": true`
  以区别于单文件 outbox）原子落盘，随后只向账本 durable 追加**一条**
  `action=import`、`key_id=null` 事件，最后统一清除标记。账本失败时删除本次
  新建的全部文件（既有文件永远不会被恢复覆盖，因为冲突检查先于写入），
  HTTP 返回 `500`、CLI 退出码 `1`；进程在期间崩溃则下次启动按 event_id
  分组：事件已入帐则清除标记完成事务，未入帐则删除全部半成品文件，两条路径
  都幂等，不重不漏。空包恢复（`keys: []`、`policy: null`）不建文件但仍补记
  一条成功事件。
- 事件与查询投影均不含任何私钥材料。`GET /v1/audit` 成功时不产生审计事件。


## 命令行

除 `serve` 外，每个子命令都必须提供非空的 `--operator`（对应 HTTP 的
`X-Operator-Id`，同时作为策略匹配的 `subject`）；缺失由 argparse 报错、
为空以退出码 `2` 报错。

`gen` / `show` 与上述接口一一对应，均打印单行 JSON，字段名与 HTTP 响应完全一致：

```bash
python -m keymgr --data-dir ./keymgr_data gen \
  --tenant-id tenant-a --algorithm RSA2048 --label "my key" --operator alice
python -m keymgr --data-dir ./keymgr_data show \
  --tenant-id tenant-a --key-id <key_id> --operator alice
```

版本与轮换命令同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 轮换：输出 {"key_id","version","algorithm","public_key"}
python -m keymgr --data-dir ./keymgr_data rotate \
  --tenant-id tenant-a --key-id <key_id> --algorithm AES256 --operator alice
# 指定历史版本：输出 {"key_id","version","created_at","algorithm","public_key"}
python -m keymgr --data-dir ./keymgr_data version \
  --tenant-id tenant-a --key-id <key_id> --version 1 --operator alice
# 当前版本：字段同 version
python -m keymgr --data-dir ./keymgr_data current \
  --tenant-id tenant-a --key-id <key_id> --operator alice
```

吊销与状态查询同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 吊销：输出 {"key_id","status","reason","operator","revoked_at"}
# --operator 既是调用者（策略 subject）也记录为吊销操作者
python -m keymgr --data-dir ./keymgr_data revoke \
  --tenant-id tenant-a --key-id <key_id> --reason "compromised" --operator alice
# 状态：字段同 revoke；active 时 reason/operator/revoked_at 为 null
python -m keymgr --data-dir ./keymgr_data status \
  --tenant-id tenant-a --key-id <key_id> --operator alice
```

加密导入 / 导出同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 导出：输出 {"format","bundle"}，bundle 为不透明 base64
python -m keymgr --data-dir ./keymgr_data export \
  --tenant-id tenant-a --key-id <key_id> --passphrase 'hunter2' --operator alice
# 导入：输出 {"key_id","algorithm","public_key"}（201 的创建响应字段）
python -m keymgr --data-dir ./keymgr_data import \
  --tenant-id tenant-b --passphrase 'hunter2' --bundle '<bundle>' --operator alice
```

导出、导入分别写 `action=export` / `action=import` 的审计事件。

租户级备份 / 恢复同样打印单行 JSON，字段与对应 HTTP 响应一致：

```bash
# 备份：输出 {"format":"tenant-backup-v1","bundle"}
python -m keymgr --data-dir ./keymgr_data backup \
  --tenant-id tenant-a --passphrase 'hunter2' --operator alice
# 恢复：输出 {"tenant_id","key_ids","policy_restored"}
python -m keymgr --data-dir ./keymgr_data restore \
  --tenant-id tenant-a --passphrase 'hunter2' --bundle '<bundle>' --operator alice
```

备份、恢复分别写 `action=export` / `action=import`、`key_id=null` 的审计
事件；口令缺失/错误、bundle 格式错误以退出码 `2` 报错，策略拒绝以 `3`、
同租户冲突（已有 key_id 或已有策略）以 `3`、包内租户不一致或跨租户占用以
`4` 报错，账本写失败以 `1` 失败。

审计查询同样打印单行 JSON，字段与 `GET /v1/audit` 响应一致
（`{"events","next_cursor"}`）：

```bash
# 查询本租户事件；--key-id / --action / --limit / --cursor 均可选
python -m keymgr --data-dir ./keymgr_data audit \
  --tenant-id tenant-a --action rotate --limit 100 --operator alice
# 用上一页输出里的 next_cursor 继续翻页（其为空串/null 时即末页）
python -m keymgr --data-dir ./keymgr_data audit \
  --tenant-id tenant-a --cursor '<next_cursor>' --operator alice
```

策略管理用 `policy show|set|delete` 子命令，均需 `--operator` 与
`--tenant-id`，输出与对应 HTTP 响应同形（`set` 另需 `--rules`，值为
JSON 数组字符串）：

```bash
# 输出 {"tenant_id","rules"}
python -m keymgr --data-dir ./keymgr_data policy --operator admin set \
  --tenant-id tenant-a \
  --rules '[{"subject":"alice","actions":["read","create"],"effect":"allow"}]'
# 输出 {"tenant_id","rules"}
python -m keymgr --data-dir ./keymgr_data policy --operator admin show \
  --tenant-id tenant-a
# 输出 {"tenant_id","deleted":true}
python -m keymgr --data-dir ./keymgr_data policy --operator admin delete \
  --tenant-id tenant-a
```

非法的 `--key-id` / `--action` / `--limit` 或失效篡改的 `--cursor` 以
退出码 `2` 报错，错误信息指出具体字段。导出/导入的口令缺失、口令错误或
bundle 格式、版本、字段错误，以及策略 `--rules` 的任何校验错误同样以
退出码 `2` 报错。

被租户策略拒绝（HTTP `403`）以退出码 `3` 报错；同租户重复导入已存在的
`key_id` 也以退出码 `3` 报错（对应 HTTP `409`，原记录不变）。

未知 key/版本/策略或跨租户访问以退出码 `4` 报错；非法 algorithm / version
（非正整数）等参数错误以退出码 `2` 报错，错误信息指明字段；审计账写失败
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
- 租户备份包 `tenant-backup-v1` 复用同一 scrypt + AES-256-GCM 信封与固定
  KDF 参数，仅格式 AAD 标签不同（与 `keymgr-export-v1` 互不接受）；载荷
  `{format, tenant_id, keys, policy}` 逐字段校验（key 投影与单 key 导出同
  一套版本/吊销校验，`keys` 允许空数组、`key_id` 不可重复，`policy` 为
  `null` 或带合法 `rules` 的对象），缺字段/版本错误以 `400` 指出
  `keys[i].xxx` 等具体字段。恢复走多文件 outbox 事务（见上文“审计”），
  冲突先于任何写入检查，既有 key/策略文件绝不被覆盖。
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
