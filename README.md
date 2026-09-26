# SOLOTASK01 多租户密钥管理后端

一个多租户密钥管理服务，同时提供 HTTP API 与命令行入口。支持 AES256 / RSA2048
密钥的生成、版本化轮换、吊销、加密导出/导入、租户级加密备份/恢复、按租户的
操作者策略、只追加的审计账，以及可插拔的 KMS/HSM 提供者。HTTP 信封加密、
轮换/导入/恢复是幂等操作：同一 `Idempotency-Key` 的重试只重放原结果，进程
在任一步骤崩溃后重启都能据 `operation_id` 判定是否已耐久并一致收尾。
（CLI `encrypt` 保持旧的非幂等行为，不携带 `Idempotency-Key`。）私钥只保存
在服务端，任何响应与审计投影都不含私钥、句柄或包装材料。

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
`module:factory`，首次使用时才惰性加载，绝不回退本地）。也可用
`KEYMGR_PROVIDER_CHAIN` 配置主备链：逗号分隔的 `local`/`module:factory`
项，项与项建厂所得的 `provider_id` 都必须唯一；未设时沿用
`KEYMGR_PROVIDER`，设为空、含空项或格式错误的链一律不可用（固定
`503`/CLI `1`）。链的初选、故障转移与状态提交见下。

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
- `GET /v1/keys`：本租户密钥快照分页清单。单一租户来源（单一头或单一
  `?tenant_id=`）；可选单值参数 `status`(active|revoked)、
  `algorithm`(AES256|RSA2048)、`limit`(1–1000，默认 100)、`cursor`，重复/
  空/非法/越界均 `400` 并指出字段，校验先于授权。`200` →
  `{items, next_cursor}`，项键序 `key_id,label,current_version,algorithm,
  status,created_at,public_key`（`created_at` 取首版时间，其余字段与筛选取
  已提交当前快照，未结算记录沿用既有投影），按 `(created_at, key_id)` 升序，
  空页 `items:[]`，末页 `next_cursor:null`。游标沿用审计游标规则（HMAC 签名，
  绑定租户/筛选/limit/可见快照），篡改、过期、跨租户或筛选不符均 `400`；并发
  变更使旧游标失效而非重漏。策略拒绝 `403` 记一条 `list/rejected`，成功记一条
  `list/success`，`key_id` 均为 null；存储/账本失败 `500`。
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
- `POST /v1/keys/{key_id}/migrate`，body 仅 `{"tenant_id": T}`，需
  `Idempotency-Key` 与操作者头。把主备链中该键**全部版本**从各自当前
  绑定的提供者导出、导入此刻 **ready** 的链项并就地重绑键文件：版本号、
  算法、公钥、各版本时间、`current` 与吊销状态保持不变，仅替换每版的
  `provider_id/handle/encrypted_material`。各版本由其原提供者导出；
  ready 项缺失/不健康、材料与算法/公钥不符或共用 5 秒门限超时，一律
  固定 `503`（`error` 为 `key management provider is unavailable`）。
  绑定后策略拒绝 `403`、未知/跨租户键 `404`；所有版本已在 ready 项上时
  `409`（绑定后才判定，不铸句柄、不写事件）。成功 `200`，键序固定
  `key_id,provider_id,versions,operation_id`，`versions` 为升序正整数
  数组；绑定后错误体仅 `{"error","operation_id"}`。提交前失败删除全部
  新句柄并恢复旧键文件；提交点之后才幂等删除原句柄——删除失败仍按
  成功重放并由重启清理，崩溃/重试绝不重复迁移或重复记账（每操作至多
  一条 `event_id=operation_id,action=migrate,key_id=K` 事件）。明文
  密钥材料只在导出与导入之间驻留内存，绝不进入响应、审计或错误。
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
- `POST /v1/keys/{key_id}/encrypt`，需单一 `Idempotency-Key` 头，body
  `{tenant_id, version?, plaintext, aad?}`；`plaintext`、`aad` 为 base64，
  `version` 缺省为 current。幂等键先于请求体与一切业务校验：缺失/为空/重复/
  非法一律 `400`，绑定前的参数/解析错误也是无副作用 `400`（不写审计、操作
  记录或句柄）。绑定即生成 UUID4 `operation_id`；同键同规范化请求重放首次
  状态码、信封与审计（同一 `operation_id`，业务不执行第二次），同键异请求
  `409` 并在错误体给出原 `operation_id`。成功 `200`，键序固定
  `{"format","envelope","operation_id"}`：`format` 固定
  `keymgr-envelope-v1`、`envelope` 为 base64、`operation_id` 为本次操作；
  内含 key_id、version、算法、nonce/tag、密文及**包装后的数据密钥**：每次
  新绑定生成新的 256 位数据密钥，以 AES-256-GCM 加密明文；AES256 版本用
  AES-GCM 包装数据密钥，RSA2048 版本用 RSA-OAEP-SHA256 包装（重放返回首次
  信封，不再生成新数据密钥、不再调用提供者）。绑定后错误体仅
  `{"error","operation_id"}`：授权拒绝 `403`、未知/跨租户 key 或未知版本
  `404`、吊销版本（含旧版本）`409`、提供者不可用 `503`（文案固定
  `key management provider is unavailable`）；等待同 key 锁超过 5 秒为
  `503` timed_out（等待方不写任何东西）。事件耐久前崩溃保持 `pending` 且
  对 `GET operation` 隐藏 http_status/response（含信封），同键重启或重试在
  同一 `operation_id` 下恰好再执行一次并原样重放；事件耐久后严格重放首次
  结果。绑定只持久化明文/AAD 的不透明键控承诺，明文、AAD、数据/私钥、句柄
  与后端异常绝不进入响应、审计或任何文件。
- `POST /v1/keys/{key_id}/decrypt`，body `{tenant_id, envelope, aad?}`，接
  受 `keymgr-envelope-v1`。`200` → `{plaintext}`（base64）。信封内 key_id
  必须与路径一致；缺字段、非法 base64、篡改、AAD 不符为 `400` 且错误指明
  字段；未知或跨租户的 key/version 为 `404`；吊销版本（含旧版本）为 `409`；
  提供者不可用为 `503`，沿用固定脱敏文案。私钥、数据密钥只存在于进程内存，
  绝不进入响应或审计。
- `POST /v1/keys/{key_id}/rewrap`，**非幂等**（无需
  `Idempotency-Key`），body 仅
  `{tenant_id, envelope, target_version?, aad?}`；`envelope`、`aad` 为
  标准带填充 base64，`target_version` 缺省为 current（须正整数）。把已
  认证信封内的数据密钥从源版本重新包装到目标版本：先以源版本 KEK 完整
  认证原信封（解包数据密钥并校验内容 GCM tag），再仅把**同一数据密钥**
  按目标版本重新包装；`nonce`、`tag`、`ciphertext`、`aad`、`key_id` 字
  节不变，version、algorithm 及包装字段按目标重建（AES256→AES-GCM，
  RSA2048→RSA-OAEP-SHA256）。正文、UUID4、base64、信封结构非法或信封
  key_id 异于路径，均在授权前 `400` 指出字段且**不记账**；仅 tenant 来
  源缺失/冲突照旧记 `tenant_conflict`。策略动作新增 `rewrap`，拒权 `403`
  并记 `rewrap/rejected`（带 key_id）；授权后未知/跨租户 key 或未知版本
  `404`，算法与源版本不符或认证失败 `400`（不记账），吊销或目标与源同
  版本 `409`，提供者/材料故障 `503` 且 error 固定
  `key management provider is unavailable`（不记账）；账本失败 `500`。
  `200` 键序固定 `format,envelope`，`format` 固定
  `keymgr-envelope-v1`。成功记 `rewrap/success`（带 key_id）。无 CLI；
  AAD 只可随信封返回，明文、数据密钥、私钥、句柄绝不入其他响应、审计、
  错误或落盘。
- `POST /v1/keys/{key_id}/sign`，**非幂等**（无需 `Idempotency-Key`），
  body 仅 `{tenant_id, version?, message}`；`message` 为标准 base64（可空），
  `version` 缺省为 current。用 RSASSA-PKCS1-v1_5/SHA-256 **确定性**签名，
  `200` 键序固定 `key_id,version,signature`，`signature` 为标准 base64。
  正文结构、字段、UUID4、base64 或 version 非正整数均 `400` 并指出字段，
  且不记账；身份参数失败照旧记 `tenant_conflict`。拒权 `403`；未知/跨租户
  key 或 version 为 `404`；AES256 版本或吊销版本（含旧版本）为 `409`；
  提供者或私钥材料故障一律固定文案 `503`（沿用 README 文案），不记账。
  成功记 `sign/success`，业务拒绝记 `sign/rejected`，均带 key_id。版本的
  提供者声明 `sign` 操作时走 KMS/HSM 原生路径：在五秒门限内调用绑定提供者
  的 `sign(handle, message)`，绝不调用 `export_material`，私钥不进入服务
  进程，并以版本公钥验签；结果非 256 字节、验签失败或提供者异常均为固定文
  案 `503` 且不记账。未声明者沿用导出私钥在内存中计算。message、signature
  绝不入审计，私钥、句柄与包装材料绝不入响应、审计或任何新文件。
- `POST /v1/keys/{key_id}/verify`，body 仅
  `{tenant_id, version?, message, signature}`，二者均为标准 base64
  （message 可空），`version` 缺省为 current。**只用该版本存储的公钥**验签：
  绝不加载、探活或调用 KMS/HSM 提供者，因此重启、轮换或迁移后的旧版本（甚
  至其原提供者不可用时）仍可验签。`200` 仅返 `{valid}`；签名不匹配（含长度
  /填充非法）一律 `{"valid": false}`，不是错误，仍记 `verify/success`。正文
  校验与身份规则同 sign（正文 400 不记账，身份冲突照旧）；拒权 `403`，未知/
  跨租户 key 或 version 为 `404`，AES256 或吊销版本为 `409`，业务拒绝记
  `verify/rejected`，均带 key_id。message 与 signature 绝不入审计。
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
- `GET /v1/provider/status` 与 `POST /v1/provider/reconnect`：KMS/HSM
  健康检查与无中断重连，见下（全局、非租户作用域，不带也不接受
  `tenant_id`，不记审计）。
- `POST /v1/provider/switchover`：主备链定向切换，见下（同样全局、非
  租户作用域，不记审计）。

## KMS/HSM 健康检查与无中断重连

- `GET /v1/provider/status`：只需单一非空 `X-Operator-Id`，不收
  `tenant_id`（头/查询/体均不接受，违者 `400`），也不记审计。返回 `200`，
  键序固定 `{"provider_id","status"}`；`status` 仅 `ready`/`unavailable`。
  提供者尚未加载时该探测会惰性建厂；加载/契约/配置失败时
  `provider_id` 为 `null`、`status` 为 `unavailable`，后端异常文本绝不外泄。
- 提供者可选实现 `health()`：无参数、返回 `bool`。缺少该方法视为健康；
  返回非 `bool`（即使为真值）或抛异常均视为不可用，文本不外泄。普通
  provider 调用路径上的单次 `health()` 探活至多等待 **1 秒**：`False`、
  非 `bool`、抛异常或超时各计一次失败；超过 1 秒才迟到的结果作废（既不
  算成功也不另计，只算这次超时）。重连/定向切换自身的健康检查不受 1 秒
  单探限制，但仍受其共用 5 秒门限约束。
- `POST /v1/provider/reconnect`：同样只需单一非空操作者头、不收
  `tenant_id`。请求体必须恰为 `{}`：坏 JSON、非对象或任何多余字段一律
  无副作用 `400`。按当前 `KEYMGR_PROVIDER`/`KEYMGR_PROVIDER_CHAIN` 配置
  重新建厂（链配置时按链序重选**首个健康项**，这是唯一可能切回已恢复
  主项的操作）、校验契约、用已绑定的数据目录配置并做健康检查，成功才替
  换实例并 `200` 返回与 status 同序结构；任一失败（排水/建厂/配置/健康
  超过共用 5 秒门限）都 `503` 且保留旧实例，错误体固定
  `{"error":"key management provider is unavailable"}`。
- **共用 5 秒门限、无中断**：重连与提供者调用共用 5 秒门限。重连先排水：
  在途调用由其进入时捕获的旧实例完成，绝不中途换实例；新调用在门内等待，
  等待超 5 秒返回固定 `503` 且零副作用（未调用任何提供者、未铸句柄、未写
  审计）。重连成功后新调用一律落到新实例。
- **pending 操作绑定原 provider_id**：幂等操作记录其提供者 `provider_id`。
  重连装入的提供者 `provider_id` 不同而某 pending 操作仍绑定旧 id 时，该
  操作保持 `pending` 并返回固定 `503`（不终态化、不写拒绝事件、镜像复位为
  干净的 `bound` 待续线索）；重连同 `provider_id` 的提供者后，同
  `Idempotency-Key` 的请求在**同一** `operation_id`/`event_id` 下继续恰好
  一次，事件绝不重复。从未在本数据目录激活过的 provider_id 仍按原“未激活
  提供者”规则终态 `503`。曾激活的 provider_id 记在
  `provider-ids.json`(0600)，跨进程可识别。
- **主备故障转移（`KEYMGR_PROVIDER_CHAIN`）**：链配置后，首次健康激活
  选链中首个健康项。**每次普通 provider 调用都从其首次等待或首次探活起
  共用一个不可重置的 5 秒总预算**：门内等待、活动项探活、第三次失败后的
  再验与备项探活共用同一截止时刻，超预算即固定 `503`，不得重置或另开预
  算；**单次 `health()` 至多等 1 秒**，`False`、非 `bool`、异常或超时各
  计一次失败，迟到结果作废。每次调用都先探活活动实例：探活恰好返回
  `True` 即把连续失败数清零并继续；否则把活动项的连续失败数加一（持久
  化、最多 3）并固定 `503`。前两次失败**不切换**；第三次初探失败后，用
  **同一总预算的余量**在现有跨进程意图/排水门内**再验一次**活动实例
  （仍逐次限 1 秒）——恢复则清零并继续本次调用——否则按**链序**用余量
  探活各备项（仍逐次限 1 秒），切到首个健康备项：只做一次
  `switching`→`ready` 提交、`generation` 加 1，并在**新代**继续本次调
  用。在途旧调用由其进入时捕获的实例完成，切换提交后到达的其他调用只
  用新代，并发的第三次失败仅一次建厂/提交（其余等待者直接采用已提交的
  代，不在备项上重放；失败计数本身由独立的 `provider-health.lock` 短排
  他锁跨进程串行化，前两次失败不排水、不阻断在途调用）。余量耗尽或无健
  康备项：固定 `503`，**旧代不变**、连续失败数封顶 3，禁止重置计数或另
  开预算。切换的其他失败（提交失败等）同样不改旧代，固定 `503`
  （CLI `1`），不铸句柄、不写审计、不外泄后端文本。主项恢复健康后**不
  自动回切**；只有 reconnect 按链序重选首个健康项。pending 幂等操作仍绑
  定原 `provider_id`，绝不在备端重放；重连回同 id 提供者后，同
  `Idempotency-Key` 的请求在同一 `operation_id`/`event_id` 下继续恰好
  一次。
- **定向切换（`POST /v1/provider/switchover`）**：只需单一非空
  `X-Operator-Id`，不收 `tenant_id`（头/查询/体均 `400`），不记审计。
  请求体严格为 `{"provider_id": P}`（P 非空）：坏 JSON、非对象、缺
  字段、空值或任何多余字段均无副作用 `400` 并指出字段；未配置
  `KEYMGR_PROVIDER_CHAIN` 或 P 不在链中同样 `400` 指出 `provider_id`
  且零副作用。P 即当前活动项时：健康则 `200` 且代不变，否则固定
  `503`。目标建厂/契约/健康检查失败或共用 5 秒门限耗尽均固定 `503`
  （体 `{"error":"key management provider is unavailable"}`）且零副作
  用。成功复用同一跨进程意图/排水门：在途旧调用由其捕获的实例完成，
  后到调用等待；先原子写 `switching`（旧 ID、P、原代、reason
  `reconnect`），再写 `ready`（P、null、代+1）；同目标并发切换只提交
  一次；写间崩溃仅在 P 健康时完成该切换，否则保留 `switching` 并
  `503`。`200` 键序固定 `provider_id,status`，值为 P、`ready`。
  pending 幂等操作仍绑定原 `provider_id`。
- **跨进程激活状态 `provider-state.json`(0600)**：首次健康激活、每次成功
  重连与每次主备切换都原子提交（temp 文件 fsync 后 rename）该文件：紧凑
  UTF-8 JSON、非 ASCII 原样、无末尾换行，键序固定
  `schema_version,provider_id,target_provider_id,generation,reason,phase`
  （依次为固定整数 2、非空字符串、null/非空字符串、从 1 递增的正整数、
  `initial`/`reconnect`/`failover`、`ready`/`switching`）；旧
  schema_version 1 文件（仅 `schema_version,provider_id,generation`
  三字段）视作 `ready`。切换（故障转移
  或改换 provider_id 的重连）先原子写 `switching`（旧 ID、目标 ID、原
  代），再写 `ready`（目标 ID、null、代+1）；重启或任一进程读到
  `switching` 时重验目标：健康即完成该切换（写 `ready`、代+1），否则保
  留文件原样并固定 `503`。文件缺失由首次健康激活创建（generation 1）；
  损坏或字段非法时，提供者调用与重连一律按固定文案 `503` 且绝不改写该
  文件。仅健康候选能在跨进程排他锁（`provider-state.lock`，与进程内门
  共用 5 秒门限）下互斥递增 generation；失败或提交前崩溃保留旧代。提交
  后各进程下次调用重建当前配置，所得 `provider_id` 不符或不健康则
  `503`（链配置时改为按下面的持久化故障门限处理）且零副作用。
- **持久化故障门限 `provider-health.json`(0600)**：记录活动项的连续失败
  数，使“三次失败才切换”的门限跨重启生效、跨进程共享。紧凑 UTF-8 JSON、
  非 ASCII 原样、无末尾换行，temp 文件 fsync 后原子 rename，顶层键序固定
  `schema_version,provider_id,generation,status,consecutive_failures`（依次
  为固定整数 1、非空字符串、正整数、`ready`/`unavailable`、0–3 整数）。它
  是 **ready** `provider-state.json` 的卫星文件，须与其同 ID 同代：文件缺失
  或代落后于已提交代时，据后者重建为该代 `ready`/0；文件损坏、代超前、或
  同代但 `provider_id` 不符，普通 provider 调用一律固定 `503` 且**绝不改
  写**该文件（reconnect/switchover/failover 的提交也会在落笔前被这种毒文件
  挡住、两个文件都保持原样；status 同样报 `unavailable`）。切换/重连/首次
  激活**先提交 `provider-state.json`，再写新代的 `ready`/0**（两步之间崩溃
  时，旧 health 因代落后于新 state 而在下次读取时重建为 `ready`/0）。重启
  按上述规则收敛；探活 `True` 清零，`False`/非 bool/异常/单次探活 1 秒
  超时（迟到结果作废）各加一，且每次普通调用的全部探活与等待共用不可重
  置的 5 秒总预算，并发失败的
  计数由 `provider-health.lock` 短排他锁串行（前两次失败不排水、不阻断在途
  调用），只有第三次失败才触发那一次切换。
- CLI：`provider status --operator O`、
  `provider reconnect --operator O` 与
  `provider switchover --operator O --provider-id P`，成功输出同序单行
  JSON；`400→2`、`503→1`，成功 `0`。status 在提供者不可用时仍以退出
  `0` 返回 `{"provider_id":null,"status":"unavailable"}`。

## 幂等操作

- HTTP 的 rotate/import/restore/batch-rotate/migrate/encrypt（CLI：
  `rotate`/`import`/`restore`/`batch-rotate`/`migrate`；CLI `encrypt`
  维持非幂等、无此头）必须携带**单一** `Idempotency-Key` 头（前五个 CLI
  必填 `--idempotency-key`），值为 1–128 个 `[A-Za-z0-9._~-]` 字符。缺失、为空、
  重复、非法一律 `400`（CLI `2`），且该校验先于请求体读取与一切业务：不写
  审计、操作记录、密钥或提供者句柄。
- 键全局唯一，绑定记录 `operation_id`(UUID4)、租户、操作者、路径、规范化体
  （键排序紧凑 JSON）、状态、HTTP 状态与响应；存于 `operations/<id>.json`
  (0600) 与 `operations/index.json`，进程内锁 + `operations.lock` 的 fcntl
  排他锁串行化。encrypt 的规范化体对明文/AAD 只保存键控不透明承诺，绝不保存
  明文或 AAD 本身。
- 相同绑定重试：直接重放首次状态码、响应体与审计事件（同一
  `operation_id`，业务不执行第二次）。同键不同绑定：`409`（CLI `3`），错误
  体给出已有 `operation_id`。绑定前的导入/恢复解密无副作用：口令错误 `400`
  不占用该键。
- 状态：`pending`/`succeeded`/`failed`/`conflict`/`timed_out`。变更类成功为
  `201` succeeded，只读 encrypt 成功为 `200` succeeded；同租户冲突为 `409`
  conflict；`403/404/400` 与提供者/账本失败为 failed（保留原状态码）。并发
  同键仅一个执行，其余等待；等待超 5 秒返回 `503` timed_out（CLI `1`），等待
  方不写任何东西。
- 多/单轮换互斥：批量轮换与单键 rotate 都按 `key_id` 排序获取 per-key
  进程内锁 + `<key_id>.lock` fcntl 排他锁（整批共享一个 5 秒截止时刻）。对同一
  key 的并发变更要么全在批量之前、要么全在之后；等待同一被占 key 超过 5 秒的
  批量返回 `503` timed_out 且零副作用（此时尚无 journal、事件或句柄）。
- `operation_id` 即该变更审计事件的 `event_id`，因此每个终态至多一条事件，
  HTTP 与 CLI 共用同一套记录，可跨入口用相同键重放或按 id 查询。
- **崩溃一致性**：进程可在绑定、outbox 落盘、账本追加或清理任一步骤崩溃。
  重启（或任一 CLI 入口）在 key/restore outbox 恢复之后，按同一
  `operation_id` 判定：事件已入帐即已提交，据耐久事实重建原
  `200`/`201`/`403`/`404`/`409` 响应与审计投影并置终态（拒绝终态的状态码随
  事件持久化，严格重放）；变更类操作事件未入帐则置 failed(`500`)，半成品文
  件、提供者句柄与标记由 outbox/provision 恢复回滚；只读 encrypt 事件未入帐
  时保持 `pending`（信封无法在无请求的情况下重建，故绝不臆造终态），由同键
  HTTP 重试在同一 `operation_id` 下恰好再执行一次。不重复记账（账本按
  event_id 去重），不误判。
- **operation 工件镜像**：rotate/import/restore/batch-rotate/migrate 以及
  HTTP encrypt 在幂等键绑定记录耐久**之后**、首次调用提供者**之前**，原子创建
  `operation-artifacts/<operation_id>.json`（0600、temp 文件 fsync 后 rename；
  非幂等入口与未绑定请求不创建该目录；CLI `encrypt` 为非幂等入口不创建）。
  镜像是一次尝试全部耐久工件的交叉索引，记录租户、操作者、路径、规范化请求
  体、`kind`/审计动作、完整写集（rotate/import/migrate/encrypt 为该
  key_id，batch 为全部 key_id，restore 为全部新建 key_id 及是否含策略）、阶段
  （`bound`→`provisioning`→`staged`→`committed`/`rolled_back`）、
  `provisions/<id>.json` 引用（batch 另引用 `batch-rotations/<id>.json`，空
  restore 另记录其 `restore-empty-*` 标记，migrate 另引用其
  `migrations/<id>.json`：旧键文件字节与全部旧句柄）以及每铸一个句柄即登记的
  新句柄 `provider_id`/`handle`；只读 encrypt 不铸句柄、无 journal/snapshot，
  镜像始终停在 `bound`，事件耐久且无残留证据即清除。镜像与 journal 条目同步落
  盘，二者永不矛盾。请求到达终态后：事件确认且 action/tenant/operation 一致、
  写集文件拥有全部新句柄且 journal/snapshot 已清，才删镜像并保留新版本（
  encrypt 另核对暂存信封命名写集 key 且版本存在；migrate 另核对每版均已绑定
  暂存响应所报的 ready provider 且版本序一致，其 `migrations/<id>.json` 仅在
  全部旧句柄确认删除后才消失）；事件未入账时，变更类先由 outbox 恢复幂等删除
  全部新句柄并恢复可信旧写集，证据清零才删镜像；encrypt 则保持 pending 并保留
  镜像作为待重试线索。账本不可读、提交不确定（同 id 事件
  action/tenant 不符）、镜像缺失/损坏、镜像与 `operations/<id>.json` 绑定不
  一致、引用缺失/不一致或 batch snapshot 损坏时，**保留整组证据**（镜像、标
  记、journal、snapshot 与句柄），不猜测回滚也不暴露未提交 current：该
  operation 保持 `pending`，请求/重启返回 `500`/`503` 等待下次重试。无镜像的
  旧 journal 与旧 restore 标记沿用原有恢复规则，镜像从不强制存在。
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
  `create/read/rotate/revoke/import/export/migrate/encrypt/decrypt/
  rewrap/sign/verify/audit/list`，单条内重复去重；`effect` 为 `allow`/`deny`；未知字段、类型错误、同
  subject+effect+无序动作集的重复规则均 `400`；`rules:[]` 合法（全拒绝）。
- 执行：管理动作 policy_* 免检；租户无策略时全部允许；有策略时匹配规则中
  deny 优先于 allow，无匹配则拒绝 → `403`，并记一条原动作名、
  `outcome=rejected`、携带当时已知 `key_id` 的事件（create/解密前的 import/
  audit 查询为 null）。参数校验先于授权，授权先于存在性判断。

## 审计

- 事件字段 `{event_id, tenant_id, action, key_id, outcome, timestamp}`；
  `action` 为 `create/read/rotate/batch_rotate/revoke/import/export/
  migrate/encrypt/decrypt/rewrap/sign/verify/audit/list/tenant_conflict/
  policy_read/policy_update/policy_delete`，`outcome` 为 `success/rejected`。
  信封加密/解密/重包装事件只含元数据（无 plaintext、aad、envelope、数据密钥或私钥）；
  签名/验签事件同样只含元数据（无 message、signature、私钥或句柄），成功记
  `sign`/`verify` 的 success、业务拒绝记同名 rejected，均携带当时 key_id；
  重包装成功记 `rewrap/success`、拒权/业务拒绝记 `rewrap/rejected`，均带
  key_id，正文 `400`（含算法不符与认证失败）与提供者故障的 `503` 都不记账；
  sign 的正文 `400` 与提供者故障 `503` 同样不记账。幂等 HTTP encrypt
  每个终态至多一条 `event_id=operation_id,action=encrypt` 事件（成功 200 与
  绑定后拒绝都随操作重放，绝不重复记账），非幂等 CLI/decrypt 每次请求各记一
  条；策略拒绝写一条对应 `encrypt`/`decrypt` 的 rejected 事件（携带 key_id），
  成功写对应 action 的 success 事件。备份记 `export`、恢复记 `import`，两者
  `key_id` 均为 null；恢复的所有事件（含成功）`key_id` 为 null；批量轮换整批
  至多一条 `batch_rotate` 事件，成功与拒绝终态的 `key_id` 均为 null，可按
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
python -m keymgr list     --tenant-id t --operator alice \
                          [--status active|revoked] [--algorithm AES256|RSA2048] \
                          [--limit 100] [--cursor <cursor>]
python -m keymgr current  --tenant-id t --key-id <id> --operator alice
python -m keymgr version  --tenant-id t --key-id <id> --version 1 --operator alice
python -m keymgr rotate   --tenant-id t --key-id <id> --algorithm AES256 \
                          --operator alice --idempotency-key rotate-0001
python -m keymgr migrate  --tenant-id t --key-id <id> --operator alice \
                          --idempotency-key migrate-0001
python -m keymgr batch-rotate --tenant-id t --operator alice \
                          --idempotency-key batch-0001 \
                          --items '[{"key_id":"<id1>","algorithm":"AES256"},{"key_id":"<id2>","algorithm":"RSA2048"}]'
python -m keymgr revoke   --tenant-id t --key-id <id> --reason r --operator alice
python -m keymgr status   --tenant-id t --key-id <id> --operator alice
# 导出/导入、备份/恢复
python -m keymgr export   --tenant-id t --key-id <id> --passphrase pw --operator alice
# 信封加密/解密（plaintext/aad 为 base64，version 缺省 current）
python -m keymgr encrypt  --tenant-id t --key-id <id> \
                          --plaintext <base64> [--aad <base64>] [--version 1] \
                          --operator alice
python -m keymgr decrypt  --tenant-id t --key-id <id> \
                          --envelope <keymgr-envelope-v1-base64> [--aad <base64>] \
                          --operator alice
python -m keymgr import   --tenant-id t --passphrase pw --bundle <b> \
                          --operator alice --idempotency-key import-0001
python -m keymgr backup   --tenant-id t --passphrase pw --operator alice
python -m keymgr restore  --tenant-id t --passphrase pw --bundle <b> \
                          --operator alice --idempotency-key restore-0001
# 审计 / 操作 / 策略
python -m keymgr audit    --tenant-id t --action rotate --limit 100 --operator alice
python -m keymgr operation --tenant-id t --operator alice --operation-id <id>
python -m keymgr policy --operator admin set|show|delete --tenant-id t [--rules '<json>']
# KMS/HSM 健康检查与无中断重连（全局，无 --tenant-id）
python -m keymgr provider status    --operator alice
python -m keymgr provider reconnect --operator alice
```

## KMS/HSM 提供者

- 工厂返回对象须有非空 `provider_id`、`capabilities`
  （algorithms 含 AES256/RSA2048；operations 含
  generate/rotate/import_material/export_material/delete）及这五个方法。
  generate/rotate/import_material → `{handle, public_key, encrypted_material}`；
  export_material(handle) → `{public_key, encrypted_material}`；delete(handle)
  幂等。`capabilities.operations` 可另含 `sign`：声明即须实现
  `sign(handle: str, message: bytes) -> bytes`——handle 非非空 str 抛
  `ValueError`、message 非 bytes 抛 `TypeError`、未知/非 RSA 句柄或后端故
  障抛 `ProviderUnavailable`，成功返回 256 字节 RSASSA-PKCS1-v1_5/SHA-256
  签名；声明而无该方法（或方法不可调用）即契约不符。本地提供者已实现并声
  明 `sign`。另可实现可选 `health()`（无参、返回 `bool`）：缺少视为健康，非
  `bool`/抛异常视为不可用。普通 provider 调用路径上单次探活至多等 1
  秒（超时按一次失败、迟到结果作废），且一次调用的全部探活/等待共用不
  可重置的 5 秒总预算。模块缺失/工厂失败/契约不符/后端异常一律 `503`
  （CLI `1`），固定文案
  "key management provider is unavailable"，绝不回退；导入材料不符算法（AES
  非 32 字节、RSA 公私钥不匹配等）为 `400`，错误只指名字段。
- 本地提供者用 `local.dek`(0600) 以 AES-256-GCM 包装材料，句柄与包装材料登
  记在 `local-registry.json`(0600)；密钥文件每个版本只存
  `{provider_id, handle, encrypted_material}` 三元组，导出包/备份包版本额外
  带 `provider` 来源块，旧 `keymgr-export-v1` 包无来源块时按本地处理。
- `KEYMGR_PROVIDER_CHAIN` 为主备链：逗号分隔的 `local`/`module:factory`
  项，项唯一且建厂所得 `provider_id` 唯一（重复即整链不可用）。首次激活
  选首个健康项；活动实例不健康时按上节规则故障转移到首个健康备项，主项
  恢复后不自动回切，reconnect 才按链序重选。链配置时“本地提供者是否活
  动”以已提交的 `provider-state.json` 为准（`provider_id` 为 `local`），
  旧记录接管等门控不会因此导入任何 module:factory 提供者。
- 轮换/导出/导入/恢复必须命中记录登记的 provider：记录属于未激活提供者，或
  导入/恢复来源块与当前提供者不符，均 `503`，不静默切换。唯一例外是
  `POST /v1/keys/{key_id}/migrate`：它显式把各版本由其原提供者（链内
  任意一项，需健康）导出、导入当前 ready 项；原提供者不在链中、建厂/
  契约失败或不健康均固定 `503`，绝不回退本地。
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
- rotate/import/restore/batch-rotate/migrate 另有 0600 的 operation 工件镜像
  `operation-artifacts/<operation_id>.json`：绑定后、调用提供者前创建，交叉
  关联 `operations/<id>.json`、`provisions/<id>.json`、restore 标记（含空
  restore 标记）或 batch snapshot；migrate 另关联其
  `migrations/<id>.json` 快照（旧键文件字节与全部旧句柄），记录租户/操作
  者/路径/规范请求/动作/写集/阶段及新句柄；确认提交并核对句柄归属后随
  journal/snapshot 一并清理，未提交时待全部新句柄删除、旧写集恢复后清理，
  任何证据缺失或不一致则整组保留（详见“幂等操作”一节）。
