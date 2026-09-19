# SOLOTASK01 多租户密码与密钥管理后端

要实现一个多租户密钥管理后端，同时提供 HTTP 服务和命令行入口。技术选型用 Python 加 cryptography，不引入额外运行时依赖。密钥生成走 POST /v1/keys，请求体是 JSON，含 tenant_id、algorithm 与 label 三个字符串字段，algorithm 只接受 AES256 和 RSA2048；成功返回 201，响应含 key_id、algorithm 与 public_key，RSA2048 的 public_key 是 PEM 编码公钥，AES256 的 public_key 为 null。读取走 GET /v1/keys/{key_id}，返回 algorithm、label、created_at 与 public_key。缺少任一必填字段或 algorithm 不受支持时返回 400，错误信息需指出具体是哪个字段。命令行提供 gen 与 show 两个子命令，分别对应上面两个接口，打印单行 JSON 且字段名与 HTTP 响应完全一致。租户之间必须隔离，用另一个 tenant_id 查询同一 key_id 一律返回 404。私钥只保存在服务端，任何响应都不得包含私钥材料。密钥写入磁盘后重启服务仍可查到，created_at 不因重启而改变。

## 当前状态

上述接口尚未实现。实现完成后，请在此补充安装依赖、启动方式与基础测试命令。
