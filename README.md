# SOLOTASK01

多租户密码与密钥管理后端。Python 实现，对外提供 HTTP 服务与命令行入口，两者能力一致。

## 运行

    python -m app --port <port>      # 启动 HTTP 服务
    python -m app <subcommand>       # 命令行入口，输出单行 JSON

## 公开接口

POST /v1/keys
  请求：tenant_id、algorithm、label
  algorithm 取值：AES256 | RSA2048
  成功：201 -> key_id、algorithm、public_key
        （RSA2048 的 public_key 为 PEM 公钥；AES256 为 null）

GET /v1/keys/{key_id}
  成功：200 -> algorithm、label、created_at、public_key

## 约定

- 缺少必填字段或 algorithm 不受支持：400，错误信息需能定位到具体字段
- 跨租户读取：一律当作不存在，404
- 私钥只保存在服务端，任何响应都不得包含私钥材料
- 服务重启后 key_id 仍然有效，created_at 保持不变

## 当前状态

接口尚未实现；实现完成后需在此补充安装依赖、启动方式与基础测试命令。
