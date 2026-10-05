# NyaPassword 服务端（server）

NyaPassword 的同步服务端：只保存密文（端到端加密），提供 OPAQUE 登录、条目同步（乐观并发、只追加的修订历史）、附件、WebSocket 推送、自动备份（阿里云 OSS / WebDAV / 服务器上的目录）与恢复演练，以及嵌入的网页版和管理后台。

设计见 [../common/docs/设计方案.md](../common/docs/设计方案.md)，进度见 [../common/docs/开发计划.md](../common/docs/开发计划.md)。

## 仓库关系

和 `../common` 并列检出；通过 path 依赖使用 common 的 `npw-api`、`npw-crypto`、`npw-backup`、`npw-otp`，测试还用 `npw-core` 做真实客户端。发版时 `COMMON_REF` 固定 common 的提交。

## 开发

```powershell
cargo test                                  # 单元 + 端到端（真实服务端 + 真实客户端核心）
$env:NPW_STRESS_OPS=20000; cargo test --release --test stress   # 更长的随机多设备压测
.\scripts\build-web.ps1                     # 构建 ../common/web 并嵌入（不构建时嵌入占位页）
cargo run -- --data .\data                  # 本地运行，监听 127.0.0.1:8087
```

## 部署（Docker）

```bash
mkdir -p /opt/nyapassword && cd /opt/nyapassword
# 解压 Release 里的 NyaPassword-Server-deploy_<版本>.tar.gz，进入 deploy/docker
cp .env.example .env            # 设置 VERSION、首次的 ADMIN_PASSWORD
docker compose up -d
```

- 服务只监听 `127.0.0.1:8087`，由 Caddy（`deploy/caddy/Caddyfile`，把 `vault.example.com` 换成你的域名）负责 HTTPS 和 WebSocket。
- 数据在 `./data`：`nyapassword.sqlite3`（数据库）、`attachments/`（加密附件）、`server.key`（服务端自己的密钥，备份里也有）。
- 第一个账户可以直接注册；之后注册需要邀请码：`docker compose exec nyapassword nyapassword-server invite`。
- 管理后台：`https://vault.example.com/admin`。密码：`.env` 的 `ADMIN_PASSWORD`（只在未设置时生效）或 `docker compose exec nyapassword nyapassword-server admin-password`；建议再开 TOTP：管理后台“管理员”页，或 `... nyapassword-server admin-totp`（手机丢了用 `admin-totp --off` 关闭）。

## 管理后台

左侧导航，每项一页（手机上收进左上角菜单）：

| 页面 | 内容 |
|---|---|
| 概览 | 状态卡片；**待处理清单**（没有备份目标、没有离线恢复密钥、没有告警通道、备份失败或超过 26 小时、自动校验失败、管理员没开 TOTP、手动恢复演练超过 90 天），点一项直接跳到修复它的页面 |
| 备份 | 上次成功、下次计划、有没有未备份的变更、“立即备份”；备份目标列表（测试连接、编辑、停用、删除）；“添加目标”向导：选类型（阿里云 OSS / WebDAV / 服务器上的目录）→ 填写 → 测试连接 → 保存；最近备份记录 |
| 恢复密钥 | 离线恢复密钥（原“备份接收者”）。“生成离线恢复密钥”在浏览器里生成，私钥不发给服务器；下载或打印“备份恢复密钥”页（含恢复命令），勾选“我已保存”后才登记公钥。也可以粘贴已有的 `age1…` 公钥。服务器自己的密钥总是接收者 |
| 备份校验 | 每周自动校验（原“演练”）的结果和“立即校验”；每季度用离线恢复密钥做一次手动恢复演练的步骤，做完点“标记为已完成” |
| 告警通知 | Webhook、Telegram、Bark、邮件（SMTP）各一行：已配置 / 未配置、开关；点开填写，单独“发送测试”（不用先保存）；选择哪些事件通知（备份失败、校验失败、太久没有成功备份） |
| 计划与保留 | 变更后等待几分钟、每日备份时间（按浏览器时区显示）、保留份数（最近 / 每日 / 每周 / 每月） |
| 账户与设备、邀请码、审计日志 | 同前 |
| 管理员 | 修改管理员密码、开关两步验证（TOTP）；都要再输一次当前密码 |

## 备份

在管理后台配置：

1. **恢复密钥**：在“恢复密钥”页点“生成离线恢复密钥”，下载或打印，和紧急恢复包放在一起，**不要只存在密码库或服务器上**，再确认登记。不想在浏览器里生成时，在一台离线电脑上运行 `nyapassword-server age-keygen`，把公钥（`age1...`）粘贴进去。
2. **备份目标**（“备份 → 添加目标”）：
   - 阿里云 OSS：建议给服务器一个只有 `oss:PutObject`、`oss:GetObject`、`oss:ListObjects` 权限的 AccessKey，桶开版本控制 / 合规保留策略，勾选“防删模式”（服务端不再清理，过期交给生命周期规则）。
   - WebDAV（坚果云、NAS 等）：服务端按保留策略清理旧备份。
   - 服务器上的目录（如挂载的 NAS；Docker 部署时先把目录映射进容器）。
3. 向导里的“测试连接”会写入、读回、删除一个探测文件；防删模式下删除失败是预期的。
4. **告警通知**至少开一个渠道，用“发送测试”确认收得到。

之后：有变更 10 分钟后自动备份（每小时最多一次）、每天定时一次；上传后读回校验；每周自动校验（下载最新备份、用服务器自己的密钥解密、检查数据库）；超过 26 小时没有成功备份会告警。

## 恢复

服务器（连同数据目录）没了时，用离线私钥从备份目标直接恢复：

```bash
nyapassword-server restore --identity offline.key --to ./data \
  --kind oss --endpoint https://oss-cn-hangzhou.aliyuncs.com --bucket <桶> --root <目录> \
  --username <AccessKeyId>       # 私钥口令用环境变量 NYAPASSWORD_RESTORE_SECRET 传
nyapassword-server restore --identity offline.key --file ./nyapassword-....tar.zst.age --to ./data
```

`--identity` 可以直接用管理后台下载的 `nyapassword-recovery-key.txt`（`#` 开头的说明行会被跳过）。加 `--dry-run` 只下载、解密、校验，不写任何东西（建议每季度做一次手动演练，做完在“备份校验”页标记）。恢复后数据库的 epoch 会变，所有客户端下次同步时自动对账，并把比备份新的内容重新上传。

## 发布

```powershell
.\scripts\release.ps1 0.1.0          # 改 VERSION / Cargo.toml、写 COMMON_REF、提交并打 tag
git push origin HEAD v0.1.0
```

推送 tag 后 GitHub Actions 测试（固定的 common 提交）、构建 `ghcr.io/<owner>/nyapassword-server`（amd64 + arm64，正式版另打 `MAJOR.MINOR` 和 `latest`），并发布带部署文件的 Release。CI 用 `COMMON_DEPLOY_KEY`（common 仓库的只读部署密钥）检出私有的 common 仓库。
