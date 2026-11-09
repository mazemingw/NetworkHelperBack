# 全局错误上报

**必须先发布后台，再使用新版客户端联调。** 同步发布 `server.js`、`diagnostics.js`、`diagnostic-storage.js`、`diagnostic-archive.js`、`find-diagnostic.js`，按下文核对 OSS 配置后重启原 Node 服务；无需数据库迁移或安装新依赖。客户端旧版不会调用这些接口。修改本地仓库不代表线上已经发布。

默认保存于后台目录 `data/diagnostics/`，JSON 使用 gzip 压缩，仅服务进程可读写，不提供静态目录或公开下载接口。容器部署务必通过 `DIAGNOSTIC_REPORT_DIR` 指向持久化、非网站公开目录。备份或迁移目录时同时保留 `clients/`；该目录存安装级令牌哈希，不存明文令牌，日志清理不会删除它。

## 每小时 OSS 归档与本地容量

服务启动时执行一次归档，之后每个整点执行；即使没有新请求也会清理。任务不重叠，直接上传现有 `.json.gz`，不在服务器额外生成整包副本。OSS 路径默认 `DIAGNOSTICS/YYYY-MM-DD/回执码.json.gz`，设置私有 ACL、禁止覆盖，并下载流核对大小与 SHA-256 后才记录归档成功。每日 `.oss-index.json` 避免重复上传已核验且未变更的文件。

复用 `OSS_ACCESS_KEY_ID`、`OSS_ACCESS_KEY_SECRET` 和可选 `OSS_SECURITY_TOKEN`。桶和地域默认复用 `OSS_BUCKET` / `OSS_REGION`，也可通过 `DIAGNOSTIC_OSS_BUCKET` / `DIAGNOSTIC_OSS_REGION` 独立指定；路径前缀为 `DIAGNOSTIC_OSS_PREFIX`，默认 `DIAGNOSTICS`。为对应前缀授予 `PutObject`、`GetObject`、`GetObjectAcl` 权限。后台不删除 OSS 日志、不设置过期时间；若要长期保留，还需确认桶已有生命周期规则不会清理该前缀。

本地日志**固定只保留 7 天**，旧 `DIAGNOSTIC_RETENTION_DAYS` 配置不再生效。另有默认 1 GiB 的压缩日志额度（`DIAGNOSTIC_MAX_LOCAL_BYTES=1073741824`），并预留 256 MiB 文件系统空闲空间。容量不足时接口返回 503，触发额外归档并清理已核验的较早日志以腾出空间；客户端保留有界待发队列。7 天以内且未核验归档的日志不会为了额度而删除。

**超过 7 天按硬上限删除，即使 OSS 当时不可用。** 每轮先尝试归档；连续 3 次云端失败后暂停本轮云端尝试，下次任务再重试，清理仍执行。归档失败、校验失败、索引写入失败及未归档过期删除数量均会告警。最新结果在 `data/diagnostics/archive-status.json`（自定义根目录时随之变化）；部署后检查 `configurationError`、`failed`、`indexWriteFailed`、`unarchivedExpired` 等字段。`unarchivedExpired > 0` 表示发生未成功归档的过期删除，不能视为云端已有副本。

## POST /networkhelp/diagnostics/register

JSON：`installationId` 为客户端生成的 UUID v4；`secret` 为客户端生成的 32 字节安全随机数的小写十六进制。重复注册必须验证原 secret，不能覆盖旧凭据。成功返回 `{ "ok": true }`。

## POST /networkhelp/diagnostics/reports

请求头 `Authorization: Bearer <installationId>.<secret>`，JSON 最大 512 KiB。schema 1 字段：

| 字段 | 内容 |
| --- | --- |
| `id` / `occurredAt` | UUID v4 / 客户端发生时间（毫秒） |
| `source` / `severity` | 模块来源 / `error` 或 `fatal` |
| `message` / `stack` | 错误摘要 / 异常堆栈 |
| `device` | 机型、SoC、Android/系统/安全补丁/基带/内核、应用版本及 APK SHA-256、ABI、内存、剩余空间、网络类型 |
| `device.imei1` / `imeiSlot` / `imeiSource` | 复用 IMEI1/SIM0，无法读取时为 null 并说明来源；不能因 IMEI 丢失而丢掉错误报告 |
| `breadcrumbs` / `context` | 脱敏的近期上下文、模块诊断信息；EFS 失败附已有后台日志，备份错误附只读分区映射及 rmt_storage/rmtfs 打开设备 |

成功返回 `{ "ok": true, "id": "原报告 UUID", "receiptCode": "NH-YYYYMMDD-0123456789ABCDEF" }`。同日重复上报相同安装、相同 UUID 不覆盖已收文件，回执稳定。文件名直接使用回执码，不包含 IMEI；只有私有报告内的 `device.imei1` 保留 IMEI，其他文本再次脱敏。生产反向代理应使用 HTTPS，避免记录请求体和 Authorization 头，并允许自动错误接口 512 KiB、手动监控台接口 16 MiB 请求体。没有公开浏览或下载日志的 API；管理员通过服务器文件系统读取。

## POST /networkhelp/diagnostics/console

手动上传监控台，沿用相同安装级鉴权，容量上限 16 MiB。报告头与 `/reports` 相同，但 `severity` 固定 `info`，额外包含 1–12800 个 `entries`。每条含 `firstAt`、`lastAt`（毫秒）、`level`（`INFO`、`WARNING`、`ERROR`）、`source`（最多 100 字符）、`message`（1200 字符）、`detail`（6000 字符）、`repeats`（1–1000000）。客户端只上传当前筛选的记录。自动上报关闭时，用户仍可主动上传。部署时需同步将反向代理此路径的请求体上限配置为至少 16 MiB。

返回回执后，客户端提供“复制回执”和“最近回执”。后台文件位于 `data/diagnostics/YYYY-MM-DD/NH-YYYYMMDD-0123456789ABCDEF.json.gz`。管理员可在后台目录执行：

```powershell
node find-diagnostic.js NH-YYYYMMDD-0123456789ABCDEF
```

脚本读取原 `.env`，优先输出本地文件路径；本地已清理时查询 OSS 并输出私有对象位置，不生成公开链接。若本地没有文件，可下载云端副本到一个不存在的目标文件：

```powershell
node find-diagnostic.js NH-YYYYMMDD-0123456789ABCDEF --download ./receipt.json.gz
```

已部署的旧 `/reports` 接口仍兼容原客户端。

状态码：400 格式错误、401 未注册/缺少鉴权、403 凭据不匹配、413 超出大小、429 频率限制、503 存储不可用。客户端保留有界离线队列，采用系统任务的指数退避重试；404/503 等部署前失败不会阻塞业务或解除 EFS 写入保护。

客户端设置右上角日志图标进入监控台；“自动错误上报”默认开启，关闭会取消待发任务、在途请求并清空待发标记。监控台清除同时删除本地报告及待发标记；分享/导出始终脱敏，不调用 IMEI 读取器。控制台上限 16 MiB，另有 12800 条记录上限，重复日志 60 秒合并，新增日志每秒最多 30 条。logcat 按线程和标签聚合异常堆栈，不再逐帧上传；没有异常头的堆栈片段仅记警告。自动报告同类错误每 10 分钟最多一份、全局每小时最多 20 份，配额持久化，重启和清除日志均不会重置。系统图形/WebView、已知厂商反射噪声降为信息，预期基带拒绝降为警告，不自动上报。保留堆栈中的公开 R8 映射标识及 `device.apkSha256`，用于匹配对应构建；其他敏感字段继续脱敏。

本地后端检查：`node --check diagnostic-archive.js`、`node --test diagnostics.test.js diagnostic-archive.test.js`。测试仅使用合成标识、临时目录、回环 HTTP 和 OSS 替身，不上传真机日志、不操作真实 OSS 对象。后端接口测试不依赖 Android 构建，也不生成 APK。
