# 欧加网络助手后台（NetworkHelperBack）

[English](README.en.md)

[欧加网络助手 Android 客户端](https://github.com/mazemingw/oplus-network-helper)的 Node.js / Express / MySQL 服务，提供版本更新、公告、LTE/NR 工参查询与维护、附近基站查询、开发者鉴权和工程插件分享接口。

原创代码采用 [Apache License 2.0](LICENSE)。仓库包含源码、建表结构与配置示例，不包含生产数据库内容、真实环境配置或管理员凭据。

## 运行

需要 Node.js 18 或更高版本、npm 和 MySQL。`schema.sql` 使用现有数据库导出的 MySQL 建表语法，包含 8 张业务表。

```powershell
npm ci
Copy-Item .env.example .env
```

填写 `.env` 的数据库地址、用户名、密码、库名与端口。先创建目标数据库，并将 `schema.sql` 导入该库，例如在 MySQL 客户端执行：

```sql
CREATE DATABASE IF NOT EXISTS NetworkHelper CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE NetworkHelper;
SOURCE schema.sql;
```

建表文件使用 `CREATE TABLE IF NOT EXISTS`，不导入记录、不删除旧表，也不迁移已有表结构。已有完整数据库可直接使用原 `.env`；附近基站功能无需改表。新库为空，需要自行导入获准使用的工参数据与应用配置。

配置 `DEV_AUTH_TOKEN_SECRET` 为独立随机值，例如执行以下命令生成后写入 `.env`：

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
npm start
```

默认端口 `9895`，路由前缀 `/networkhelp`。现有部署未指定令牌密钥时兼容使用 `DB_PASSWORD`；二者都为空时使用进程随机值，重启会使旧令牌失效。生产部署应显式设置独立令牌密钥。

开发者账号由 `dev_auth_credentials` 表的角色、SHA-256 密码哈希和启用状态配置，支持 `developer`、`super_admin`。仓库不提供默认账号或密码。真实凭据初始化文件 `dev_auth_credentials.sql` 已忽略。

插件分享需要额外设置 OSS 环境变量，不使用该功能时可留空。OSS/STS 的权限、桶与网络配置由部署者管理。

## LTE 扩展信息

`lte_cell_params.extra_info` 保存逗号分隔的附加业务信息，字段名或值中的逗号、等号、反斜杠分别转义为 `\,`、`\=`、`\\`。`station_type` 为 `default`（普通 LTE）或 `nb-iot`；原 `site_type` 仍表示宏站、室分、微站等物理站型。

小区查询、站址查询（含 `anchor`）和附近基站查询返回这两个字段。LTE 更新及批量导入接受对应的下划线或驼峰字段名；旧客户端上传时省略它们，会保留已有扩展信息。现有数据库需已具备这两列，`schema.sql` 不会自动升级已有表。

## 附近基站

`POST /networkhelp/cell-params/nearby` 支持 1–10 km 圆形查询，制式与频段可独立指定或省略：

```json
{
  "latitude": 31.2304,
  "longitude": 121.4737,
  "radius_km": 3,
  "rat": "NR",
  "band": "n78"
}
```

- 不指定 `rat` / `band`：4G + 5G 全频段。
- 仅指定 `rat`：4G 或 5G 的全部频段。
- 仅指定数字 `band`：匹配两种制式的同号频段；`B` / `n` 前缀限定制式。
- 同时指定：筛选目标制式与 Band，冲突前缀返回 HTTP 400。

坐标使用 WGS84。先进行地理边界与频点筛选，再计算圆形距离并排序；每种制式最多返回最近 1000 个小区，并标记结果截断。完整参数、频段匹配限制及错误码见 [nearby-api.md](nearby-api.md)。

现有部署更新时同时发布 `routes.js`、`nearby.js`、`nearby-bands.js` 并重启原 Node 服务。本仓库推送不等同于线上部署。

## 接口范围

全局错误上报的部署要求、私有日志存储及 POST 协议见 [diagnostics-api.md](diagnostics-api.md)。**先发布后台并重启服务，再用新版客户端联调**；无需改表。日志启动时及每小时归档到私有 OSS，本地最多保留 7 天，默认额度 1 GiB；复用现有 OSS 配置并核对 `DIAGNOSTICS/*` 权限。OSS 副本不由后台定期删除。

所有路由均位于 `/networkhelp` 下，当前使用 POST：

| 路由组 | 用途 |
| --- | --- |
| `/version-updates`、`/version-updates/legacy` | 版本查询与对应创建/更新/删除接口 |
| `/app-info`、`/announcements` | 应用信息、公告与维护接口 |
| `/lte/cell-params/*`、`/lte/site/query` | LTE 查询、站址查询与工参维护 |
| `/nr/cell-params/*`、`/nr/site/query` | NR 查询、站址查询与工参维护 |
| `/cell-params/nearby` | 按半径、制式、Band 查询附近小区 |
| `/dev-auth/verify-password` | 开发者密码校验与令牌签发 |
| `/plugin-share/*` | OSS 上传签名、下载候选与上传结果登记 |

各维护路由的鉴权要求以 `routes.js` 为准；本服务没有为全部读写路由统一增加鉴权。部署时按现有业务接入访问控制。

## 检查与测试

```powershell
npm run check
npm test
```

回归测试使用注入的数据库替身及临时本地 HTTP 服务，不需要连接生产数据库。覆盖参数校验、制式/Band 组合、筛选前置、球面距离、跨日期变更线/极区查询及结果截断。此次也对现有 MySQL 库核对了半径与频段筛选，没有导出记录或修改业务数据。

## 文件

```text
server.js          Express 启动与路由前缀
db.js              从环境变量读取 MySQL 连接池配置
routes.js          现有业务接口及附近查询路由注册
nearby.js          附近基站查询与距离计算
nearby-bands.js    LTE/NR 下行频点范围及筛选参数
nearby.test.js     附近查询回归测试
nearby-api.md      接口说明
schema.sql         仅建表，无账号与业务记录
.env.example       本地配置模板
```

## 许可证

本项目原创代码采用 Apache-2.0；依赖项保留各自许可证，见其包内声明及锁文件。
