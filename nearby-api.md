# 附近基站查询

`POST /networkhelp/cell-params/nearby`

```json
{
  "latitude": 31.2304,
  "longitude": 121.4737,
  "radius_km": 3,
  "rat": "LTE",
  "band": "B3"
}
```

坐标使用 WGS84，半径支持 1–10 km。`rat`、`band` 都可省略、设为 `null` 或空字符串。

| rat | band | 查询范围 |
| --- | --- | --- |
| 省略 | 省略 | 4G + 5G，全部频段 |
| LTE / 4G | 省略 | 仅 4G，全部频段 |
| NR / 5G | 省略 | 仅 5G，全部频段 |
| LTE / 4G | 3 或 B3 | 仅 4G B3 |
| NR / 5G | 78 或 n78 | 仅 5G n78 |
| 省略 | 3 | 4G B3 + 5G n3 |
| 省略 | B3 | 仅 4G B3 |
| 省略 | n78 | 仅 5G n78 |

制式及 Band 前缀不区分大小写；`rat: "ALL"` 表示全部。Band 支持整数或字符串。
不支持的 Band 返回 HTTP 400 `invalid_band`，不支持的制式返回 `invalid_rat`，
制式与 Band 前缀冲突（例如 `LTE` + `n78`）返回 `band_rat_mismatch`。

响应保持 `lte`、`nr` 两个数组；未选中的制式返回空数组。
`rat`、`band` 回显规范化的筛选条件，未指定时为 `null`。
筛选在 SQL 中、按距离排序和截断之前执行；每种制式最多返回最近的 1000 个小区。
`lte_truncated`、`nr_truncated`、`truncated` 指示是否还有更多匹配结果。

工参库没有独立 Band 字段，本接口按下行 EARFCN / NR-ARFCN 范围筛选。
NR 频段可能重叠，例如同一频点可能同时匹配 n77 和 n78；不能据此确定基站实际配置的 Band。
筛选使用频段的频点范围，不对信道带宽、栅格步进或 SUL 做推断。
支持的下行范围维护在 `nearby-bands.js`，依据
[3GPP TS 36.104 表 5.7.3-1](https://www.etsi.org/deliver/etsi_ts/136100_136199/136104/18.05.00_60/ts_136104v180500p.pdf) 和
[3GPP TS 38.104 表 5.4.2.3-1/2](https://www.etsi.org/deliver/etsi_ts/138100_138199/138104/18.09.00_60/ts_138104v180900p.pdf)。

运行接口回归测试：`node --test nearby.test.js`。
更新服务时同时发布 `routes.js`、`nearby.js`、`nearby-bands.js` 并重启 Node 服务，无需改表。
