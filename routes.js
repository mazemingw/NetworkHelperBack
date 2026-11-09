const express = require("express");
const router = express.Router();
const db = require("./db");
router.use('/efs-backups', require('./efs-backups').createEfsBackupRouter(db));
router.use(require("./nearby").createNearbyRouter(db));
const crypto = require("crypto");
const PopCore = require("@alicloud/pop-core");
const OSS = require("ali-oss");


function chunkArray(arr, size) {
  const result = [];
  for (let i = 0; i < arr.length; i += size) {
    result.push(arr.slice(i, i + size));
  }
  return result;
}

function toNull(v) {
  if (v === undefined || v === null) return null;
  if (typeof v === "string" && v.trim() === "") return null;
  return v;
}

function toIntOrNull(v) {
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function toFloatOrNull(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function sha256Hex(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

function normalizeDevRole(role) {
  const v = String(role ?? "").trim().toLowerCase();
  if (v === "developer") return "developer";
  if (v === "super_admin") return "super_admin";
  return null;
}

const DEV_AUTH_TOKEN_SECRET = String(
  process.env.DEV_AUTH_TOKEN_SECRET || process.env.DB_PASSWORD || crypto.randomBytes(32).toString("hex")
);
const DEV_AUTH_TOKEN_TTL_MS = Number(process.env.DEV_AUTH_TOKEN_TTL_MS || 12 * 60 * 60 * 1000);

function base64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(String(input));
  return buf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64urlDecodeToString(input) {
  const s = String(input).replace(/-/g, "+").replace(/_/g, "/");
  const padded = s + "===".slice((s.length + 3) % 4);
  return Buffer.from(padded, "base64").toString("utf8");
}

function issueDevAuthToken(role) {
  const now = Date.now();
  const payload = {
    role,
    iat: now,
    exp: now + Math.max(60_000, DEV_AUTH_TOKEN_TTL_MS)
  };
  const payloadEncoded = base64urlEncode(JSON.stringify(payload));
  const sign = crypto
    .createHmac("sha256", DEV_AUTH_TOKEN_SECRET)
    .update(payloadEncoded)
    .digest();
  const signature = base64urlEncode(sign);
  return {
    token: `${payloadEncoded}.${signature}`,
    expiresAtMs: payload.exp
  };
}

function verifyDevAuthToken(token) {
  const raw = String(token ?? "").trim();
  if (!raw || !raw.includes(".")) return null;

  const [payloadEncoded, signature] = raw.split(".", 2);
  if (!payloadEncoded || !signature) return null;

  const expected = base64urlEncode(
    crypto.createHmac("sha256", DEV_AUTH_TOKEN_SECRET).update(payloadEncoded).digest()
  );
  if (expected !== signature) return null;

  let payload;
  try {
    payload = JSON.parse(base64urlDecodeToString(payloadEncoded));
  } catch {
    return null;
  }

  const role = normalizeDevRole(payload?.role);
  const exp = Number(payload?.exp);
  if (!role || !Number.isFinite(exp) || exp <= Date.now()) return null;

  return { role, exp };
}

function requireSuperAdmin(req, res) {
  const token = toNull(req.body?.auth_token) || toNull(req.headers["x-dev-auth-token"]);
  if (!token) {
    res.status(401).json({ ok: false, error: "auth_token_required" });
    return null;
  }

  const payload = verifyDevAuthToken(token);
  if (!payload) {
    res.status(401).json({ ok: false, error: "auth_token_invalid_or_expired" });
    return null;
  }

  if (payload.role !== "super_admin") {
    res.status(403).json({ ok: false, error: "super_admin_required" });
    return null;
  }

  return payload;
}

function normalizeOssPathSegment(v, fallback = "unknown") {
  const s = String(v ?? "").trim();
  if (!s) return fallback;
  return s
    .replace(/[\\\/]+/g, "_")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 96) || fallback;
}

function normalizeOssFileName(v, fallback = "plugin-release.zip") {
  const s = String(v ?? "").trim();
  if (!s) return fallback;
  const cleaned = s
    .replace(/[\\\/]+/g, "_")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .slice(0, 128);
  return cleaned || fallback;
}

async function getStsCredentials({
  accessKeyId,
  accessKeySecret,
  bucket,
  objectPrefix,
  durationSeconds,
  tokenName
}) {
  const stsClient = new PopCore({
    accessKeyId,
    accessKeySecret,
    endpoint: "https://sts.aliyuncs.com",
    apiVersion: "2015-04-01"
  });

  const policy = {
    Version: "1",
    Statement: [
      {
        Effect: "Allow",
        Action: ["oss:PutObject"],
        Resource: [`acs:oss:*:*:${bucket}/${objectPrefix}*`]
      }
    ]
  };

  const resp = await stsClient.request(
    "GetFederationToken",
    {
      Name: tokenName,
      DurationSeconds: durationSeconds,
      Policy: JSON.stringify(policy)
    },
    { method: "POST" }
  );

  const token = resp?.FederationToken;
  if (!token?.AccessKeyId || !token?.AccessKeySecret || !token?.SecurityToken) {
    throw new Error("invalid_sts_response");
  }

  return {
    accessKeyId: token.AccessKeyId,
    accessKeySecret: token.AccessKeySecret,
    securityToken: token.SecurityToken,
    expiration: token.Expiration || null
  };
}

function buildSignedDownloadUrl({
  region,
  bucket,
  key,
  accessKeyId,
  accessKeySecret,
  securityToken,
  expiresSeconds
}) {
  const client = new OSS({
    region: `oss-${region}`,
    bucket,
    accessKeyId,
    accessKeySecret,
    stsToken: securityToken || undefined,
    secure: true
  });
  return client.signatureUrl(key, {
    method: "GET",
    expires: expiresSeconds
  });
}

// 开发者密码鉴权（普通开发者 / 超级管理员）
router.post("/dev-auth/verify-password", async (req, res) => {
  const password = String(req.body?.password ?? "").trim();
  if (!password) {
    return res.status(400).json({ ok: false, error: "password_required" });
  }

  const pwdHash = sha256Hex(password);

  try {
    const [rows] = await db.execute(
      `SELECT role
       FROM dev_auth_credentials
       WHERE is_enabled = 1
         AND password_sha256 = ?
       ORDER BY CASE role WHEN 'super_admin' THEN 0 ELSE 1 END
       LIMIT 1`,
      [pwdHash]
    );

    if (!Array.isArray(rows) || rows.length === 0) {
      return res.status(401).json({ ok: false, error: "invalid_password" });
    }

    const role = normalizeDevRole(rows[0]?.role);
    if (!role) {
      return res.status(500).json({ ok: false, error: "invalid_role_config" });
    }

    const session = issueDevAuthToken(role);

    return res.json({
      ok: true,
      role,
      role_label: role === "super_admin" ? "超级管理员" : "普通开发者",
      auth_token: session.token,
      expires_at_ms: session.expiresAtMs
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});


// 鑾峰彇鏈€鍚庝竴涓増鏈洿鏂颁俊鎭紙鍙幏鍙栨渶鏂颁竴鏉★紝骞舵洿鏂拌闂鏁帮級
router.post("/version-updates", async (req, res) => {
  try {
    // 鑾峰彇鏈€鏂扮殑鐗堟湰淇℃伅
    const [rows] = await db.execute(
      "SELECT * FROM app_version_updates ORDER BY release_date DESC LIMIT 1",
    );

    // 濡傛灉鏈夋渶鏂扮殑鐗堟湰璁板綍
    if (rows.length > 0) {
      const version = rows[0];

      // 鏇存柊璁块棶娆℃暟
      await db.execute(
        "UPDATE app_version_updates SET view_count = view_count + 1 WHERE id = ?",
        [version.id],
      );

      // 杩斿洖鏈€鏂扮殑鐗堟湰淇℃伅锛屽苟鍖呭惈璁块棶娆℃暟
      const [updatedVersion] = await db.execute(
        "SELECT * FROM app_version_updates WHERE id = ?",
        [version.id],
      );
      res.json(updatedVersion[0]);
    } else {
      res.status(404).json({ error: "No version updates found" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 获取 legacy 版本最新更新信息（只获取最新一条，并更新访问次数）
router.post("/version-updates/legacy", async (req, res) => {
  try {
    const [rows] = await db.execute(
      "SELECT * FROM app_version_legacy_updates ORDER BY release_date DESC LIMIT 1",
    );

    if (rows.length > 0) {
      const version = rows[0];

      await db.execute(
        "UPDATE app_version_legacy_updates SET view_count = view_count + 1 WHERE id = ?",
        [version.id],
      );

      const [updatedVersion] = await db.execute(
        "SELECT * FROM app_version_legacy_updates WHERE id = ?",
        [version.id],
      );
      res.json(updatedVersion[0]);
    } else {
      res.status(404).json({ error: "No legacy version updates found" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 娣诲姞鐗堟湰鏇存柊淇℃伅
router.post("/version-updates/create", async (req, res) => {
  const {
    version_code,
    version_name,
    update_content,
    release_date,
    is_mandatory,
    download_url,
  } = req.body;
  try {
    const [result] = await db.execute(
      "INSERT INTO app_version_updates (version_code, version_name, update_content, release_date, is_mandatory, download_url) VALUES (?, ?, ?, ?, ?, ?)",
      [
        version_code,
        version_name,
        update_content,
        release_date,
        is_mandatory,
        download_url,
      ],
    );
    res
      .status(201)
      .json({ message: "Version update created", id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 添加 legacy 版本更新信息
router.post("/version-updates/legacy/create", async (req, res) => {
  const {
    version_code,
    version_name,
    update_content,
    release_date,
    is_mandatory,
    download_url,
  } = req.body;
  try {
    const [result] = await db.execute(
      "INSERT INTO app_version_legacy_updates (version_code, version_name, update_content, release_date, is_mandatory, download_url) VALUES (?, ?, ?, ?, ?, ?)",
      [
        version_code,
        version_name,
        update_content,
        release_date,
        is_mandatory,
        download_url,
      ],
    );
    res
      .status(201)
      .json({ message: "Legacy version update created", id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鏇存柊鐗堟湰鏇存柊淇℃伅
router.post("/version-updates/update", async (req, res) => {
  const {
    id,
    version_code,
    version_name,
    update_content,
    release_date,
    is_mandatory,
    download_url,
  } = req.body;
  try {
    const [result] = await db.execute(
      "UPDATE app_version_updates SET version_code = ?, version_name = ?, update_content = ?, release_date = ?, is_mandatory = ?, download_url = ? WHERE id = ?",
      [
        version_code,
        version_name,
        update_content,
        release_date,
        is_mandatory,
        download_url,
        id,
      ],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Version update not found" });
    }
    res.json({ message: "Version update updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 更新 legacy 版本更新信息
router.post("/version-updates/legacy/update", async (req, res) => {
  const {
    id,
    version_code,
    version_name,
    update_content,
    release_date,
    is_mandatory,
    download_url,
  } = req.body;
  try {
    const [result] = await db.execute(
      "UPDATE app_version_legacy_updates SET version_code = ?, version_name = ?, update_content = ?, release_date = ?, is_mandatory = ?, download_url = ? WHERE id = ?",
      [
        version_code,
        version_name,
        update_content,
        release_date,
        is_mandatory,
        download_url,
        id,
      ],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Legacy version update not found" });
    }
    res.json({ message: "Legacy version update updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鍒犻櫎鐗堟湰鏇存柊淇℃伅
router.post("/version-updates/delete", async (req, res) => {
  const { id } = req.body;
  try {
    const [result] = await db.execute(
      "DELETE FROM app_version_updates WHERE id = ?",
      [id],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Version update not found" });
    }
    res.json({ message: "Version update deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 删除 legacy 版本更新信息
router.post("/version-updates/legacy/delete", async (req, res) => {
  const { id } = req.body;
  try {
    const [result] = await db.execute(
      "DELETE FROM app_version_legacy_updates WHERE id = ?",
      [id],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Legacy version update not found" });
    }
    res.json({ message: "Legacy version update deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鑾峰彇App鍩虹淇℃伅锛堟煡璇級
router.post("/app-info", async (req, res) => {
  try {
    const [rows] = await db.execute("SELECT * FROM app_info LIMIT 1");
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鏇存柊App鍩虹淇℃伅
router.post("/app-info/update", async (req, res) => {
  const {
    id,
    app_name,
    app_version,
    app_package,
    min_sdk_version,
    target_sdk_version,
    app_icon_url,
  } = req.body;
  try {
    const [result] = await db.execute(
      "UPDATE app_info SET app_name = ?, app_version = ?, app_package = ?, min_sdk_version = ?, target_sdk_version = ?, app_icon_url = ? WHERE id = ?",
      [
        app_name,
        app_version,
        app_package,
        min_sdk_version,
        target_sdk_version,
        app_icon_url,
        id,
      ],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "App info not found" });
    }
    res.json({ message: "App info updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鑾峰彇App鍏憡锛堟煡璇㈡墍鏈夛級
router.post("/announcements", async (req, res) => {
  try {
    const [rows] = await db.execute(
      "SELECT * FROM app_announcements ORDER BY announcement_date DESC",
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 娣诲姞App鍏憡
router.post("/announcements/create", async (req, res) => {
  const { title, content, announcement_date } = req.body;
  try {
    const [result] = await db.execute(
      "INSERT INTO app_announcements (title, content, announcement_date) VALUES (?, ?, ?)",
      [title, content, announcement_date],
    );
    res
      .status(201)
      .json({ message: "Announcement created", id: result.insertId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鏇存柊App鍏憡
router.post("/announcements/update", async (req, res) => {
  const { id, title, content, announcement_date } = req.body;
  try {
    const [result] = await db.execute(
      "UPDATE app_announcements SET title = ?, content = ?, announcement_date = ? WHERE id = ?",
      [title, content, announcement_date, id],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Announcement not found" });
    }
    res.json({ message: "Announcement updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鍒犻櫎App鍏憡
router.post("/announcements/delete", async (req, res) => {
  const { id } = req.body;
  try {
    const [result] = await db.execute(
      "DELETE FROM app_announcements WHERE id = ?",
      [id],
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Announcement not found" });
    }
    res.json({ message: "Announcement deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 鏌ヨ LTE 宸ュ弬锛堜富鏌ヨ + 澶氱骇 fallback锛?
// 鏌ヨ LTE 宸ュ弬锛堜富鏌ヨ + 澶氱骇 fallback锛?
// 鏀归€犵偣锛?
// 1. 涓嶅啀鎶娾€滄煡涓嶅埌 / 鏉′欢涓嶅叏鈥濆綋 HTTP 400
// 2. 鍙璇锋眰鏍煎紡鍚堟硶锛岀粺涓€杩斿洖 200
// 3. eci 鏌ヨ涓嶅啀寮虹粦 tac / earfcn
router.post("/lte/cell-params/query", async (req, res) => {
  const { tac, earfcn, pci, cell_id, eci } = req.body;
  const MAX_RETURN = 50;

  const qTac = toIntOrNull(tac);
  const qEarfcn = toIntOrNull(earfcn);
  const qPci = toIntOrNull(pci);
  const qCellIdInput = toIntOrNull(cell_id);
  const qEci = toIntOrNull(eci);
  const qEnbFromEci = qEci != null ? Math.floor(qEci / 256) : null;
  const qCellIdFromEci = qEci != null ? ((qEci % 256) + 256) % 256 : null;
  const qCellId = qCellIdInput != null ? qCellIdInput : qCellIdFromEci;

  const empty = (matchLevel = "not_found", reason = null, extra = {}) => ({
    match_level: matchLevel,
    count: 0,
    total_count: 0,
    truncated: false,
    data: [],
    reason,
    ...extra
  });

  const ok = (matchLevel, total, rows, reason = null) => ({
    match_level: matchLevel,
    count: rows.length,
    total_count: total,
    truncated: total > rows.length,
    data: rows,
    reason
  });

  try {
    const countAndListByWhere = async (whereSql, params, orderBy = "created_at DESC") => {
      const [countRows] = await db.execute(
        `SELECT COUNT(*) AS total FROM lte_cell_params WHERE ${whereSql}`,
        params
      );
      const total = Number(countRows?.[0]?.total ?? 0);
      const [rows] = await db.execute(
        `SELECT *
         FROM lte_cell_params
         WHERE ${whereSql}
         ORDER BY ${orderBy}
         LIMIT ${MAX_RETURN}`,
        params
      );
      return { total, rows };
    };

    // ECI path: never degrade to wide tac+earfcn pool.
    if (qEci != null) {
      if (qTac != null) {
        const r = await countAndListByWhere("tac = ? AND eci = ?", [qTac, qEci]);
        if (r.total > 0) return res.json(ok("primary_tac_eci", r.total, r.rows));
      }

      {
        const r = await countAndListByWhere("eci = ?", [qEci]);
        if (r.total > 0) return res.json(ok("primary_eci", r.total, r.rows));
      }

      if (qTac != null && qEarfcn != null && qPci != null && qCellId != null) {
        const r = await countAndListByWhere(
          "tac = ? AND earfcn = ? AND pci = ? AND cell_id = ?",
          [qTac, qEarfcn, qPci, qCellId]
        );
        if (r.total > 0) {
          return res.json(ok("fallback_tac_earfcn_pci_cellid_from_eci", r.total, r.rows));
        }
      }

      if (qEnbFromEci != null && qCellId != null) {
        const r = await countAndListByWhere(
          "enodeb_id = ? AND cell_id = ?",
          [qEnbFromEci, qCellId]
        );
        if (r.total > 0) {
          return res.json(ok("fallback_enb_cellid_from_eci", r.total, r.rows));
        }
      }

      if (qEnbFromEci != null) {
        const [metaRows] = await db.execute(
          `SELECT COUNT(*) AS rows_cnt,
                  GROUP_CONCAT(DISTINCT cell_id ORDER BY cell_id) AS cell_ids
           FROM lte_cell_params
           WHERE enodeb_id = ?`,
          [qEnbFromEci]
        );
        const rowsCnt = Number(metaRows?.[0]?.rows_cnt ?? 0);
        if (rowsCnt > 0) {
          return res.json(
            empty(
              "enb_only_incomplete_from_eci",
              "eci not found; enodeb exists but target sector missing",
              {
                enodeb_id: qEnbFromEci,
                derived_cell_id: qCellId,
                candidate_count: rowsCnt,
                candidate_cell_ids: metaRows?.[0]?.cell_ids ?? null
              }
            )
          );
        }
      }

      return res.json(
        empty(
          "not_found_eci",
          "eci not found; strict fallback also missed",
          { enodeb_id: qEnbFromEci, derived_cell_id: qCellId }
        )
      );
    }

    if (qTac != null && qEarfcn != null && qPci != null && qCellId != null) {
      const r = await countAndListByWhere(
        "tac = ? AND earfcn = ? AND pci = ? AND cell_id = ?",
        [qTac, qEarfcn, qPci, qCellId]
      );
      if (r.total > 0) return res.json(ok("primary_tac_earfcn_pci_cellid", r.total, r.rows));

      const f1 = await countAndListByWhere(
        "tac = ? AND pci = ? AND cell_id = ?",
        [qTac, qPci, qCellId]
      );
      if (f1.total === 1) return res.json(ok("fallback_tac_pci_cellid", f1.total, f1.rows));
      if (f1.total > 1) {
        return res.json(
          empty("ambiguous_tac_pci_cellid", "multiple candidates; provide eci", {
            candidate_count: f1.total
          })
        );
      }

      const f2 = await countAndListByWhere(
        "pci = ? AND cell_id = ?",
        [qPci, qCellId]
      );
      if (f2.total === 1) return res.json(ok("fallback_pci_cellid", f2.total, f2.rows));
      if (f2.total > 1) {
        return res.json(
          empty("ambiguous_pci_cellid", "multiple candidates; provide eci", {
            candidate_count: f2.total
          })
        );
      }
    }

    if (qTac != null && qEarfcn != null && qPci != null) {
      const r = await countAndListByWhere(
        "tac = ? AND earfcn = ? AND pci = ?",
        [qTac, qEarfcn, qPci]
      );
      if (r.total === 1) return res.json(ok("fallback_tac_earfcn_pci", r.total, r.rows));
      if (r.total > 1) {
        return res.json(
          empty("ambiguous_tac_earfcn_pci", "multiple candidates; provide eci or cell_id", {
            candidate_count: r.total
          })
        );
      }
    }

    if (qTac != null && qEarfcn != null) {
      return res.json(
        empty(
          "invalid_query",
          "tac+earfcn is too broad; provide eci or (tac+earfcn+pci+cell_id)"
        )
      );
    }

    return res.json(empty("invalid_query", "insufficient query fields"));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 鏌ヨ鍚岀珯宸ュ弬锛堝懡涓敋鐐?+ 鎷夊悓绔?N 鏉★級鈥斺€斿寮虹増
router.post("/lte/site/query", async (req, res) => {
  const { tac, earfcn, pci, cell_id, eci } = req.body;

  const MAX_RETURN = 120;
  const GRID_SCALE = 1000; // 1e-3 ~= 111m

  const qTac = toIntOrNull(tac);
  const qEarfcn = toIntOrNull(earfcn);
  const qPci = toIntOrNull(pci);
  const qCellIdInput = toIntOrNull(cell_id);
  const qEci = toIntOrNull(eci);
  const qEnbFromEci = qEci != null ? Math.floor(qEci / 256) : null;
  const qCellIdFromEci = qEci != null ? ((qEci % 256) + 256) % 256 : null;
  const qCellId = qCellIdInput != null ? qCellIdInput : qCellIdFromEci;

  const siteEmpty = (matchLevel, reason = null, extra = {}) => ({
    match_level: matchLevel,
    site_match: "none",
    reason,
    anchor: null,
    enodeb_id: null,
    sector_count: 0,
    count: 0,
    total_count: 0,
    truncated: false,
    data: [],
    ...extra
  });

  if (qEci == null && (qTac == null || qEarfcn == null)) {
    return res.json(siteEmpty("invalid_query", "need eci or (tac + earfcn)"));
  }

  try {
    let anchor = null;
    let anchorLevel = "none";

    if (qEci != null) {
      const [rowsEci] = await db.execute(
        `SELECT *
         FROM lte_cell_params
         WHERE eci = ?
         ORDER BY created_at DESC
         LIMIT 1`,
        [qEci]
      );
      if (rowsEci.length) {
        anchor = rowsEci[0];
        anchorLevel = "eci";
      }

      if (!anchor && qEnbFromEci != null && qCellId != null) {
        const [rowsEnbCell] = await db.execute(
          `SELECT *
           FROM lte_cell_params
           WHERE enodeb_id = ? AND cell_id = ?
           ORDER BY created_at DESC
           LIMIT 1`,
          [qEnbFromEci, qCellId]
        );
        if (rowsEnbCell.length) {
          anchor = rowsEnbCell[0];
          anchorLevel = "enb_cellid_from_eci";
        }
      }

      if (!anchor && qEnbFromEci != null) {
        const [rowsEnbOnly] = await db.execute(
          `SELECT *
           FROM lte_cell_params
           WHERE enodeb_id = ?
           ORDER BY ABS(cell_id - ?) ASC, created_at DESC
           LIMIT 1`,
          [qEnbFromEci, qCellId ?? 0]
        );
        if (rowsEnbOnly.length) {
          anchor = rowsEnbOnly[0];
          anchorLevel = "enb_only_from_eci";
        }
      }

      if (!anchor) {
        return res.json(
          siteEmpty(
            "not_found_eci",
            "eci not found and no usable enodeb fallback",
            { enodeb_id: qEnbFromEci, derived_cell_id: qCellId }
          )
        );
      }
    }

    if (!anchor && qTac != null && qEarfcn != null && qPci != null && qCellIdInput != null) {
      const [rows] = await db.execute(
        `SELECT *
         FROM lte_cell_params
         WHERE tac = ? AND earfcn = ? AND pci = ? AND cell_id = ?
         ORDER BY created_at DESC
         LIMIT 1`,
        [qTac, qEarfcn, qPci, qCellIdInput]
      );
      if (rows.length) {
        anchor = rows[0];
        anchorLevel = "tac_earfcn_pci_cellid";
      }
    }

    if (!anchor && qTac != null && qEarfcn != null && qPci != null) {
      const [countRows] = await db.execute(
        `SELECT COUNT(*) AS total
         FROM lte_cell_params
         WHERE tac = ? AND earfcn = ? AND pci = ?`,
        [qTac, qEarfcn, qPci]
      );
      const total = Number(countRows?.[0]?.total ?? 0);
      if (total === 1) {
        const [rows] = await db.execute(
          `SELECT *
           FROM lte_cell_params
           WHERE tac = ? AND earfcn = ? AND pci = ?
           ORDER BY created_at DESC
           LIMIT 1`,
          [qTac, qEarfcn, qPci]
        );
        if (rows.length) {
          anchor = rows[0];
          anchorLevel = "tac_earfcn_pci_unique";
        }
      } else if (total > 1) {
        return res.json(
          siteEmpty("ambiguous_tac_earfcn_pci", "multiple anchors matched; provide eci or cell_id", {
            candidate_count: total
          })
        );
      }
    }

    if (!anchor && qTac != null && qEarfcn != null) {
      return res.json(
        siteEmpty(
          "invalid_query",
          "tac+earfcn is too broad for site anchor; provide eci or (pci+cell_id)"
        )
      );
    }

    if (!anchor) {
      return res.json(siteEmpty("not_found", "anchor not found"));
    }

    const enb = Number(anchor.enodeb_id ?? 0);
    const hasEnb = Number.isFinite(enb) && enb > 0;
    const lat = anchor.latitude;
    const lon = anchor.longitude;
    const hasLL = lat != null && lon != null;
    const glat = hasLL ? Math.floor(Number(lat) * GRID_SCALE) : null;
    const glon = hasLL ? Math.floor(Number(lon) * GRID_SCALE) : null;

    let siteRows = [];
    let siteTotal = 0;
    let siteLevel = hasEnb ? "site_enodeb_id" : "site_grid";

    if (hasEnb) {
      const [countRows] = await db.execute(
        `SELECT COUNT(*) AS total
         FROM lte_cell_params
         WHERE enodeb_id = ?`,
        [enb]
      );
      siteTotal = Number(countRows?.[0]?.total ?? 0);

      const [rows] = await db.execute(
        `SELECT *
         FROM lte_cell_params
         WHERE enodeb_id = ?
         ORDER BY
           (earfcn = ?) DESC,
           sector_id ASC,
           azimuth ASC,
           earfcn ASC,
           pci ASC
         LIMIT ${MAX_RETURN}`,
        [enb, qEarfcn ?? anchor.earfcn]
      );
      siteRows = rows;
    }

    // Grid fallback only when no enodeb anchor or enodeb has zero rows.
    const needGridFallback = (!hasEnb && hasLL) || (hasEnb && siteRows.length === 0 && hasLL);
    if (needGridFallback) {
      const [countRows2] = await db.execute(
        `SELECT COUNT(*) AS total
         FROM lte_cell_params
         WHERE FLOOR(latitude * ?) = ?
           AND FLOOR(longitude * ?) = ?`,
        [GRID_SCALE, glat, GRID_SCALE, glon]
      );
      const total2 = Number(countRows2?.[0]?.total ?? 0);

      const [rows2] = await db.execute(
        `SELECT *
         FROM lte_cell_params
         WHERE FLOOR(latitude * ?) = ?
           AND FLOOR(longitude * ?) = ?
         ORDER BY
           (earfcn = ?) DESC,
           (tac = ?) DESC,
           sector_id ASC,
           azimuth ASC,
           earfcn ASC,
           pci ASC
         LIMIT ${MAX_RETURN}`,
        [GRID_SCALE, glat, GRID_SCALE, glon, qEarfcn ?? anchor.earfcn, qTac ?? anchor.tac]
      );

      siteRows = rows2;
      siteTotal = total2;
      siteLevel = "site_grid";
    }

    const seen = new Set();
    const deduped = [];
    for (const r of siteRows) {
      const k = r.eci
        ? `eci:${r.eci}`
        : `k:${r.tac}:${r.earfcn}:${r.pci}:${r.cell_id ?? -1}`;
      if (seen.has(k)) continue;
      seen.add(k);
      deduped.push(r);
      if (deduped.length >= MAX_RETURN) break;
    }

    const sectorSet = new Set(deduped.map(r => r.sector_id).filter(v => v != null));
    const sectorCount = sectorSet.size;

    return res.json({
      match_level: anchorLevel,
      site_match: siteLevel,
      reason: null,
      anchor: {
        id: anchor.id,
        tac: anchor.tac,
        earfcn: anchor.earfcn,
        pci: anchor.pci,
        eci: anchor.eci,
        enodeb_id: anchor.enodeb_id,
        cell_id: anchor.cell_id,
        sector_id: anchor.sector_id,
        azimuth: anchor.azimuth,
        longitude: anchor.longitude,
        latitude: anchor.latitude,
        cell_name: anchor.cell_name,
        site_type: anchor.site_type,
        source: anchor.source,
      },
      enodeb_id: anchor.enodeb_id,
      sector_count: sectorCount,
      count: deduped.length,
      total_count: siteTotal,
      truncated: siteTotal > deduped.length,
      data: deduped,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// 鏌ヨ NR 宸ュ弬锛堣交閲忕増锛屽绾?fallback锛屼絾涓嶄贡鐚滐級
// 浼樺厛绾э細gcell_id > nr_tac+nr_arfcn+nr_pci > nr_arfcn+nr_pci > nr_arfcn
router.post("/nr/cell-params/query", async (req, res) => {
  const { gcell_id, gCellId, nr_tac, tac, nr_arfcn, arfcn, nr_pci, pci } = req.body;
  const MAX_RETURN = 50;

  const qGcellId = toNull(gcell_id ?? gCellId);
  const qTac = toIntOrNull(nr_tac ?? tac);
  const qArfcn = toIntOrNull(nr_arfcn ?? arfcn);
  const qPci = toIntOrNull(nr_pci ?? pci);

  const empty = (matchLevel = "not_found", reason = null) => ({
    match_level: matchLevel,
    count: 0,
    total_count: 0,
    truncated: false,
    data: [],
    reason
  });

  try {
    const countAndList = async (countSql, countParams, listSql, listParams) => {
      const [countRows] = await db.execute(countSql, countParams);
      const total = Number(countRows?.[0]?.total ?? 0);
      const [rows] = await db.execute(listSql, listParams);
      return { total, rows };
    };

    // 1) gcell_id锛氬敮涓€閿紝鏈€楂樹紭鍏堢骇
    if (qGcellId) {
      const { total, rows } = await countAndList(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE gcell_id = ?`,
        [qGcellId],
        `SELECT *
         FROM nr_cell_params
         WHERE gcell_id = ?
         LIMIT ${MAX_RETURN}`,
        [qGcellId]
      );

      return res.json({
        match_level: total > 0 ? "primary_gcell_id" : "not_found",
        count: rows.length,
        total_count: total,
        truncated: total > rows.length,
        data: rows
      });
    }

    // 2) nr_tac + nr_arfcn + nr_pci
    if (qTac != null && qArfcn != null && qPci != null) {
      const { total, rows } = await countAndList(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE nr_tac = ? AND nr_arfcn = ? AND nr_pci = ?`,
        [qTac, qArfcn, qPci],
        `SELECT *
         FROM nr_cell_params
         WHERE nr_tac = ? AND nr_arfcn = ? AND nr_pci = ?
         LIMIT ${MAX_RETURN}`,
        [qTac, qArfcn, qPci]
      );

      if (total > 0) {
        return res.json({
          match_level: "primary_tac_arfcn_pci",
          count: rows.length,
          total_count: total,
          truncated: total > rows.length,
          data: rows
        });
      }
    }

    // 3) nr_arfcn + nr_pci
    if (qArfcn != null && qPci != null) {
      const { total, rows } = await countAndList(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE nr_arfcn = ? AND nr_pci = ?`,
        [qArfcn, qPci],
        `SELECT *
         FROM nr_cell_params
         WHERE nr_arfcn = ? AND nr_pci = ?
         LIMIT ${MAX_RETURN}`,
        [qArfcn, qPci]
      );

      if (total > 0) {
        return res.json({
          match_level: "fallback_arfcn_pci",
          count: rows.length,
          total_count: total,
          truncated: total > rows.length,
          data: rows
        });
      }
    }

    // 4) nr_arfcn only
    if (qArfcn != null) {
      const { total, rows } = await countAndList(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE nr_arfcn = ?`,
        [qArfcn],
        `SELECT *
         FROM nr_cell_params
         WHERE nr_arfcn = ?
         LIMIT ${MAX_RETURN}`,
        [qArfcn]
      );

      return res.json({
        match_level: total > 0 ? "fallback_arfcn" : "not_found",
        count: rows.length,
        total_count: total,
        truncated: total > rows.length,
        data: rows
      });
    }

    return res.json(empty("invalid_query", "insufficient query fields"));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});


// 鏌ヨ NR 鍚岀珯宸ュ弬锛堜互缁忕含搴︾綉鏍艰仛绫讳负涓伙紝瀛楁灏戯紝鍒浣滄湁 enodeb_id锛?
router.post("/nr/site/query", async (req, res) => {
  const { gcell_id, gCellId, nr_tac, tac, nr_arfcn, arfcn, nr_pci, pci } = req.body;

  const qGcellId = toNull(gcell_id ?? gCellId);
  const qTac = toIntOrNull(nr_tac ?? tac);
  const qArfcn = toIntOrNull(nr_arfcn ?? arfcn);
  const qPci = toIntOrNull(nr_pci ?? pci);

  const MAX_RETURN = 120;
  const GRID_SCALE = 1000; // 1e-3 鈮?111m

  if (!qGcellId && qArfcn == null && qPci == null && qTac == null) {
    return res.json({
      match_level: "invalid_query",
      site_match: "none",
      anchor: null,
      count: 0,
      total_count: 0,
      truncated: false,
      data: [],
    });
  }

  try {
    let anchor = null;
    let anchorLevel = "none";

    // 1) gcell_id 閿氱偣
    if (qGcellId) {
      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE gcell_id = ?
         LIMIT 1`,
        [qGcellId]
      );
      if (rows.length) {
        anchor = rows[0];
        anchorLevel = "gcell_id";
      }
    }

    // 2) nr_tac + nr_arfcn + nr_pci 閿氱偣
    if (!anchor && qTac != null && qArfcn != null && qPci != null) {
      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE nr_tac = ? AND nr_arfcn = ? AND nr_pci = ?
         LIMIT 1`,
        [qTac, qArfcn, qPci]
      );
      if (rows.length) {
        anchor = rows[0];
        anchorLevel = "tac_arfcn_pci";
      }
    }

    // 3) nr_arfcn + nr_pci 閿氱偣
    if (!anchor && qArfcn != null && qPci != null) {
      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE nr_arfcn = ? AND nr_pci = ?
         LIMIT 1`,
        [qArfcn, qPci]
      );
      if (rows.length) {
        anchor = rows[0];
        anchorLevel = "arfcn_pci";
      }
    }

    // 4) nr_arfcn only 閿氱偣
    if (!anchor && qArfcn != null) {
      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE nr_arfcn = ?
         LIMIT 1`,
        [qArfcn]
      );
      if (rows.length) {
        anchor = rows[0];
        anchorLevel = "arfcn";
      }
    }

    if (!anchor) {
      return res.json({
        match_level: "not_found",
        site_match: "none",
        anchor: null,
        count: 0,
        total_count: 0,
        truncated: false,
        data: [],
      });
    }

    let siteRows = [];
    let siteTotal = 0;
    let siteLevel = "none";

    const lat = anchor.latitude != null ? Number(anchor.latitude) : null;
    const lon = anchor.longitude != null ? Number(anchor.longitude) : null;
    const hasLL = Number.isFinite(lat) && Number.isFinite(lon);

    // 1) 浼樺厛鎸夌綉鏍艰仛绫?
    if (hasLL) {
      const glat = Math.floor(lat * GRID_SCALE);
      const glon = Math.floor(lon * GRID_SCALE);

      const [countRows] = await db.execute(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE FLOOR(latitude * ?) = ?
           AND FLOOR(longitude * ?) = ?`,
        [GRID_SCALE, glat, GRID_SCALE, glon]
      );
      siteTotal = Number(countRows?.[0]?.total ?? 0);

      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE FLOOR(latitude * ?) = ?
           AND FLOOR(longitude * ?) = ?
         ORDER BY
           (nr_arfcn = ?) DESC,
           (nr_tac <=> ?) DESC,
           azimuth ASC,
           nr_pci ASC,
           gcell_id ASC
         LIMIT ${MAX_RETURN}`,
        [GRID_SCALE, glat, GRID_SCALE, glon, anchor.nr_arfcn, anchor.nr_tac]
      );

      siteRows = rows;
      siteLevel = "site_grid";
    }

    // 2) 娌＄粡绾害鏃讹紝閫€鍖栦负鍚?tac + arfcn
    if (siteRows.length === 0 && anchor.nr_tac != null && anchor.nr_arfcn != null) {
      const [countRows] = await db.execute(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE nr_tac = ? AND nr_arfcn = ?`,
        [anchor.nr_tac, anchor.nr_arfcn]
      );
      siteTotal = Number(countRows?.[0]?.total ?? 0);

      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE nr_tac = ? AND nr_arfcn = ?
         ORDER BY
           (nr_pci = ?) DESC,
           azimuth ASC,
           gcell_id ASC
         LIMIT ${MAX_RETURN}`,
        [anchor.nr_tac, anchor.nr_arfcn, anchor.nr_pci]
      );

      siteRows = rows;
      siteLevel = "fallback_tac_arfcn";
    }

    // 3) 鍐嶄笉琛屽彧鎸?arfcn
    if (siteRows.length === 0 && anchor.nr_arfcn != null) {
      const [countRows] = await db.execute(
        `SELECT COUNT(*) AS total
         FROM nr_cell_params
         WHERE nr_arfcn = ?`,
        [anchor.nr_arfcn]
      );
      siteTotal = Number(countRows?.[0]?.total ?? 0);

      const [rows] = await db.execute(
        `SELECT *
         FROM nr_cell_params
         WHERE nr_arfcn = ?
         ORDER BY
           (nr_pci = ?) DESC,
           azimuth ASC,
           gcell_id ASC
         LIMIT ${MAX_RETURN}`,
        [anchor.nr_arfcn, anchor.nr_pci]
      );

      siteRows = rows;
      siteLevel = "fallback_arfcn";
    }

    // gcell_id 鍘婚噸
    const seen = new Set();
    const deduped = [];
    for (const r of siteRows) {
      const k = `gcell:${r.gcell_id}`;
      if (seen.has(k)) continue;
      seen.add(k);
      deduped.push(r);
      if (deduped.length >= MAX_RETURN) break;
    }

    return res.json({
      match_level: anchorLevel,
      site_match: siteLevel,
      anchor: {
        id: anchor.id,
        gcell_id: anchor.gcell_id,
        cell_name: anchor.cell_name,
        nr_pci: anchor.nr_pci,
        nr_arfcn: anchor.nr_arfcn,
        nr_tac: anchor.nr_tac,
        longitude: anchor.longitude,
        latitude: anchor.latitude,
        azimuth: anchor.azimuth,
        site_type: anchor.site_type,
        source: anchor.source,
      },
      count: deduped.length,
      total_count: siteTotal,
      truncated: siteTotal > deduped.length,
      data: deduped,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// LTE 工参更新（仅超级管理员）
router.post("/lte/cell-params/update", async (req, res) => {
  if (!requireSuperAdmin(req, res)) return;

  const body = req.body || {};
  const id = toIntOrNull(body.id);
  const eci = toIntOrNull(body.eci);
  if (id == null && eci == null) {
    return res.status(400).json({ ok: false, error: "id_or_eci_required" });
  }

  const updates = [];
  const params = [];
  const addUpdate = (col, val) => {
    updates.push(`${col} = ?`);
    params.push(val);
  };

  if ("cell_name" in body || "cellName" in body) {
    addUpdate("cell_name", toNull(body.cell_name ?? body.cellName));
  }
  if ("site_type" in body || "siteType" in body) {
    addUpdate("site_type", toNull(body.site_type ?? body.siteType));
  }
  if ("azimuth" in body) {
    addUpdate("azimuth", toIntOrNull(body.azimuth));
  }
  if ("antenna_height" in body || "antennaHeight" in body) {
    addUpdate("antenna_height", toFloatOrNull(body.antenna_height ?? body.antennaHeight));
  }
  if ("longitude" in body) {
    addUpdate("longitude", toFloatOrNull(body.longitude));
  }
  if ("latitude" in body) {
    addUpdate("latitude", toFloatOrNull(body.latitude));
  }
  if ("source" in body) {
    addUpdate("source", toNull(body.source));
  }

  if (updates.length === 0) {
    return res.status(400).json({ ok: false, error: "no_update_fields" });
  }

  try {
    let result;
    if (eci != null) {
      const [r] = await db.execute(
        `UPDATE lte_cell_params
         SET ${updates.join(", ")}
         WHERE eci = ?`,
        [...params, eci]
      );
      result = r;
    } else {
      const [r] = await db.execute(
        `UPDATE lte_cell_params
         SET ${updates.join(", ")}
         WHERE id = ?
         LIMIT 1`,
        [...params, id]
      );
      result = r;
    }

    if (!result || Number(result.affectedRows || 0) <= 0) {
      return res.status(404).json({ ok: false, error: "row_not_found" });
    }

    return res.json({
      ok: true,
      affectedRows: Number(result.affectedRows || 0),
      id: id ?? null,
      eci: eci ?? null
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// LTE 工参删除（仅超级管理员）
router.post("/lte/cell-params/delete", async (req, res) => {
  if (!requireSuperAdmin(req, res)) return;

  const id = toIntOrNull(req.body?.id);
  const eci = toIntOrNull(req.body?.eci);
  if (id == null && eci == null) {
    return res.status(400).json({ ok: false, error: "id_or_eci_required" });
  }

  try {
    let result;
    if (eci != null) {
      const [r] = await db.execute(
        `DELETE FROM lte_cell_params WHERE eci = ?`,
        [eci]
      );
      result = r;
    } else {
      const [r] = await db.execute(
        `DELETE FROM lte_cell_params WHERE id = ? LIMIT 1`,
        [id]
      );
      result = r;
    }

    if (!result || Number(result.affectedRows || 0) <= 0) {
      return res.status(404).json({ ok: false, error: "row_not_found" });
    }

    return res.json({
      ok: true,
      affectedRows: Number(result.affectedRows || 0),
      id: id ?? null,
      eci: eci ?? null
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// NR 工参更新（仅超级管理员）
router.post("/nr/cell-params/update", async (req, res) => {
  if (!requireSuperAdmin(req, res)) return;

  const body = req.body || {};
  const id = toIntOrNull(body.id);
  const gcellId = toNull(body.gcell_id ?? body.gcellId);
  if (id == null && !gcellId) {
    return res.status(400).json({ ok: false, error: "id_or_gcell_id_required" });
  }

  const updates = [];
  const params = [];
  const addUpdate = (col, val) => {
    updates.push(`${col} = ?`);
    params.push(val);
  };

  if ("cell_name" in body || "cellName" in body) {
    addUpdate("cell_name", toNull(body.cell_name ?? body.cellName));
  }
  if ("site_type" in body || "siteType" in body) {
    addUpdate("site_type", toNull(body.site_type ?? body.siteType));
  }
  if ("azimuth" in body) {
    addUpdate("azimuth", toIntOrNull(body.azimuth));
  }
  if ("antenna_height" in body || "antennaHeight" in body) {
    addUpdate("antenna_height", toFloatOrNull(body.antenna_height ?? body.antennaHeight));
  }
  if ("longitude" in body) {
    addUpdate("longitude", toFloatOrNull(body.longitude));
  }
  if ("latitude" in body) {
    addUpdate("latitude", toFloatOrNull(body.latitude));
  }
  if ("source" in body) {
    addUpdate("source", toNull(body.source));
  }

  if (updates.length === 0) {
    return res.status(400).json({ ok: false, error: "no_update_fields" });
  }

  try {
    let result;
    if (gcellId) {
      const [r] = await db.execute(
        `UPDATE nr_cell_params
         SET ${updates.join(", ")}
         WHERE gcell_id = ?
         LIMIT 1`,
        [...params, gcellId]
      );
      result = r;
    } else {
      const [r] = await db.execute(
        `UPDATE nr_cell_params
         SET ${updates.join(", ")}
         WHERE id = ?
         LIMIT 1`,
        [...params, id]
      );
      result = r;
    }

    if (!result || Number(result.affectedRows || 0) <= 0) {
      return res.status(404).json({ ok: false, error: "row_not_found" });
    }

    return res.json({
      ok: true,
      affectedRows: Number(result.affectedRows || 0),
      id: id ?? null,
      gcell_id: gcellId ?? null
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// NR 工参删除（仅超级管理员）
router.post("/nr/cell-params/delete", async (req, res) => {
  if (!requireSuperAdmin(req, res)) return;

  const id = toIntOrNull(req.body?.id);
  const gcellId = toNull(req.body?.gcell_id ?? req.body?.gcellId);
  if (id == null && !gcellId) {
    return res.status(400).json({ ok: false, error: "id_or_gcell_id_required" });
  }

  try {
    let result;
    if (gcellId) {
      const [r] = await db.execute(
        `DELETE FROM nr_cell_params WHERE gcell_id = ? LIMIT 1`,
        [gcellId]
      );
      result = r;
    } else {
      const [r] = await db.execute(
        `DELETE FROM nr_cell_params WHERE id = ? LIMIT 1`,
        [id]
      );
      result = r;
    }

    if (!result || Number(result.affectedRows || 0) <= 0) {
      return res.status(404).json({ ok: false, error: "row_not_found" });
    }

    return res.json({
      ok: true,
      affectedRows: Number(result.affectedRows || 0),
      id: id ?? null,
      gcell_id: gcellId ?? null
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// LTE 宸ュ弬鎵归噺瀵煎叆 / 鏇存柊
router.post("/lte/cell-params/batch-upsert", async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  const requestSource = toNull(req.body?.source);

  if (items.length === 0) {
    return res.status(400).json({ error: "items is required and cannot be empty" });
  }

  const BATCH_SIZE = 500;

  try {
    let totalReceived = items.length;
    let totalAffected = 0;
    let totalInsertedOrUpdated = 0;
    let totalSkipped = 0;

    const validRows = [];

    for (const raw of items) {
      const row = {
        tac: toIntOrNull(raw.tac),
        pci: toIntOrNull(raw.pci),
        enodeb_id: toIntOrNull(raw.enodebId ?? raw.enodeb_id),
        earfcn: toIntOrNull(raw.earfcn),
        cell_id: toIntOrNull(raw.cellId ?? raw.cell_id),
        eci: toIntOrNull(raw.eci),
        local_cell_id: toIntOrNull(raw.localCellId ?? raw.local_cell_id),
        cell_name: toNull(raw.cellName ?? raw.cell_name),
        sector_id: toIntOrNull(raw.sectorId ?? raw.sector_id),
        longitude: toFloatOrNull(raw.longitude),
        latitude: toFloatOrNull(raw.latitude),
        azimuth: toIntOrNull(raw.azimuth),
        site_type: toNull(raw.siteType ?? raw.site_type),
        antenna_height: toFloatOrNull(raw.antennaHeight ?? raw.antenna_height),
        source: toNull(raw.source) ?? requestSource
      };

      // 鑷冲皯婊¤冻涓€绉嶅敮涓€瀹氫綅璺緞锛屽惁鍒欒烦杩?
      const hasEci = row.eci != null;
      const hasComposite =
        row.tac != null &&
        row.earfcn != null &&
        row.pci != null &&
        row.cell_id != null;

      if (!hasEci && !hasComposite) {
        totalSkipped++;
        continue;
      }

      validRows.push(row);
    }

    if (validRows.length === 0) {
      return res.json({
        message: "no valid rows",
        received: totalReceived,
        success: 0,
        skipped: totalSkipped
      });
    }

    const chunks = chunkArray(validRows, BATCH_SIZE);

    for (const chunk of chunks) {
      const values = [];
      const placeholders = chunk.map(() => {
        return `(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      }).join(", ");

      for (const r of chunk) {
        values.push(
          r.tac,
          r.pci,
          r.enodeb_id,
          r.earfcn,
          r.cell_id,
          r.eci,
          r.local_cell_id,
          r.cell_name,
          r.sector_id,
          r.longitude,
          r.latitude,
          r.azimuth,
          r.site_type,
          r.antenna_height,
          r.source
        );
      }

      const sql = `
        INSERT INTO lte_cell_params (
          tac, pci, enodeb_id, earfcn, cell_id, eci, local_cell_id,
          cell_name, sector_id, longitude, latitude, azimuth,
          site_type, antenna_height, source
        ) VALUES ${placeholders}
        ON DUPLICATE KEY UPDATE
          tac = VALUES(tac),
          pci = VALUES(pci),
          enodeb_id = VALUES(enodeb_id),
          earfcn = VALUES(earfcn),
          cell_id = VALUES(cell_id),
          eci = VALUES(eci),
          local_cell_id = VALUES(local_cell_id),
          cell_name = VALUES(cell_name),
          sector_id = VALUES(sector_id),
          longitude = VALUES(longitude),
          latitude = VALUES(latitude),
          azimuth = VALUES(azimuth),
          site_type = VALUES(site_type),
          antenna_height = VALUES(antenna_height),
          source = VALUES(source)
      `;

      const [result] = await db.query(sql, values);
      totalAffected += Number(result.affectedRows || 0);
      totalInsertedOrUpdated += chunk.length;
    }

    return res.json({
      message: "lte batch upsert success",
      received: totalReceived,
      success: totalInsertedOrUpdated,
      skipped: totalSkipped,
      affectedRows: totalAffected
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// NR 宸ュ弬鎵归噺瀵煎叆 / 鏇存柊
router.post("/nr/cell-params/batch-upsert", async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  const requestSource = toNull(req.body?.source);

  if (items.length === 0) {
    return res.status(400).json({ error: "items is required and cannot be empty" });
  }

  const BATCH_SIZE = 500;

  try {
    let totalReceived = items.length;
    let totalAffected = 0;
    let totalInsertedOrUpdated = 0;
    let totalSkipped = 0;

    const validRows = [];

    for (const raw of items) {
      const row = {
        gcell_id: toNull(raw.gcellId ?? raw.gcell_id),
        cell_name: toNull(raw.cellName ?? raw.cell_name),
        longitude: toFloatOrNull(raw.longitude),
        latitude: toFloatOrNull(raw.latitude),
        azimuth: toIntOrNull(raw.azimuth),
        nr_pci: toIntOrNull(raw.nrPci ?? raw.nr_pci),
        nr_arfcn: toIntOrNull(raw.nrArfcn ?? raw.nr_arfcn),
        nr_tac: toIntOrNull(raw.nrTac ?? raw.nr_tac),
        site_type: toNull(raw.siteType ?? raw.site_type),
        antenna_height: toFloatOrNull(raw.antennaHeight ?? raw.antenna_height),
        source: toNull(raw.source) ?? requestSource
      };

      if (!row.gcell_id) {
        totalSkipped++;
        continue;
      }

      validRows.push(row);
    }

    if (validRows.length === 0) {
      return res.json({
        message: "no valid rows",
        received: totalReceived,
        success: 0,
        skipped: totalSkipped
      });
    }

    const chunks = chunkArray(validRows, BATCH_SIZE);

    for (const chunk of chunks) {
      const values = [];
      const placeholders = chunk.map(() => {
        return `(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      }).join(", ");

      for (const r of chunk) {
        values.push(
          r.gcell_id,
          r.cell_name,
          r.longitude,
          r.latitude,
          r.azimuth,
          r.nr_pci,
          r.nr_arfcn,
          r.nr_tac,
          r.site_type,
          r.antenna_height,
          r.source
        );
      }

      const sql = `
        INSERT INTO nr_cell_params (
          gcell_id, cell_name, longitude, latitude, azimuth,
          nr_pci, nr_arfcn, nr_tac, site_type, antenna_height, source
        ) VALUES ${placeholders}
        ON DUPLICATE KEY UPDATE
          cell_name = VALUES(cell_name),
          longitude = VALUES(longitude),
          latitude = VALUES(latitude),
          azimuth = VALUES(azimuth),
          nr_pci = VALUES(nr_pci),
          nr_arfcn = VALUES(nr_arfcn),
          nr_tac = VALUES(nr_tac),
          site_type = VALUES(site_type),
          antenna_height = VALUES(antenna_height),
          source = VALUES(source)
      `;

      const [result] = await db.query(sql, values);
      totalAffected += Number(result.affectedRows || 0);
      totalInsertedOrUpdated += chunk.length;
    }

    return res.json({
      message: "nr batch upsert success",
      received: totalReceived,
      success: totalInsertedOrUpdated,
      skipped: totalSkipped,
      affectedRows: totalAffected
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// 宸ョ▼妯″紡鎻掍欢鍏变韩锛氱敓鎴?OSS 鐩翠紶绛惧悕
router.post("/plugin-share/oss-sign", async (req, res) => {
  const bucket = process.env.OSS_BUCKET;
  const regionRaw = String(process.env.OSS_REGION || "").trim();
  const region = regionRaw
    .replace(/^oss-/, "")
    .replace(/\.aliyuncs\.com$/, "");
  const accessKeyId = process.env.OSS_ACCESS_KEY_ID;
  const accessKeySecret = process.env.OSS_ACCESS_KEY_SECRET;
  const useSts = String(process.env.OSS_USE_STS || "false").toLowerCase() === "true";
  const stsDuration = Number(process.env.OSS_STS_DURATION_SECONDS || 900);
  const stsName = process.env.OSS_STS_TOKEN_NAME || "networkhelper-plugin-share";
  const stsStrict = String(process.env.OSS_STS_STRICT || "false").toLowerCase() === "true";
  const staticToken = process.env.OSS_SECURITY_TOKEN || null;
  const maxSizeBytes = Number(process.env.PLUGIN_SHARE_MAX_BYTES || 200 * 1024 * 1024);

  if (!bucket || !region || !accessKeyId || !accessKeySecret) {
    console.error("[plugin-share/oss-sign] oss_config_missing", {
      hasBucket: Boolean(bucket),
      hasRegion: Boolean(region),
      hasAccessKeyId: Boolean(accessKeyId),
      hasAccessKeySecret: Boolean(accessKeySecret)
    });
    return res.status(500).json({
      error: "oss_config_missing",
      message: "缺少 OSS 配置，请设置 OSS_REGION/OSS_BUCKET/OSS_ACCESS_KEY_ID/OSS_ACCESS_KEY_SECRET"
    });
  }

  const brand = normalizeOssPathSegment(req.body?.brand, "unknown_brand");
  const model = normalizeOssPathSegment(req.body?.model, "unknown_model");
  const buildDisplayId = normalizeOssPathSegment(req.body?.buildDisplayId, "unknown_build");
  const fileName = normalizeOssFileName(req.body?.fileName, "plugin-release.zip");
  const fileMd5 = toNull(req.body?.fileMd5);
  const fileSizeBytes = toIntOrNull(req.body?.fileSizeBytes);

  if (fileSizeBytes == null || fileSizeBytes <= 0) {
    return res.status(400).json({ error: "invalid_file_size" });
  }
  if (fileSizeBytes > maxSizeBytes) {
    return res.status(400).json({
      error: "file_too_large",
      message: `fileSizeBytes exceeds limit ${maxSizeBytes}`,
      fileSizeBytes,
      limitBytes: maxSizeBytes
    });
  }

  const requestId = crypto.randomUUID();
  const dir = `NetworkHelper/${brand}/${model}/${buildDisplayId}/`;
  const key = `${dir}${fileName}`;
  const objectPrefix = dir;

  let signKeyId = accessKeyId;
  let signKeySecret = accessKeySecret;
  let securityToken = staticToken;
  let expireAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  let stsFallbackToStatic = false;

  if (useSts && !staticToken) {
    try {
      const sts = await getStsCredentials({
        accessKeyId,
        accessKeySecret,
        bucket,
        objectPrefix,
        durationSeconds: Math.min(Math.max(stsDuration, 900), 3600),
        tokenName: stsName
      });
      signKeyId = sts.accessKeyId;
      signKeySecret = sts.accessKeySecret;
      securityToken = sts.securityToken;
      expireAt = sts.expiration || expireAt;
    } catch (err) {
      console.error("[plugin-share/oss-sign] sts_issue_token_failed", err);
      if (stsStrict) {
        return res.status(500).json({
          error: "sts_issue_token_failed",
          message: String(err.message || err)
        });
      }
      stsFallbackToStatic = true;
    }
  }

  const policyObj = {
    expiration: expireAt,
    conditions: [
      ["content-length-range", 1, maxSizeBytes],
      { bucket },
      ["eq", "$key", key],
      ...(securityToken ? [["eq", "$x-oss-security-token", securityToken]] : [])
    ]
  };
  const policy = Buffer.from(JSON.stringify(policyObj)).toString("base64");
  const signature = crypto
    .createHmac("sha1", signKeySecret)
    .update(policy)
    .digest("base64");

  const endpointNoProtocol = `oss-${region}.aliyuncs.com`;
  const host = `https://${bucket}.${endpointNoProtocol}`;

  try {
    await db.execute(
      `INSERT INTO plugin_share_uploads (
         request_id, brand, model, build_display_id, plugin_file_name,
         plugin_file_size, plugin_file_md5, oss_bucket, oss_endpoint, oss_object_key,
         upload_status
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        requestId,
        brand,
        model,
        buildDisplayId,
        fileName,
        fileSizeBytes,
        fileMd5,
        bucket,
        endpointNoProtocol,
        key,
        "SIGNED"
      ]
    );
  } catch (err) {
    console.error("[plugin-share/oss-sign] db_insert_failed", err);
    return res.status(500).json({ error: `db_insert_failed: ${err.message}` });
  }

  return res.json({
    requestId,
    host,
    key,
      policy,
      signature,
      OSSAccessKeyId: signKeyId,
      securityToken,
      expireAt,
      stsFallbackToStatic
  });
});

// plugin share: list downloadable plugins by device model
router.post("/plugin-share/download-candidates", async (req, res) => {
  const regionRaw = String(process.env.OSS_REGION || "").trim();
  const defaultRegion = regionRaw.replace(/^oss-/, "").replace(/\.aliyuncs\.com$/, "");
  const defaultBucket = String(process.env.OSS_BUCKET || "").trim();
  const accessKeyId = String(process.env.OSS_ACCESS_KEY_ID || "").trim();
  const accessKeySecret = String(process.env.OSS_ACCESS_KEY_SECRET || "").trim();
  const staticToken = toNull(process.env.OSS_SECURITY_TOKEN);
  const expiresSeconds = Math.min(
    Math.max(Number(process.env.PLUGIN_SHARE_DOWNLOAD_URL_EXPIRES || 900), 60),
    24 * 3600
  );

  if (!defaultRegion || !defaultBucket || !accessKeyId || !accessKeySecret) {
    return res.status(500).json({
      error: "oss_config_missing",
      message: "missing OSS_REGION/OSS_BUCKET/OSS_ACCESS_KEY_ID/OSS_ACCESS_KEY_SECRET"
    });
  }

  const brand = normalizeOssPathSegment(req.body?.brand, "");
  const model = normalizeOssPathSegment(req.body?.model, "");
  const buildDisplayId = normalizeOssPathSegment(req.body?.buildDisplayId, "");
  if (!model) {
    return res.status(400).json({ error: "model_required" });
  }

  try {
    let rows = [];
    let fallbackUsed = false;

    if (brand) {
      const [exactRows] = await db.execute(
        `SELECT id, brand, model, build_display_id, plugin_file_name, plugin_file_size, plugin_file_md5,
                oss_bucket, oss_endpoint, oss_object_key, updated_at
           FROM plugin_share_uploads
          WHERE upload_status = 'UPLOADED' AND brand = ? AND model = ?
          ORDER BY CASE WHEN build_display_id = ? THEN 0 ELSE 1 END ASC, updated_at DESC, id DESC
          LIMIT 200`,
        [brand, model, buildDisplayId]
      );
      rows = exactRows || [];
    }

    if (!rows.length) {
      if (brand) fallbackUsed = true;
      const [modelRows] = await db.execute(
        `SELECT id, brand, model, build_display_id, plugin_file_name, plugin_file_size, plugin_file_md5,
                oss_bucket, oss_endpoint, oss_object_key, updated_at
           FROM plugin_share_uploads
          WHERE upload_status = 'UPLOADED' AND model = ?
          ORDER BY CASE WHEN build_display_id = ? THEN 0 ELSE 1 END ASC, updated_at DESC, id DESC
          LIMIT 200`,
        [model, buildDisplayId]
      );
      rows = modelRows || [];
    }

    const seenBuild = new Set();
    const now = Date.now();
    const expiresAt = new Date(now + expiresSeconds * 1000).toISOString();
    const items = [];

    for (const row of rows) {
      const build = String(row.build_display_id || "");
      if (!build || seenBuild.has(build)) continue;
      seenBuild.add(build);

      const rowBucket = String(row.oss_bucket || defaultBucket).trim() || defaultBucket;
      const endpointRaw = String(row.oss_endpoint || "").trim();
      const endpointRegion = endpointRaw
        .replace(/^https?:\/\//, "")
        .replace(/^oss-/, "")
        .replace(/\.aliyuncs\.com$/, "");
      const rowRegion = endpointRegion || defaultRegion;

      let downloadUrl = null;
      try {
        downloadUrl = buildSignedDownloadUrl({
          region: rowRegion,
          bucket: rowBucket,
          key: String(row.oss_object_key || ""),
          accessKeyId,
          accessKeySecret,
          securityToken: staticToken,
          expiresSeconds
        });
      } catch (err) {
        console.error("[plugin-share/download-candidates] sign_url_failed", {
          model,
          build,
          key: row.oss_object_key,
          error: err?.message || String(err)
        });
      }
      if (!downloadUrl) continue;

      items.push({
        brand: String(row.brand || ""),
        model: String(row.model || ""),
        buildDisplayId: build,
        fileName: String(row.plugin_file_name || "plugin-release.zip"),
        fileSizeBytes: Number(row.plugin_file_size || 0),
        fileMd5: toNull(row.plugin_file_md5),
        ossObjectKey: String(row.oss_object_key || ""),
        updatedAt: row.updated_at ? new Date(row.updated_at).toISOString() : null,
        downloadUrl,
        expiresAt
      });
    }

    return res.json({
      brand: brand || null,
      model,
      currentBuildDisplayId: buildDisplayId || null,
      fallbackUsed,
      expiresInSeconds: expiresSeconds,
      count: items.length,
      items
    });
  } catch (err) {
    console.error("[plugin-share/download-candidates] query_failed", err);
    return res.status(500).json({
      error: "download_candidates_query_failed",
      message: String(err.message || err)
    });
  }
});

// plugin share: report upload result
router.post("/plugin-share/report", async (req, res) => {
  const requestId = toNull(req.body?.requestId);
  const status = toNull(req.body?.status);
  const uploadedBytes = toIntOrNull(req.body?.uploadedBytes);
  const durationMs = toIntOrNull(req.body?.durationMs);
  const avgSpeedBps = toFloatOrNull(req.body?.avgSpeedBps);
  const ossEtag = toNull(req.body?.ossEtag);
  const ossObjectKey = toNull(req.body?.ossObjectKey);
  const errorMessage = toNull(req.body?.errorMessage);

  if (!requestId || !status) {
    return res.status(400).json({ error: "requestId/status required" });
  }

  const statusUpper = String(status).toUpperCase();
  if (!["UPLOADED", "FAILED"].includes(statusUpper)) {
    return res.status(400).json({ error: "status must be UPLOADED or FAILED" });
  }

  try {
    const [result] = await db.execute(
      `UPDATE plugin_share_uploads
       SET upload_status = ?,
           uploaded_bytes = ?,
           upload_duration_ms = ?,
           upload_avg_speed_bps = ?,
           oss_etag = COALESCE(?, oss_etag),
           oss_object_key = COALESCE(?, oss_object_key),
           error_message = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE request_id = ?`,
      [
        statusUpper,
        uploadedBytes,
        durationMs,
        avgSpeedBps,
        ossEtag,
        ossObjectKey,
        errorMessage,
        requestId
      ]
    );

    if (!result || Number(result.affectedRows || 0) <= 0) {
      return res.status(404).json({ error: "request_id_not_found" });
    }
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
