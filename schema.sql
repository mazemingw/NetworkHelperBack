-- Schema only: no records or credentials.
-- Select the target database before importing.

CREATE TABLE IF NOT EXISTS `app_announcements` (
  `id` int NOT NULL AUTO_INCREMENT,
  `title` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `announcement_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS `app_info` (
  `id` int NOT NULL AUTO_INCREMENT,
  `app_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `app_version` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `app_package` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `min_sdk_version` int NOT NULL,
  `target_sdk_version` int NOT NULL,
  `app_icon_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS `app_version_legacy_updates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `version_code` int NOT NULL,
  `version_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `update_content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `release_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `is_mandatory` tinyint(1) DEFAULT '0',
  `download_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `view_count` int DEFAULT '0',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS `app_version_updates` (
  `id` int NOT NULL AUTO_INCREMENT,
  `version_code` int NOT NULL,
  `version_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `update_content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
  `release_date` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `is_mandatory` tinyint(1) DEFAULT '0',
  `download_url` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `view_count` int DEFAULT '0',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC;

CREATE TABLE IF NOT EXISTS `dev_auth_credentials` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `role` varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '角色：developer / super_admin',
  `password_sha256` char(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '密码 SHA256（十六进制）',
  `is_enabled` tinyint(1) NOT NULL DEFAULT '1' COMMENT '是否启用',
  `remark` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '备注',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP,
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE KEY `uk_role_hash` (`role`,`password_sha256`) USING BTREE,
  KEY `idx_enabled_role` (`is_enabled`,`role`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='开发者鉴权密码表';

CREATE TABLE IF NOT EXISTS `lte_cell_params` (
  `id` bigint NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `tac` int DEFAULT NULL COMMENT 'Tracking Area Code',
  `pci` int DEFAULT NULL COMMENT 'Physical Cell ID',
  `enodeb_id` int DEFAULT NULL COMMENT 'eNodeB ID',
  `earfcn` int DEFAULT NULL COMMENT 'LTE EARFCN',
  `cell_id` int DEFAULT NULL COMMENT 'Cell ID（短号，0-255，部分工参不存在）',
  `eci` bigint DEFAULT NULL COMMENT 'ECI（长号/厂商逻辑ID）',
  `local_cell_id` int DEFAULT NULL COMMENT '本地小区标识',
  `cell_name` varchar(512) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '小区名称/地址描述',
  `sector_id` int DEFAULT NULL COMMENT '扇区号',
  `longitude` decimal(10,6) DEFAULT NULL COMMENT '经度',
  `latitude` decimal(10,6) DEFAULT NULL COMMENT '纬度',
  `azimuth` int DEFAULT NULL COMMENT '方向角',
  `site_type` varchar(16) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '站型（宏站/室分/微站等）',
  `antenna_height` decimal(5,1) DEFAULT NULL COMMENT '天线挂高(m)',
  `source` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL COMMENT '数据来源',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  KEY `idx_match_core` (`tac`,`pci`,`earfcn`) USING BTREE,
  KEY `idx_enodeb` (`enodeb_id`) USING BTREE,
  KEY `idx_eci` (`eci`) USING BTREE,
  KEY `idx_geo` (`longitude`,`latitude`) USING BTREE,
  KEY `idx_match_primary` (`tac`,`earfcn`,`pci`,`cell_id`) USING BTREE,
  KEY `idx_match_eci` (`tac`,`earfcn`,`eci`) USING BTREE,
  KEY `idx_tac_earfcn_pci` (`tac`,`earfcn`,`pci`) USING BTREE,
  KEY `idx_tac_earfcn` (`tac`,`earfcn`) USING BTREE,
  KEY `idx_lte_cell_params_eci` (`eci`) USING BTREE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci ROW_FORMAT=DYNAMIC COMMENT='LTE 基站工参表';

CREATE TABLE IF NOT EXISTS `nr_cell_params` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',
  `gcell_id` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '5G小区全局标识（GCellID）',
  `cell_name` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '小区名称',
  `longitude` decimal(10,6) DEFAULT NULL COMMENT '经度',
  `latitude` decimal(10,6) DEFAULT NULL COMMENT '纬度',
  `azimuth` smallint unsigned DEFAULT NULL COMMENT '方位角（0-360）',
  `nr_pci` smallint unsigned DEFAULT NULL COMMENT '5G物理小区标识（NR_PCI）',
  `nr_arfcn` int unsigned DEFAULT NULL COMMENT '5G绝对频点号（NR_ARFCN）',
  `nr_tac` int unsigned DEFAULT NULL COMMENT '5G大区号，目前非必要',
  `site_type` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '站点类型（宏站/室分/拉远等）',
  `antenna_height` decimal(5,2) DEFAULT NULL COMMENT '天线高度（米）',
  `source` varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL COMMENT '数据来源',
  `created_at` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `updated_at` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_gcell_id` (`gcell_id`),
  KEY `idx_cell_name` (`cell_name`),
  KEY `idx_nr_pci` (`nr_pci`),
  KEY `idx_nr_arfcn_pci` (`nr_arfcn`,`nr_pci`),
  KEY `idx_nr_tac_arfcn_pci` (`nr_tac`,`nr_arfcn`,`nr_pci`),
  KEY `idx_lon_lat` (`longitude`,`latitude`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='5G NR小区参数表';

CREATE TABLE IF NOT EXISTS `efs_backup_vaults` (
  `vault_id` char(36) NOT NULL PRIMARY KEY,
  `token_sha256` char(64) NOT NULL,
  `model` varchar(64) NOT NULL,
  `imei` char(15) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY `idx_efs_device` (`model`, `imei`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `efs_partition_backups` (
  `backup_id` char(36) NOT NULL PRIMARY KEY,
  `vault_id` char(36) NOT NULL,
  `oss_bucket` varchar(128) NOT NULL,
  `oss_region` varchar(64) NOT NULL,
  `object_key` varchar(512) NOT NULL,
  `archive_sha256` char(64) NOT NULL,
  `archive_bytes` bigint unsigned NOT NULL,
  `status` enum('SIGNED','VERIFIED') NOT NULL DEFAULT 'SIGNED',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `verified_at` timestamp NULL,
  KEY `idx_efs_vault` (`vault_id`, `status`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS `plugin_share_uploads` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `request_id` char(36) COLLATE utf8mb4_unicode_ci NOT NULL,
  `brand` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `model` varchar(64) COLLATE utf8mb4_unicode_ci NOT NULL,
  `build_display_id` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `plugin_file_name` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `plugin_file_size` bigint unsigned NOT NULL,
  `plugin_file_md5` char(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `oss_bucket` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `oss_endpoint` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `oss_object_key` varchar(512) COLLATE utf8mb4_unicode_ci NOT NULL,
  `oss_etag` varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `upload_status` enum('SIGNED','UPLOADED','FAILED') COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'SIGNED',
  `uploaded_bytes` bigint unsigned DEFAULT NULL,
  `upload_duration_ms` int unsigned DEFAULT NULL,
  `upload_avg_speed_bps` double DEFAULT NULL,
  `error_message` text COLLATE utf8mb4_unicode_ci,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_plugin_share_request_id` (`request_id`),
  KEY `idx_plugin_share_created_at` (`created_at`),
  KEY `idx_plugin_share_status` (`upload_status`),
  KEY `idx_plugin_share_device` (`brand`,`model`,`build_display_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
