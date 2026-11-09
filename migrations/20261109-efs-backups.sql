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
