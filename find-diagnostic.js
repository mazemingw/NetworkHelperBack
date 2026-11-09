// Local administrator tool only; no public log lookup endpoint is exposed.
require('dotenv').config({ quiet: true });
const fs = require('node:fs/promises');
const nativeFs = require('node:fs');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { diagnosticRoot } = require('./diagnostic-storage');
const { archiveConfig, archiveClient } = require('./diagnostic-archive');
async function main() {
  const code = String(process.argv[2] || '').toUpperCase();
  const match = /^NH-(\d{4})(\d{2})(\d{2})-[A-F0-9]{16}$/.exec(code);
  if (!match) throw new Error('Usage: node find-diagnostic.js NH-YYYYMMDD-0123456789ABCDEF');
  const day = `${match[1]}-${match[2]}-${match[3]}`;
  const file = path.join(diagnosticRoot(), day, `${code}.json.gz`);
  try { await fs.access(file); console.log(file); return; } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const config = archiveConfig(), client = archiveClient(config);
  const key = `${config.prefix}/${day}/${code}.json.gz`;
  await client.head(key);
  if (process.argv[3] === '--download' && process.argv[4]) {
    const output = path.resolve(process.argv[4]);
    const response = await client.getStream(key);
    await pipeline(response.stream, nativeFs.createWriteStream(output, { flags: 'wx', mode: 0o600 }));
    console.log(output);
  } else console.log(`oss://${config.bucket}/${key}`);
}
main().catch(() => { console.error('Receipt not found locally or in OSS; check code, storage credentials and RAM permissions.'); process.exitCode = 1; });
