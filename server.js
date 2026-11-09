const dotenv = require('dotenv');

dotenv.config();

const express = require('express');
const app = express();
const routes = require('./routes');
const diagnosticArchive = require('./diagnostic-archive').createDiagnosticArchive();

// Diagnostics has its own body limit and private disk storage, with hourly OSS archival.
app.use('/networkhelp/diagnostics', require('./diagnostics').createDiagnosticsRouter({
  onStoragePressure: () => { diagnosticArchive.run({ storagePressure: true }).catch(() => console.warn('[diagnostic-archive] pressure_cycle_failed')); },
}));

app.use(express.json({ limit: '128mb' }));
app.use(express.urlencoded({ extended: true, limit: '128mb' }));

app.use('/networkhelp', routes);

const PORT = Number(process.env.PORT || 9895);
const server = app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
  diagnosticArchive.start();
});
function stop() {
  diagnosticArchive.stop();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 10000).unref();
}
process.once('SIGTERM', stop);
process.once('SIGINT', stop);
