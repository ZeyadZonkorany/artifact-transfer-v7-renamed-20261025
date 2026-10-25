const {spawnSync} = require('node:child_process');
const script = process.env.PROBE_SUITE === 'metadata-controls' ? 'controls.py' : 'probe.py';
const result = spawnSync('python3', ['-u', script], {env: process.env, stdio: 'inherit'});
if (result.error) { console.error(result.error.message); process.exit(1); }
process.exit(result.status ?? 1);
