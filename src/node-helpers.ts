import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import childProcess from 'node:child_process';
import { maskSensitive, type Logger } from './logger';

export function createNodeFileLogger(options: { enabled: boolean; appName: string }): Logger {
  const enabled = Boolean(options.enabled);
  const appName = (options.appName || 'AuthlyX').trim() || 'AuthlyX';

  return {
    enabled,
    log: (line: string) => {
      if (!enabled) return;
      if (!line || !String(line).trim()) return;
      try {
        const programData = process.env.PROGRAMDATA || '';
        const root =
          process.platform === 'win32' && programData
            ? path.join(programData, 'AuthlyX', appName)
            : path.join(os.homedir(), '.authlyx', appName);

        fs.mkdirSync(root, { recursive: true });
        const now = new Date();
        const ymd = now.toISOString().slice(0, 10).replace(/-/g, '_');
        const file = path.join(root, `${ymd}.log`);
        const hh = String(now.getUTCHours()).padStart(2, '0');
        const mm = String(now.getUTCMinutes()).padStart(2, '0');
        const ss = String(now.getUTCSeconds()).padStart(2, '0');
        const msg = `[${hh}:${mm}:${ss}] ${maskSensitive(line)}\n`;
        fs.appendFileSync(file, msg, { encoding: 'utf8' });
      } catch {
        return;
      }
    },
  };
}

export function getWindowsSid(): string {
  if (process.platform !== 'win32') return '';
  try {
    const out = childProcess.execSync('whoami /user', { stdio: ['ignore', 'pipe', 'ignore'] }).toString('utf8');
    const m = out.match(/S-\d-\d+-(\d+-){1,}\d+/);
    return m ? String(m[0]).trim() : '';
  } catch {
    return '';
  }
}

