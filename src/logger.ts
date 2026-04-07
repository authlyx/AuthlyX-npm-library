const SENSITIVE_PATTERNS: RegExp[] = [
  /("session_id"\s*:\s*")([^"]+)(")/gi,
  /("owner_id"\s*:\s*")([^"]+)(")/gi,
  /("secret"\s*:\s*")([^"]+)(")/gi,
  /("password"\s*:\s*")([^"]+)(")/gi,
  /("key"\s*:\s*")([^"]+)(")/gi,
  /("license_key"\s*:\s*")([^"]+)(")/gi,
  /("hash"\s*:\s*")([^"]+)(")/gi,
  /("request_id"\s*:\s*")([^"]+)(")/gi,
  /("nonce"\s*:\s*")([^"]+)(")/gi,
  /("hwid"\s*:\s*")([^"]+)(")/gi,
  /("sid"\s*:\s*")([^"]+)(")/gi,
  /(\bx-auth-signature\s*:\s*)([A-Za-z0-9+/=]+)/gi,
  /(\bx-v2-signature\s*:\s*)([A-Za-z0-9+/=]+)/gi,
  /(\bx-v2-request-id\s*:\s*)([A-Za-z0-9-]+)/gi,
  /(\bx-v2-nonce\s*:\s*)([A-Za-z0-9]+)/gi,
  /(\bx-v2-timestamp\s*:\s*)([0-9]+)/gi,
];

export type Logger = {
  enabled: boolean;
  log: (line: string) => void;
};

export function maskSensitive(input: unknown): string {
  if (input === null || input === undefined) return '';
  let text = String(input);
  for (const p of SENSITIVE_PATTERNS) {
    text = text.replace(p, (_m, a, _b, c) => (c ? `${a}***${c}` : `${a}***`));
  }
  return text;
}

export function createConsoleLogger(enabled: boolean): Logger {
  return {
    enabled,
    log: (line: string) => {
      if (!enabled) return;
      if (!line || !String(line).trim()) return;
      // Keep this minimal for "everywhere". Node file logging is in ./node
      // eslint-disable-next-line no-console
      console.log(maskSensitive(line));
    },
  };
}

