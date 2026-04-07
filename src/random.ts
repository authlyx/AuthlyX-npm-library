function getCrypto(): Crypto | null {
  const g: any = globalThis as any;
  return g && g.crypto ? (g.crypto as Crypto) : null;
}

export function randomBytesHex(byteLen: number): string {
  const c = getCrypto();
  if (c && c.getRandomValues) {
    const b = new Uint8Array(byteLen);
    c.getRandomValues(b);
    return Array.from(b)
      .map((x) => x.toString(16).padStart(2, '0'))
      .join('');
  }
  // Very old environments: last-resort fallback
  let out = '';
  for (let i = 0; i < byteLen; i++) out += Math.floor(Math.random() * 256).toString(16).padStart(2, '0');
  return out;
}

export function randomUUID(): string {
  const c = getCrypto() as any;
  if (c && typeof c.randomUUID === 'function') return String(c.randomUUID());

  // RFC4122 v4-ish using getRandomValues if possible.
  const bytes = new Uint8Array(16);
  if (c && c.getRandomValues) c.getRandomValues(bytes);
  else for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes).map((x) => x.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

