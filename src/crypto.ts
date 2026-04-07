import nacl from 'tweetnacl';

function getSubtle(): SubtleCrypto | null {
  const g: any = globalThis as any;
  return g && g.crypto && g.crypto.subtle ? (g.crypto.subtle as SubtleCrypto) : null;
}

function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const subtle = getSubtle();
  if (subtle) {
    const digest = await subtle.digest('SHA-256', data);
    const b = new Uint8Array(digest);
    return Array.from(b).map((x) => x.toString(16).padStart(2, '0')).join('');
  }
  // Fallback: JS implementation not provided; return empty to avoid false security.
  return '';
}

export async function sha256HexFromString(text: string): Promise<string> {
  return sha256Hex(utf8Bytes(text));
}

function pemToDerBytes(pem: string): Uint8Array | null {
  const cleaned = String(pem || '')
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '')
    .trim();
  if (!cleaned) return null;
  try {
    const bin =
      typeof (globalThis as any).atob === 'function'
        ? (globalThis as any).atob(cleaned)
        : Buffer.from(cleaned, 'base64').toString('binary');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const raw = String(b64 || '').trim();
    const bin =
      typeof (globalThis as any).atob === 'function'
        ? (globalThis as any).atob(raw)
        : Buffer.from(raw, 'base64').toString('binary');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

// Best-effort Ed25519 response verification:
// - If WebCrypto supports Ed25519 verify, we use it.
// - Otherwise we fall back to tweetnacl, which requires a raw 32-byte public key.
export async function verifyEd25519Signature(options: {
  publicKeyPem: string;
  message: string;
  signatureBase64: string;
}): Promise<boolean> {
  const { publicKeyPem, message, signatureBase64 } = options;
  if (!publicKeyPem || !signatureBase64) return false;

  const subtle = getSubtle() as any;
  if (subtle && typeof subtle.importKey === 'function') {
    const der = pemToDerBytes(publicKeyPem);
    const sigBytes = base64ToBytes(signatureBase64);
    if (der && sigBytes) {
      try {
        const key = await subtle.importKey(
          'spki',
          der.buffer,
          { name: 'Ed25519' },
          false,
          ['verify']
        );
        const ok = await subtle.verify({ name: 'Ed25519' }, key, sigBytes, utf8Bytes(message));
        return Boolean(ok);
      } catch {
        // fall through to nacl
      }
    }
  }

  // tweetnacl expects a 32-byte public key (raw). If pem is not raw, we can't decode reliably here.
  // Developers can pass raw key PEM export if needed; otherwise verification is skipped.
  const raw = pemToDerBytes(publicKeyPem);
  const sig = base64ToBytes(signatureBase64);
  if (!raw || !sig) return false;

  // Heuristic: last 32 bytes often contains the raw Ed25519 public key for common encodings.
  const pk = raw.length >= 32 ? raw.slice(raw.length - 32) : raw;
  if (pk.length !== 32 || sig.length !== 64) return false;
  return nacl.sign.detached.verify(utf8Bytes(message), sig, pk);
}
