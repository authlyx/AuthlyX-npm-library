// AuthlyX SDK V2.4
import { Agent, request } from 'node:https';
import { checkServerIdentity, type DetailedPeerCertificate } from 'node:tls';
import { createHash } from 'node:crypto';


const pins = new Set([
  '1DFC1605FBAD358D8BC844F76D15203FAC9CA5C1A79FD4857FFAF2864FBEBF96',
  '76B27B80A58027DC3CF1DA68DAC17010ED93997D0B603E2FADBE85012493B5A7',
]);

const agent = new Agent({
  rejectUnauthorized: true,
  maxCachedSessions: 0,
  checkServerIdentity(host, cert) {
    const error = checkServerIdentity(host, cert);
    if (error) return error;
    if (host.toLowerCase().replace(/\.$/, '') !== 'authly.cc') return;
    const seen = new Set<DetailedPeerCertificate>();
    for (let current: DetailedPeerCertificate | undefined = cert as DetailedPeerCertificate;
      current && !seen.has(current); current = current.issuerCertificate) {
      seen.add(current);
      if (current.raw && pins.has(createHash('sha256').update(current.raw).digest('hex').toUpperCase())) return;
    }
    return new Error('AuthlyX TLS certificate chain does not match a trusted pin');
  },
});

export type ApiResponse = { status: number; headers: Headers; text(): Promise<string> };

export function postPinnedJson(url: string, body: string, headers: Record<string, string>): Promise<ApiResponse> {
  return new Promise((resolve, reject) => {
    const req = request(url, {
      method: 'POST', agent,
      headers: { ...headers, 'content-length': Buffer.byteLength(body) },
    }, res => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('error', reject);
      res.on('aborted', () => reject(new Error('AuthlyX response aborted')));
      res.on('end', () => {
        const responseHeaders = new Headers();
        for (const [key, value] of Object.entries(res.headers)) {
          if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : value);
        }
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ status: res.statusCode || 0, headers: responseHeaders, text: async () => text });
      });
    });
    req.setTimeout(30_000, () => req.destroy(new Error('AuthlyX request timed out')));
    req.on('error', reject);
    req.end(body);
  });
}
