import type {
  AuthlyXChatMessages,
  AuthlyXInitOptions,
  AuthlyXResponse,
  AuthlyXUpdateData,
  AuthlyXUserData,
  AuthlyXVariableData,
} from './types';
import { createConsoleLogger, type Logger } from './logger';
import { canonicalJson, clampString, computeDaysLeft, safeJsonParse } from './utils';
import { randomBytesHex, randomUUID } from './random';
import { verifyEd25519Signature } from './crypto';

type SecurityContext = { requestId: string; nonce: string; timestamp: number };

export class AuthlyX {
  static DefaultBaseUrl = 'https://authly.cc/api/v2';
  static DefaultIpLookupUrl = 'https://api.ipify.org';

  ownerId: string;
  appName: string;
  version: string;
  secret: string;
  baseUrl: string;
  debug: boolean;
  ipLookupUrl: string;
  requireSignedResponses: boolean;
  serverPublicKeyPem: string;

  sessionId = '';
  initialized = false;
  applicationHash = '';

  response: AuthlyXResponse;
  userData: AuthlyXUserData;
  variableData: AuthlyXVariableData;
  updateData: AuthlyXUpdateData;
  chatMessages: AuthlyXChatMessages;

  private logger: Logger;
  private cachedPublicIp = '';
  private cachedPublicIpExpiresAt = 0;

  constructor(
    ownerId: string,
    appName: string,
    version: string,
    secret: string,
    debugOrOptions: boolean | AuthlyXInitOptions = true,
    api?: string
  ) {
    this.ownerId = clampString(ownerId);
    this.appName = clampString(appName);
    this.version = clampString(version);
    this.secret = clampString(secret);

    const options: AuthlyXInitOptions =
      typeof debugOrOptions === 'object' && debugOrOptions !== null ? debugOrOptions : { debug: debugOrOptions };

    this.debug = options.debug === undefined ? true : Boolean(options.debug);
    this.baseUrl = clampString(options.api ?? api ?? AuthlyX.DefaultBaseUrl).trim().replace(/\/+$/, '');
    this.ipLookupUrl = clampString(options.ipLookupUrl ?? AuthlyX.DefaultIpLookupUrl).trim();
    this.applicationHash = clampString(options.hash ?? '');

    this.serverPublicKeyPem = clampString(options.serverPublicKeyPem ?? '');
    this.requireSignedResponses = Boolean(options.requireSignedResponses ?? false);

    this.logger = options.logger ? options.logger : createConsoleLogger(this.debug);

    this.response = {
      success: false,
      message: '',
      raw: '',
      code: '',
      statusCode: 0,
      requestId: '',
      nonce: '',
      signatureKid: '',
    };

    this.userData = {
      username: '',
      email: '',
      licenseKey: '',
      subscription: '',
      subscriptionLevel: '',
      expiryDate: '',
      daysLeft: 0,
      lastLogin: '',
      registeredAt: '',
      hwidSid: '',
      ipAddress: '',
    };

    this.variableData = {
      varKey: '',
      varValue: '',
      updatedAt: '',
    };

    this.updateData = {
      available: false,
      latestVersion: '',
      downloadUrl: null,
      autoUpdateEnabled: false,
      forceUpdate: false,
      changelog: '',
      showReminder: false,
      reminderMessage: '',
      allowedUntil: null,
    };

    this.chatMessages = {
      channelName: '',
      messages: [],
      count: 0,
      nextCursor: '',
      hasMore: false,
    };

    this.logger.log(`[SDK] AuthlyX initialized for app '${this.appName}' using '${this.baseUrl}'.`);
  }

  SetLogger(logger: Logger): void {
    this.logger = logger;
  }

  private resetResponse(): void {
    this.response.success = false;
    this.response.message = '';
    this.response.raw = '';
    this.response.code = '';
    this.response.statusCode = 0;
    this.response.requestId = '';
    this.response.nonce = '';
    this.response.signatureKid = '';
  }

  private setFailure(code: string, message: string, raw = '', statusCode = 0): false {
    this.response.success = false;
    this.response.code = code || '';
    this.response.message = message || '';
    this.response.raw = raw || '';
    this.response.statusCode = Number(statusCode || 0);
    return false;
  }

  private hasRequiredCredentials(): boolean {
    return Boolean(this.ownerId && this.appName && this.version && this.secret);
  }

  private createSecurityContext(): SecurityContext {
    const requestId = randomUUID();
    const nonce = randomBytesHex(16);
    const timestamp = Date.now();
    return { requestId, nonce, timestamp };
  }

  private buildUrl(endpoint: string): string {
    const ep = clampString(endpoint).replace(/^\/+/, '');
    return `${this.baseUrl}/${ep}`;
  }

  private async getPublicIpCached(): Promise<string> {
    const now = Date.now();
    if (this.cachedPublicIp && now < this.cachedPublicIpExpiresAt) return this.cachedPublicIp;
    try {
      const res = await fetch(this.ipLookupUrl);
      const text = (await res.text()).trim();
      if (text) {
        this.cachedPublicIp = text;
        this.cachedPublicIpExpiresAt = now + 10 * 60 * 1000;
        return text;
      }
    } catch {
      // ignore
    }
    return '';
  }

  private validateResponseMetadata(headers: Headers, requestId: string, nonce: string): { ok: boolean; kid: string; code?: string; message?: string } {
    const respRequestId = headers.get('x-v2-request-id') || '';
    const respNonce = headers.get('x-v2-nonce') || '';
    const kid = headers.get('x-v2-signature-kid') || '';

    if (respRequestId && respRequestId !== requestId) {
      return { ok: false, code: 'AUTH_REQUEST_MISMATCH', message: 'Response request_id does not match the original request.', kid };
    }
    if (respNonce && respNonce !== nonce) {
      return { ok: false, code: 'AUTH_REQUEST_MISMATCH', message: 'Response nonce does not match the original request.', kid };
    }
    return { ok: true, kid };
  }

  private async maybeVerifySignedResponse(headers: Headers, canonicalBody: string): Promise<boolean> {
    if (!this.serverPublicKeyPem) return !this.requireSignedResponses;

    const signature = headers.get('x-v2-signature') || headers.get('x-auth-signature') || '';
    if (!signature) return !this.requireSignedResponses;

    const ok = await verifyEd25519Signature({
      publicKeyPem: this.serverPublicKeyPem,
      message: canonicalBody,
      signatureBase64: signature,
    });

    if (!ok && this.requireSignedResponses) return false;
    return true;
  }

  private loadUpdateData(obj: any): void {
    const u = obj && typeof obj === 'object' ? obj.update : null;
    if (!u || typeof u !== 'object') {
      if (obj && typeof obj === 'object' && (obj.auto_update_enabled !== undefined || obj.auto_update_download_url !== undefined)) {
        this.updateData.available = true;
        this.updateData.latestVersion = clampString(obj.server_version ?? obj.version ?? '');
        this.updateData.autoUpdateEnabled = Boolean(obj.auto_update_enabled ?? false);
        this.updateData.downloadUrl = obj.auto_update_download_url ?? null;
        this.updateData.forceUpdate = Boolean(obj.force_update ?? false);
      }
      return;
    }
    this.updateData.available = Boolean(u.available);
    this.updateData.latestVersion = clampString(u.latest_version ?? u.latestVersion ?? '');
    this.updateData.autoUpdateEnabled = Boolean(u.auto_update_enabled ?? false);
    this.updateData.downloadUrl = u.download_url ?? u.downloadUrl ?? null;
    this.updateData.forceUpdate = Boolean(u.force_update ?? u.forceUpdate ?? false);
    this.updateData.changelog = clampString(u.changelog ?? '');
    this.updateData.showReminder = Boolean(u.show_reminder ?? u.showReminder ?? false);
    this.updateData.reminderMessage = clampString(u.reminder_message ?? u.reminderMessage ?? '');
    this.updateData.allowedUntil = u.allowed_until ?? u.allowedUntil ?? null;
  }

  private compareSemver(current: string, latest: string): number {
    const strip = (s: string) => {
      const t = clampString(s).trim();
      const dash = t.indexOf('-');
      return dash >= 0 ? t.slice(0, dash) : t;
    };

    const parse = (s: string) => {
      const out = [0, 0, 0];
      const parts = strip(s).split('.');
      for (let i = 0; i < out.length && i < parts.length; i++) {
        const m = String(parts[i]).match(/^\d+/);
        out[i] = m ? Number(m[0]) : 0;
      }
      return out;
    };

    const a = parse(current);
    const b = parse(latest);
    for (let i = 0; i < 3; i++) {
      if (a[i] < b[i]) return -1;
      if (a[i] > b[i]) return 1;
    }
    return 0;
  }

  private shouldShowUpdatePrompt(forceShow: boolean): boolean {
    if (!this.updateData.available) return false;
    if (forceShow) return true;
    if (!this.isClientOutdated()) return false;
    if (!this.hasWhitelistedUpdateMessage()) return false;
    return true;
  }

  private openUrl(url: string): void {
    const target = clampString(url).trim();
    if (!target) return;

    const proc: any = (globalThis as any).process;
    if (!proc || !proc.platform) return;

    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const childProcess = require('child_process');
      if (proc.platform === 'win32') childProcess.exec(`cmd /c start "" "${target}"`);
      else if (proc.platform === 'darwin') childProcess.exec(`open "${target}"`);
      else childProcess.exec(`xdg-open "${target}"`);
    } catch {
      return;
    }
  }

  private isClientOutdated(): boolean {
    if (!this.updateData.latestVersion) return false;
    return this.compareSemver(this.version, this.updateData.latestVersion) < 0;
  }

  private hasWhitelistedUpdateMessage(): boolean {
    return Boolean(this.updateData.showReminder || clampString(this.updateData.allowedUntil ?? '').trim());
  }

  private isAutoUpdateEnabled(): boolean {
    return Boolean(this.updateData.autoUpdateEnabled);
  }

  private formatDisplayDate(rawDate: string | null): string {
    const value = clampString(rawDate ?? '').trim();
    if (!value) return value;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return value;
    return parsed.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  }

  private buildWhitelistedUpdateMessage(): string {
    const allowedUntil = clampString(this.updateData.allowedUntil ?? '').trim();
    const base = allowedUntil
      ? `A new version is ready, and you can keep using this build until ${this.formatDisplayDate(allowedUntil)}.`
      : 'A new version is ready, and you can still use this build for now.';

    if (!this.isAutoUpdateEnabled()) return base;
    return `${base}\n\nWould you like to download the latest version now?`;
  }

  private tryShowWindowsMessageBox(message: string, yesNo: boolean): string | null {
    const proc: any = (globalThis as any).process;
    if (!proc || proc.platform !== 'win32') return null;

    const escape = (value: string) => clampString(value).replace(/'/g, "''");
    const button = yesNo ? 'YesNo' : 'OK';
    const script = [
      'Add-Type -AssemblyName PresentationFramework',
      `$result = [System.Windows.MessageBox]::Show('${escape(message)}', 'AuthlyX Update', [System.Windows.MessageBoxButton]::${button}, [System.Windows.MessageBoxImage]::Information)`,
      'Write-Output $result',
    ].join('; ');

    try {
      const childProcess = require('child_process');
      const out = childProcess.spawnSync('powershell', ['-NoProfile', '-Command', script], { encoding: 'utf8' });
      if (out.status === 0) return clampString(out.stdout).trim();
    } catch {
      return null;
    }
    return null;
  }

  private async showRequiredUpdateConsole(): Promise<void> {
    const message = clampString(this.response.message || '').trim() || 'Please update your app to the latest version.';
    console.log(message);

    const latest = clampString(this.updateData.latestVersion).trim();
    if (latest) console.log(`Latest version: ${latest}`);

    const downloadUrl = clampString(this.updateData.downloadUrl ?? '').trim();
    if (!this.isAutoUpdateEnabled() || !downloadUrl) return;

    console.log('1. Download Latest');
    console.log('2. Exit');

    const proc: any = (globalThis as any).process;
    if (!proc || !proc.stdin || !proc.stdin.isTTY) return;

    const readline = require('readline');
    const rl = readline.createInterface({ input: proc.stdin, output: proc.stdout });
    const answer = await new Promise<string>((resolve) => rl.question('Select an option (1 or 2): ', resolve));
    rl.close();
    if (clampString(answer).trim() === '1') this.openUrl(downloadUrl);
  }

  private async promptUpdateIfNeeded(forceShow: boolean): Promise<void> {
    if (!this.shouldShowUpdatePrompt(forceShow)) return;

    if (forceShow) {
      await this.showRequiredUpdateConsole();
      return;
    }

    const downloadUrl = clampString(this.updateData.downloadUrl ?? '').trim();
    const msg = this.buildWhitelistedUpdateMessage();
    const useDownloadPrompt = this.isAutoUpdateEnabled() && !!downloadUrl;
    const messageResult = this.tryShowWindowsMessageBox(msg, useDownloadPrompt);
    if (messageResult) {
      if (useDownloadPrompt && messageResult.toLowerCase() === 'yes') this.openUrl(downloadUrl);
      return;
    }
    this.logger.log(`[UPDATE] ${msg.replace(/\n/g, ' | ')}`);

    const proc: any = (globalThis as any).process;
    if (!useDownloadPrompt || !proc || !proc.stdin || !proc.stdin.isTTY) {
      console.log(msg);
      return;
    }

    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const readline = require('readline');
    const rl = readline.createInterface({ input: proc.stdin, output: proc.stdout });
    const answer = await new Promise<string>((resolve) => rl.question('Download the latest version now? (Y/N): ', resolve));
    rl.close();
    const a = clampString(answer).trim().toLowerCase();
    if (a === 'y' || a === 'yes') this.openUrl(downloadUrl);
  }

  private async loadUserData(obj: any): Promise<void> {
    const root = obj && typeof obj === 'object' ? obj : null;
    const user = root && typeof root.user === 'object' ? root.user : null;
    const license = root && typeof root.license === 'object' ? root.license : null;
    const device = root && typeof root.device === 'object' ? root.device : null;

    if (user) {
      this.userData.username = clampString(user.username ?? '');
      this.userData.email = clampString(user.email ?? this.userData.email ?? '');
      this.userData.subscription = clampString(user.subscription ?? this.userData.subscription ?? '');
      if (user.subscription_level !== undefined && user.subscription_level !== null) {
        this.userData.subscriptionLevel = clampString(user.subscription_level);
      }
      this.userData.expiryDate = clampString(user.expiry_date ?? this.userData.expiryDate ?? '');
      this.userData.lastLogin = clampString(user.last_login ?? this.userData.lastLogin ?? '');
      this.userData.registeredAt = clampString(user.created_at ?? user.registered_at ?? this.userData.registeredAt ?? '');
      this.userData.ipAddress = clampString(user.ip_address ?? this.userData.ipAddress ?? '');
      this.userData.hwidSid = clampString(user.sid ?? user.hwid ?? this.userData.hwidSid ?? '');
    }

    if (license) {
      this.userData.licenseKey = clampString(license.license_key ?? license.licenseKey ?? this.userData.licenseKey ?? '');
      if (!this.userData.subscription) this.userData.subscription = clampString(license.subscription ?? '');
      if (!this.userData.subscriptionLevel && license.subscription_level !== undefined && license.subscription_level !== null) {
        this.userData.subscriptionLevel = clampString(license.subscription_level);
      }
      if (!this.userData.expiryDate) this.userData.expiryDate = clampString(license.expiry_date ?? '');
      if (!this.userData.lastLogin) this.userData.lastLogin = clampString(license.last_login ?? '');
      if (!this.userData.registeredAt) this.userData.registeredAt = clampString(license.created_at ?? license.registered_at ?? '');
    }

    if (device) {
      if (!this.userData.subscription) this.userData.subscription = clampString(device.subscription ?? '');
      if (!this.userData.subscriptionLevel && device.subscription_level !== undefined && device.subscription_level !== null) {
        this.userData.subscriptionLevel = clampString(device.subscription_level);
      }
      if (!this.userData.expiryDate) this.userData.expiryDate = clampString(device.expiry_date ?? '');
      if (!this.userData.lastLogin) this.userData.lastLogin = clampString(device.last_login ?? '');
      if (!this.userData.registeredAt) this.userData.registeredAt = clampString(device.created_at ?? device.registered_at ?? '');
      if (!this.userData.ipAddress) this.userData.ipAddress = clampString(device.ip_address ?? '');
      if (!this.userData.hwidSid) this.userData.hwidSid = clampString(device.sid ?? device.hwid ?? '');
    }

    if (!this.userData.ipAddress) this.userData.ipAddress = await this.getPublicIpCached();
    this.userData.daysLeft = computeDaysLeft(this.userData.expiryDate);
  }

  private loadVariableData(obj: any): void {
    const v = obj && typeof obj === 'object' ? obj.variable : null;
    if (!v || typeof v !== 'object') return;
    this.variableData.varKey = clampString(v.var_key ?? v.varKey ?? '');
    this.variableData.varValue = clampString(v.var_value ?? v.varValue ?? '');
    this.variableData.updatedAt = clampString(v.updated_at ?? v.updatedAt ?? '');
  }

  private loadChatMessages(obj: any): void {
    const c = obj && typeof obj === 'object' ? obj.chats ?? obj.messages ?? obj.chatMessages : null;
    if (!c || typeof c !== 'object') return;
    this.chatMessages.channelName = clampString(c.channel_name ?? c.channelName ?? this.chatMessages.channelName ?? '');
    this.chatMessages.messages = Array.isArray(c.messages) ? c.messages : [];
    this.chatMessages.count = Number(c.count ?? this.chatMessages.count ?? 0);
    this.chatMessages.nextCursor = clampString(c.next_cursor ?? c.nextCursor ?? '');
    this.chatMessages.hasMore = Boolean(c.has_more ?? c.hasMore ?? false);
  }

  private async post(endpoint: string, body: any): Promise<any | null> {
    this.resetResponse();
    if (!this.hasRequiredCredentials()) return this.setFailure('AUTH_CONFIG', 'Missing AuthlyX credentials.');

    const url = this.buildUrl(endpoint);
    const sec = this.createSecurityContext();

    const payload = {
      ...body,
      owner_id: this.ownerId,
      app_name: this.appName,
      version: this.version,
      secret: this.secret,
      request_id: sec.requestId,
      nonce: sec.nonce,
      timestamp: sec.timestamp,
      hash: this.applicationHash || undefined,
    };

    const jsonBody = canonicalJson(payload);
    this.logger.log(`[SDK][REQUEST] POST ${url} ${jsonBody}`);

    let res: Response;
    let text = '';
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-request-id': sec.requestId,
          'x-auth-nonce': sec.nonce,
          'x-auth-timestamp': String(sec.timestamp),
        },
        body: JSON.stringify(payload),
      });
      text = await res.text();
    } catch (e: any) {
      return this.setFailure('NETWORK_ERROR', 'Network error.', String(e?.message ?? e ?? ''), 0);
    }

    this.response.statusCode = res.status;
    this.response.raw = text || '';
    this.response.requestId = sec.requestId;
    this.response.nonce = sec.nonce;

    this.logger.log(`[SDK][RESPONSE] ${res.status} ${text}`);

    const meta = this.validateResponseMetadata(res.headers, sec.requestId, sec.nonce);
    this.response.signatureKid = meta.kid || '';
    if (!meta.ok) return this.setFailure(meta.code || 'AUTH_REQUEST_MISMATCH', meta.message || 'Request mismatch.', text, res.status);

    const parsed = safeJsonParse(text);
    if (!parsed) return this.setFailure('BAD_RESPONSE', 'Invalid JSON response.', text, res.status);

    // Optional response signature verification
    const canonicalRespBody = canonicalJson(parsed);
    const verified = await this.maybeVerifySignedResponse(res.headers, canonicalRespBody);
    if (!verified) return this.setFailure('INVALID_SIGNATURE', 'Response signature verification failed.', text, res.status);

    this.response.success = Boolean(parsed.success);
    this.response.message = clampString(parsed.message ?? '');
    this.response.code = clampString(parsed.code ?? '');

    return parsed;
  }

  Log(message: string): void {
    this.logger.log(`[SDK][LOG] ${message}`);
  }

  IsInitialized(): boolean {
    return this.initialized && Boolean(this.sessionId);
  }

  GetSessionId(): string {
    return this.sessionId || '';
  }

  async Init(): Promise<boolean> {
    const resp = await this.post('init', {});
    if (!resp) return false;

    this.sessionId = clampString(resp.session_id ?? resp.sessionId ?? '');
    this.initialized = Boolean(resp.success) && Boolean(this.sessionId);
    this.loadUpdateData(resp);
    await this.promptUpdateIfNeeded(String(this.response.code || '').toUpperCase() === 'UPDATE_REQUIRED');
    return Boolean(resp.success);
  }

  async Login(identifier: string, password: string | null = null, deviceType: string | null = null): Promise<boolean> {
    if (deviceType) return this.DeviceLogin(deviceType, identifier);
    if (!password) return this.LicenseLogin(identifier);
    return this.UsernameLogin(identifier, password);
  }

  async UsernameLogin(username: string, password: string): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('login', {
      username: clampString(username),
      password: clampString(password),
      session_id: this.sessionId,
      sid: this.userData.hwidSid || undefined,
      ip_address: this.userData.ipAddress || undefined,
    });
    if (!resp) return false;
    if (resp.success) await this.loadUserData(resp);
    return Boolean(resp.success);
  }

  async LicenseLogin(licenseKey: string): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('license-login', {
      license_key: clampString(licenseKey),
      session_id: this.sessionId,
      sid: this.userData.hwidSid || undefined,
      ip_address: this.userData.ipAddress || undefined,
    });
    if (!resp) return false;
    if (resp.success) await this.loadUserData(resp);
    return Boolean(resp.success);
  }

  async DeviceLogin(deviceType: string, deviceId: string): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('device-auth', {
      device_type: clampString(deviceType),
      device_id: clampString(deviceId),
      session_id: this.sessionId,
      sid: this.userData.hwidSid || undefined,
      ip_address: this.userData.ipAddress || undefined,
    });
    if (!resp) return false;
    if (resp.success) await this.loadUserData(resp);
    return Boolean(resp.success);
  }

  async Register(username: string, password: string, licenseKey: string, email = ''): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('register', {
      username: clampString(username),
      password: clampString(password),
      license_key: clampString(licenseKey),
      email: clampString(email),
      session_id: this.sessionId,
      sid: this.userData.hwidSid || undefined,
      ip_address: this.userData.ipAddress || undefined,
    });
    if (!resp) return false;
    if (resp.success) await this.loadUserData(resp);
    return Boolean(resp.success);
  }

  async ExtendTime(username: string, licenseKey: string): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('extend', {
      username: clampString(username),
      license_key: clampString(licenseKey),
      session_id: this.sessionId,
    });
    if (!resp) return false;
    if (resp.success) await this.loadUserData(resp);
    return Boolean(resp.success);
  }

  async ChangePassword(oldPassword: string, newPassword: string): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('change-password', {
      old_password: clampString(oldPassword),
      new_password: clampString(newPassword),
      session_id: this.sessionId,
    });
    return Boolean(resp && resp.success);
  }

  async GetVariable(key: string): Promise<string> {
    if (!this.IsInitialized()) {
      this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
      return '';
    }
    const resp = await this.post('variables/get', { var_key: clampString(key), session_id: this.sessionId });
    if (!resp) return '';
    if (resp.success) this.loadVariableData(resp);
    return this.variableData.varValue || '';
  }

  async SetVariable(key: string, value: string): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('variables/set', { var_key: clampString(key), var_value: clampString(value), session_id: this.sessionId });
    if (!resp) return false;
    if (resp.success) this.loadVariableData(resp);
    return Boolean(resp.success);
  }

  async GetChats(channelName: string, limit = 100, cursor: string | null = null): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('chats/get', {
      channel_name: clampString(channelName),
      limit: Number(limit || 100),
      cursor: cursor ? clampString(cursor) : undefined,
      session_id: this.sessionId,
    });
    if (!resp) return false;
    if (resp.success) this.loadChatMessages(resp);
    return Boolean(resp.success);
  }

  async SendChat(message: string, channelName: string | null = null): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('chats/send', {
      message: clampString(message),
      channel_name: channelName ? clampString(channelName) : undefined,
      session_id: this.sessionId,
    });
    return Boolean(resp && resp.success);
  }

  async ValidateSession(): Promise<boolean> {
    if (!this.IsInitialized()) return this.setFailure('NOT_INITIALIZED', 'AuthlyX is not initialized. Call Init() first.');
    const resp = await this.post('validate', { session_id: this.sessionId });
    return Boolean(resp && resp.success);
  }

  // Lowercase aliases (quality-of-life) so both `Init/init`, `Login/login`, etc work.
  setLogger(logger: Logger): void { return this.SetLogger(logger); }
  log(message: string): void { return this.Log(message); }
  isInitialized(): boolean { return this.IsInitialized(); }
  getSessionId(): string { return this.GetSessionId(); }

  init(): Promise<boolean> { return this.Init(); }
  login(identifier: string, password: string | null = null, deviceType: string | null = null): Promise<boolean> {
    return this.Login(identifier, password, deviceType);
  }
  register(username: string, password: string, licenseKey: string, email = ''): Promise<boolean> {
    return this.Register(username, password, licenseKey, email);
  }
  extendTime(username: string, licenseKey: string): Promise<boolean> { return this.ExtendTime(username, licenseKey); }
  changePassword(oldPassword: string, newPassword: string): Promise<boolean> { return this.ChangePassword(oldPassword, newPassword); }
  getVariable(key: string): Promise<string> { return this.GetVariable(key); }
  setVariable(key: string, value: string): Promise<boolean> { return this.SetVariable(key, value); }
  getChats(channelName: string, limit = 100, cursor: string | null = null): Promise<boolean> { return this.GetChats(channelName, limit, cursor); }
  sendChat(message: string, channelName: string | null = null): Promise<boolean> { return this.SendChat(message, channelName); }
  validateSession(): Promise<boolean> { return this.ValidateSession(); }
}
