export type AuthlyXResponse = {
  success: boolean;
  message: string;
  raw?: string;
  code?: string;
  statusCode?: number;
  requestId?: string;
  nonce?: string;
  signatureKid?: string;
};

export type AuthlyXUserData = {
  username: string;
  email: string;
  licenseKey: string;
  subscription: string;
  subscriptionLevel: string;
  expiryDate: string;
  daysLeft: number;
  lastLogin: string;
  registeredAt: string;
  hwidSid: string;
  ipAddress: string;
};

export type AuthlyXVariableData = {
  varKey: string;
  varValue: string;
  updatedAt: string;
};

export type AuthlyXUpdateData = {
  available: boolean;
  latestVersion: string;
  downloadUrl: string | null;
  forceUpdate: boolean;
  changelog: string;
  showReminder: boolean;
  reminderMessage: string;
  allowedUntil: string | null;
};

export type AuthlyXChatMessage = {
  id?: string;
  username?: string;
  message?: string;
  createdAt?: string;
};

export type AuthlyXChatMessages = {
  channelName: string;
  messages: AuthlyXChatMessage[];
  count: number;
  nextCursor: string;
  hasMore: boolean;
};

export type AuthlyXInitOptions = {
  debug?: boolean;
  api?: string;
  hash?: string;
  ipLookupUrl?: string;

  serverPublicKeyPem?: string;
  requireSignedResponses?: boolean;

  logger?: { enabled: boolean; log: (line: string) => void };
};
