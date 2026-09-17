import { randomBytes, randomInt, randomUUID, createHash, createHmac, createCipheriv, createDecipheriv, scrypt, pbkdf2, timingSafeEqual } from 'node:crypto';
import { compare as bcryptCompare } from 'bcryptjs';
import { domainToASCII } from 'node:url';
import { TOTP, Secret } from 'otpauth';
import { createRegistrationPolicy } from './registration.ts';
import type { RegistrationPolicy, RegistrationInput, RegistrationProfile, RegistrationOptions } from './registration.ts';
import { AuthError, openAuthStore } from './auth-store.ts';
import type { AuthRecord, SessionRecord } from './auth-store.ts';
export { AuthError };
export interface AuthUser {
    id: string;
    email: string;
    emailVerified: boolean;
    status: 'active' | 'locked' | 'pending-delete';
    roles: string[];
    created: number;
    totpEnabled: boolean;
    profile?: RegistrationProfile;
}
export type AuthRestriction = 'verify-email' | 'enroll-mfa';
export interface AuthSecurityPolicy {
    requireEmailVerification: boolean;
    requireMfa: boolean;
    deletionGraceMs: number;
}
export interface AuthPrincipal {
    restrictions?: AuthRestriction[];
    id: string;
    email: string;
    emailVerified: boolean;
    roles: string[];
    permissions: string[];
    sessionId: string;
    authenticatedAt: number;
    impersonatorId?: string;
}
export interface ExternalAuthProof {
    kind: 'oidc';
    version: number;
    provider: string;
    subject: string;
}
export interface PasskeyAuthProof {
    kind: 'passkey';
    version: number;
    credentialId: string;
    publicKeyHash: string;
    expectedCounter: number;
    newCounter: number;
}
export type AuthProof = ExternalAuthProof | PasskeyAuthProof;
export interface AuthDevice {
    id: string;
    label?: string;
}
export interface AuthSessionResult {
    newDevice?: boolean;
    user: AuthUser;
    token: string;
    principal: AuthPrincipal;
}
export interface AuthSession {
    id: string;
    created: number;
    authenticatedAt: number;
    expires: number;
    lastSeen?: number;
    deviceLabel?: string;
}
export interface AuthDailyMetric {
    day: string;
    signUps: number;
    signIns: number;
    failedSignIns: number;
    methods: {
        method: string;
        signUps: number;
        signIns: number;
        failedSignIns: number;
    }[];
}
export interface AuthAuditEvent {
    id: number;
    actor: string;
    action: string;
    subject: string;
    created: number;
    reason: string;
}
export interface AuthLifecycleEvent {
    type: 'sign-up' | 'delete';
    accountId: string;
}
export interface AuthHookStats {
    accepted: number;
    dropped: number;
    failed: number;
    timedOut: number;
}
export interface AuthOptions {
    approveConfigurationChangeFrom?: string;
    configurationTag?: string;
    requireEmailVerification?: boolean;
    requireMfa?: boolean;
    deletionGraceMs?: number;
    onLifecycle?: (event: AuthLifecycleEvent, context: {
        signal: AbortSignal;
    }) => void | Promise<void>;
    database: string;
    encryptionKey?: Uint8Array;
    encryptionKeys?: Record<string, Uint8Array>;
    activeEncryptionKey?: string;
    roles: Record<string, string[]>;
    defaultRole?: string;
    now?: () => number;
    registrationPolicy?: RegistrationPolicy;
    sessionTtlMs?: number;
    sessionIdleMs?: number;
    allowImpersonation?: boolean;
    registrationMode?: 'open' | 'invite-only' | 'waitlist' | 'off';
    allowedEmails?: string[];
    blockedEmails?: string[];
    checkPassword?: (password: string, context?: {
        signal: AbortSignal;
    }) => Promise<void>;
    allowedEmailDomains?: string[];
    blockedEmailDomains?: string[];
}
export interface AuthCredentials {
    device?: AuthDevice;
    email: string;
    password: string;
    totp?: string;
    recoveryCode?: string;
}
export interface AuthPasskey {
    id: string;
    accountId: string;
    publicKey: string;
    counter: number;
    transports?: string[];
}
export interface AuthCase {
    id: string;
    accountId: string;
    action: 'reset-factors' | 'lock' | 'unlock' | 'roles';
    roles?: string[];
    reason: string;
    makerId: string;
    approverId?: string;
    status: 'pending' | 'applied' | 'closed';
    notes?: {
        actorId: string;
        note: string;
        created: number;
    }[];
    created: number;
    expires: number;
    targetVersion: number;
}
export interface AuthService {
    register(input: {
        email: string;
        password: string;
        invitationToken?: string;
        device?: AuthDevice;
        profile?: RegistrationInput;
    }): Promise<AuthSessionResult>;
    bootstrapAdmin(input: {
        email: string;
        password: string;
    }): Promise<AuthSessionResult>;
    login(input: AuthCredentials): Promise<AuthSessionResult>;
    stepUp(input: {
        token: string;
        password: string;
        totp?: string;
        recoveryCode?: string;
    }): Promise<AuthSessionResult>;
    authenticate(token: string): Promise<AuthPrincipal | null>;
    logout(token: string): Promise<void>;
    revokeSessions(accountId: string): Promise<void>;
    listUsers(options?: {
        limit?: number;
        after?: string;
        query?: string;
        status?: AuthUser['status'];
        role?: string;
    }): Promise<{
        users: AuthUser[];
        next?: string;
    }>;
    getUser(id: string): Promise<AuthUser | null>;
    getRoles(): Record<string, string[]>;
    listSessions(accountId: string): Promise<AuthSession[]>;
    listDevices(accountId: string): Promise<{
        id: string;
        label: string;
        lastSeen: number;
    }[]>;
    listAudit(options?: {
        limit?: number;
        after?: string;
        actor?: string;
        subject?: string;
        action?: string;
        from?: number;
        to?: number;
    }): Promise<{
        events: AuthAuditEvent[];
        next?: string;
    }>;
    issueToken(input: {
        email: string;
        purpose: 'verify-email' | 'reset-password';
    }): Promise<{
        token: string | null;
    }>;
    consumeVerification(token: string): Promise<AuthUser>;
    resetPassword(input: {
        token: string;
        password: string;
    }): Promise<AuthUser>;
    beginTotp(token: string): Promise<{
        secret: string;
        otpauthUrl: string;
    }>;
    confirmTotp(input: {
        token: string;
        code: string;
    }): Promise<{
        recoveryCodes: string[];
    }>;
    disableTotp(input: {
        token: string;
        password: string;
        code: string;
    }): Promise<void>;
    adminSetRoles(input: {
        actorToken: string;
        accountId: string;
        roles: string[];
        reason?: string;
    }): Promise<AuthUser>;
    adminSetStatus(input: {
        actorToken: string;
        accountId: string;
        status: 'active' | 'locked';
        reason?: string;
    }): Promise<AuthUser>;
    adminRevokeSessions(input: {
        actorToken: string;
        accountId: string;
        reason?: string;
    }): Promise<void>;
    putFlow(input: {
        id: string;
        kind: string;
        data: unknown;
        expires: number;
    }): Promise<void>;
    consumeFlow(id: string, kind: string): Promise<unknown | null>;
    findExternal(provider: string, subject: string): Promise<AuthUser | null>;
    linkExternal(input: {
        actorToken: string;
        provider: string;
        subject: string;
    }): Promise<void>;
    createExternalAccount(input: {
        email: string;
        provider: string;
        subject: string;
        emailVerified: boolean;
        profile?: RegistrationInput;
    }): Promise<AuthUser>;
    getExternalProof(provider: string, subject: string): Promise<{
        user: AuthUser;
        proof: ExternalAuthProof;
    } | null>;
    issueSession(accountId: string, input: {
        method: 'passkey' | 'oidc';
        proof: AuthProof;
        device?: AuthDevice;
        totp?: string;
        recoveryCode?: string;
    }): Promise<AuthSessionResult>;
    addPasskey(input: {
        actorToken: string;
        credential: Omit<AuthPasskey, 'accountId'>;
    }): Promise<void>;
    getPasskey(id: string): Promise<{
        accountId: string;
        credential: Omit<AuthPasskey, 'accountId'>;
        proof: Omit<PasskeyAuthProof, 'newCounter'>;
    } | null>;
    listPasskeys(accountId: string): Promise<Omit<AuthPasskey, 'accountId'>[]>;
    advancePasskeyCounter(input: {
        id: string;
        expectedCounter: number;
        newCounter: number;
    }): Promise<void>;
    changePassword(input: {
        token: string;
        currentPassword: string;
        password: string;
        totp?: string;
        recoveryCode?: string;
    }): Promise<void>;
    exportAccount(token: string): Promise<{
        user: AuthUser;
        sessions: AuthSession[];
        passkeys: {
            id: string;
            transports?: string[];
        }[];
        identities: {
            provider: string;
            subject: string;
        }[];
    }>;
    deleteAccount(input: {
        token: string;
        password?: string;
        totp?: string;
        recoveryCode?: string;
    }): Promise<{
        cancelToken: string;
        deleteAfter: number;
    }>;
    cancelDeletion(token: string): Promise<void>;
    purgeDeleted(options?: {
        limit?: number;
    }): Promise<{
        purged: number;
    }>;
    issueEmailCode(input: {
        email: string;
    }): Promise<{
        flowId: string;
        code: string | null;
    }>;
    consumeEmailCode(input: {
        flowId: string;
        code: string;
        device?: AuthDevice;
        totp?: string;
        recoveryCode?: string;
    }): Promise<AuthSessionResult>;
    createCase(input: {
        actorToken: string;
        accountId: string;
        action: AuthCase['action'];
        roles?: string[];
        reason: string;
    }): Promise<AuthCase>;
    listCases(options?: {
        limit?: number;
        after?: string;
    }): Promise<{
        cases: AuthCase[];
        next?: string;
    }>;
    getCase(id: string): Promise<AuthCase | null>;
    approveCase(input: {
        actorToken: string;
        caseId: string;
        reason: string;
    }): Promise<AuthCase>;
    createImpersonation(input: {
        actorToken: string;
        accountId: string;
        reason: string;
    }): Promise<AuthSessionResult>;
    adminBulk(input: {
        actorToken: string;
        accountIds: string[];
        action: 'lock' | 'unlock' | 'revoke-sessions';
        reason: string;
    }): Promise<{
        affected: number;
    }>;
    dashboard(): Promise<{
        users: number;
        active: number;
        locked: number;
        pendingDeletion: number;
        sessions: number;
        waitlist: number;
        daily: AuthDailyMetric[];
    }>;
    listAllSessions(options?: {
        limit?: number;
        after?: string;
    }): Promise<{
        sessions: (AuthSession & {
            accountId: string;
            email: string;
        })[];
        next?: string;
    }>;
    importUsers(users: {
        email: string;
        passwordHash: string;
        emailVerified?: boolean;
    }[]): Promise<{
        imported: number;
    }>;
    getProfile(token: string): Promise<RegistrationProfile>;
    updateProfile(input: {
        token: string;
        profile: RegistrationInput;
    }): Promise<RegistrationProfile>;
    getConfigurationRevision(): Promise<string>;
    getSecurityPolicy(): AuthSecurityPolicy;
    getHookStats(): AuthHookStats;
    getRegistrationSchema(): RegistrationOptions;
    getRegistrationMode(): 'open' | 'invite-only' | 'waitlist' | 'off';
    requestRegistration(input: {
        email: string;
        password: string;
        profile?: RegistrationInput;
    }): Promise<{
        id: string;
    }>;
    listRegistrationRequests(options?: {
        limit?: number;
        after?: string;
    }): Promise<{
        requests: {
            id: string;
            email: string;
            created: number;
        }[];
        next?: string;
    }>;
    approveRegistration(input: {
        actorToken: string;
        requestId: string;
        reason?: string;
    }): Promise<AuthUser>;
    invite(input: {
        actorToken: string;
        email: string;
    }): Promise<{
        token: string;
    }>;
    completeStepUp(input: {
        token: string;
        accountId: string;
        method: 'passkey';
        proof: PasskeyAuthProof;
        totp?: string;
        recoveryCode?: string;
    }): Promise<AuthSessionResult>;
    removePasskey(input: {
        token: string;
        credentialId: string;
    }): Promise<void>;
    unlinkExternal(input: {
        token: string;
        provider: string;
        subject: string;
    }): Promise<void>;
    closeCase(input: {
        actorToken: string;
        caseId: string;
        reason: string;
    }): Promise<AuthCase>;
    addCaseNote(input: {
        actorToken: string;
        caseId: string;
        note: string;
    }): Promise<AuthCase>;
    cleanup(options?: {
        limit?: number;
    }): Promise<{
        removed: number;
    }>;
    requestEmailChange(input: {
        token: string;
        email: string;
        password?: string;
        totp?: string;
        recoveryCode?: string;
    }): Promise<{
        oldEmail: string;
        newEmail: string;
        verificationToken: string;
        cancelToken: string;
        activateAfter: number;
    }>;
    confirmEmailChange(token: string): Promise<AuthUser>;
    cancelEmailChange(token: string): Promise<void>;
    adminCreateUser(input: {
        actorToken: string;
        email: string;
        reason: string;
    }): Promise<{
        user: AuthUser;
        setupToken: string;
    }>;
    revokeSession(input: {
        token: string;
        sessionId: string;
    }): Promise<void>;
    adminRevokeSession(input: {
        actorToken: string;
        sessionId: string;
        reason: string;
    }): Promise<void>;
    adminExport(input: {
        actorToken: string;
        accountId: string;
        reason: string;
    }): Promise<{
        user: AuthUser;
        sessions: AuthSession[];
        identities: {
            provider: string;
            subject: string;
        }[];
    }>;
    rotateEncryptionKey(): Promise<{
        changed: number;
        remaining: number;
    }>;
    close(): Promise<void>;
}
const fail = (status: number, code: string): never => { throw new AuthError(status, code); };
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
const validToken = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value);
const id = (value: string) => {
    if (typeof value !== 'string' || value.length > 256 || !value || /[\x00-\x20\x7f]/.test(value))
        fail(400, 'invalid_identifier');
    return value;
};
export function normalizeEmail(value: string): string {
    if (typeof value !== 'string' || value.length > 254)
        fail(400, 'invalid_email');
    const parts = value.normalize('NFKC').trim().split('@');
    if (parts.length !== 2)
        fail(400, 'invalid_email');
    const local = parts[0]!.toLowerCase(), domain = domainToASCII(parts[1]!).toLowerCase();
    if (!local || local.length > 64 || /[\s\x00-\x1f\x7f"(),:;<>\[\]\\]/.test(local) || !domain || domain.length > 253 || domain.split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) || local.length + domain.length + 1 > 254)
        fail(400, 'invalid_email');
    return local + '@' + domain;
}
function password(value: string): void {
    if (typeof value !== 'string' || value.length > 1024 || [...value].length < 15 || [...value].length > 256 || Buffer.byteLength(value) > 1024)
        fail(400, 'password_length_invalid');
}
let hashing = 0;
let passwordChecks = 0;
let lifecycleActive = 0;
async function derive(value: string, salt: Buffer): Promise<Buffer> {
    if (hashing >= 2)
        fail(503, 'password_hash_busy');
    hashing++;
    try {
        return await new Promise<Buffer>((resolve, reject) => scrypt(value, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 160 * 1024 * 1024 }, (error, key) => error ? reject(new AuthError(503, 'password_hash_unavailable')) : resolve(key)));
    }
    finally {
        hashing--;
    }
}
async function hashPassword(value: string, validate = true): Promise<string> {
    if (validate)
        password(value);
    const salt = randomBytes(16), key = await derive(value, salt);
    return `scrypt-v1$${salt.toString('base64url')}$${key.toString('base64url')}`;
}
function validPasswordHash(encoded: string): boolean {
    if (typeof encoded !== 'string' || encoded.length > 512)
        return false;
    if (/^scrypt-v1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/.test(encoded))
        return true;
    const bcrypt = /^\$2[aby]\$(\d{2})\$[./A-Za-z0-9]{53}$/.exec(encoded);
    if (bcrypt)
        return Number(bcrypt[1]) >= 10 && Number(bcrypt[1]) <= 14;
    const pb = /^pbkdf2-sha256\$(\d{6,7})\$([A-Za-z0-9_-]{22,86})\$([A-Za-z0-9_-]{43})$/.exec(encoded);
    return Boolean(pb) && Number(pb![1]) >= 600000 && Number(pb![1]) <= 1000000;
}
async function verifyPassword(value: string, encoded: string | undefined): Promise<boolean> {
    if (typeof value !== 'string' || Buffer.byteLength(value) > 1024)
        fail(401, 'invalid_credentials');
    if (encoded && validPasswordHash(encoded) && !encoded.startsWith('scrypt-v1$')) {
        if (hashing >= 2)
            fail(503, 'password_hash_busy');
        hashing++;
        try {
            if (encoded.startsWith('$2')) {
                if (Buffer.byteLength(value) > 72)
                    return false;
                return await bcryptCompare(value, encoded);
            }
            const parts = encoded.split('$'), derived = await new Promise<Buffer>((resolve, reject) => pbkdf2(value, Buffer.from(parts[2]!, 'base64url'), Number(parts[1]), 32, 'sha256', (error, key) => error ? reject(new AuthError(503, 'password_hash_unavailable')) : resolve(key)));
            return timingSafeEqual(derived, Buffer.from(parts[3]!, 'base64url'));
        }
        finally {
            hashing--;
        }
    }
    const parts = encoded?.split('$'), valid = encoded && validPasswordHash(encoded) && parts?.[0] === 'scrypt-v1';
    const key = await derive(value, valid ? Buffer.from(parts![1]!, 'base64url') : Buffer.alloc(16));
    return Boolean(valid) && timingSafeEqual(key, Buffer.from(parts![2]!, 'base64url'));
}
const basePublicUser = (user: AuthRecord): AuthUser => ({ id: user.id, email: user.email, emailVerified: user.emailVerified, status: user.status, roles: [...user.roles], created: user.created, totpEnabled: Boolean(user.totpSecret) });
export async function createAuthService(options: AuthOptions): Promise<AuthService> {
    if (options.approveConfigurationChangeFrom !== undefined && (typeof options.approveConfigurationChangeFrom !== 'string' || !/^[a-f0-9]{64}$/.test(options.approveConfigurationChangeFrom)))
        fail(400, 'invalid_configuration_approval');
    if (options.configurationTag !== undefined && (typeof options.configurationTag !== 'string' || options.configurationTag.length < 1 || options.configurationTag.length > 128 || /[\x00-\x1f\x7f]/.test(options.configurationTag)))
        fail(400, 'invalid_configuration_tag');
    for (const value of [options.requireEmailVerification, options.requireMfa])
        if (value !== undefined && typeof value !== 'boolean')
            fail(400, 'invalid_security_policy');
    const deletionGraceMs = options.deletionGraceMs ?? 604800000;
    if (!Number.isSafeInteger(deletionGraceMs) || deletionGraceMs < 86400000 || deletionGraceMs > 2592000000)
        fail(400, 'invalid_deletion_grace');
    const securityPolicy: AuthSecurityPolicy = Object.freeze({ requireEmailVerification: options.requireEmailVerification === true, requireMfa: options.requireMfa === true, deletionGraceMs });
    const supplied = options.encryptionKeys ?? (options.encryptionKey ? { legacy: options.encryptionKey } : {}), activeKey = options.activeEncryptionKey ?? 'legacy';
    const keys: Record<string, Buffer> = Object.create(null);
    if (Object.keys(supplied).length < 1 || Object.keys(supplied).length > 8)
        fail(400, 'auth_encryption_key_required');
    for (const [name, value] of Object.entries(supplied)) {
        if (!/^[a-zA-Z0-9_-]{1,32}$/.test(name) || !(value instanceof Uint8Array) || value.byteLength !== 32)
            fail(400, 'auth_encryption_key_required');
        keys[name] = Buffer.from(value);
    }
    if (!keys[activeKey])
        fail(400, 'auth_encryption_key_required');
    if (!options.roles || typeof options.roles !== 'object' || Array.isArray(options.roles) || Object.keys(options.roles).length > 64)
        fail(400, 'invalid_roles');
    const roles: Record<string, string[]> = Object.create(null);
    for (const [name, list] of Object.entries(options.roles)) {
        if (!/^[a-z][a-z0-9_-]{0,63}$/.test(name) || !Array.isArray(list) || list.length > 128 || list.some(p => typeof p !== 'string' || !/^\*$|^[a-z][a-z0-9_.:-]{0,127}$/.test(p)))
            fail(400, 'invalid_roles');
        roles[name] = [...new Set(list)];
    }
    const defaultRole = options.defaultRole ?? 'user';
    if (!Object.hasOwn(roles, defaultRole) || roles[defaultRole]!.some(p => p === '*' || p.startsWith('auth.')))
        fail(400, 'unsafe_default_role');
    const mode = options.registrationMode ?? 'open';
    if (!['open', 'invite-only', 'waitlist', 'off'].includes(mode))
        fail(400, 'invalid_registration_mode');
    const domains = (values: string[] | undefined) => {
        if (values !== undefined && (!Array.isArray(values) || values.length > 100))
            fail(400, 'invalid_email_domains');
        return (values ?? []).map(value => normalizeEmail('test@' + value).split('@')[1]!);
    };
    const emailList = (values: string[] | undefined) => {
        if (values !== undefined && (!Array.isArray(values) || values.length > 1000))
            fail(400, 'invalid_email_list');
        return (values ?? []).map(normalizeEmail);
    };
    const allowedEmails = emailList(options.allowedEmails), blockedEmails = emailList(options.blockedEmails);
    const allowed = domains(options.allowedEmailDomains), blocked = domains(options.blockedEmailDomains);
    const permittedEmail = (value: string) => {
        const email = normalizeEmail(value), domain = email.split('@')[1]!;
        if (blockedEmails.includes(email) || (allowedEmails.length && !allowedEmails.includes(email)) || blocked.includes(domain) || (allowed.length && !allowed.includes(domain)))
            fail(403, 'registration_unavailable');
        return email;
    };
    const ttl = options.sessionTtlMs ?? 86400000;
    if (!Number.isSafeInteger(ttl) || ttl < 60000 || ttl > 2592000000)
        fail(400, 'invalid_session_ttl');
    const idle = options.sessionIdleMs ?? Math.min(ttl, 1800000);
    if (!Number.isSafeInteger(idle) || idle < 60000 || idle > ttl)
        fail(400, 'invalid_session_idle');
    const key = keys[activeKey]!, now = () => {
        const value = (options.now ?? Date.now)();
        if (!Number.isSafeInteger(value) || value < 0)
            fail(503, 'invalid_clock');
        return value;
    };
    const store = await openAuthStore({ database: options.database, ...(options.approveConfigurationChangeFrom ? { approveConfigurationChangeFrom: options.approveConfigurationChangeFrom } : {}), configurationChangeAt: now(), ...(options.configurationTag !== undefined ? { configurationTag: options.configurationTag } : {}), roles, defaultRole, sessionTtlMs: ttl, sessionIdleMs: idle, securityPolicy, registration: { mode, allowed, blocked, allowedEmails, blockedEmails, allowImpersonation: options.allowImpersonation === true }, activeKey, keyFingerprints: Object.fromEntries(Object.entries(keys).map(([name, value]) => [name, createHmac('sha256', value).update('urlcode-auth-store-v1').digest('hex')])) });
    let closed = false;
    const hookStats: AuthHookStats = { accepted: 0, dropped: 0, failed: 0, timedOut: 0 };
    const hookControllers = new Set<AbortController>();
    const lifecycle = (event: AuthLifecycleEvent) => {
        if (!options.onLifecycle)
            return;
        if (closed || lifecycleActive >= 4) {
            hookStats.dropped++;
            return;
        }
        lifecycleActive++;
        hookStats.accepted++;
        const controller = new AbortController();
        hookControllers.add(controller);
        let timedOut = false;
        const timer = setTimeout(() => { timedOut = true; hookStats.timedOut++; controller.abort(); }, 5000);
        timer.unref();
        void Promise.resolve().then(() => options.onLifecycle!({ ...event }, { signal: controller.signal })).catch(() => {
            if (!timedOut)
                hookStats.failed++;
        }).finally(() => { clearTimeout(timer); hookControllers.delete(controller); lifecycleActive--; });
    };
    const check = () => {
        if (closed)
            fail(503, 'auth_service_closed');
    };
    const profilePolicy = options.registrationPolicy ?? createRegistrationPolicy();
    const validateProfile = (input: RegistrationInput, existing?: RegistrationProfile) => {
        try {
            return profilePolicy.validate(input, { now: now(), ...(existing ? { existing } : {}) });
        }
        catch {
            return fail(400, 'invalid_registration_profile');
        }
    };
    const publicUser = (user: AuthRecord): AuthUser => ({ ...basePublicUser(user), ...(user.profile ? { profile: profilePolicy.publicProfile(user.profile) } : {}) });
    const newPassword = async (value: string) => {
        password(value);
        if (options.checkPassword) {
            if (passwordChecks >= 4)
                fail(503, 'password_check_busy');
            passwordChecks++;
            const controller = new AbortController();
            let timer: NodeJS.Timeout | undefined;
            const pending = Promise.resolve().then(() => options.checkPassword!(value, { signal: controller.signal }));
            void pending.finally(() => { passwordChecks--; }).catch(() => { });
            try {
                await Promise.race([pending, new Promise<never>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new AuthError(503, 'password_check_unavailable')); }, 5000); })]);
            }
            catch (error) {
                if (error instanceof AuthError && error.code === 'password_check_unavailable')
                    throw error;
                fail(400, 'password_not_allowed');
            }
            finally {
                if (timer)
                    clearTimeout(timer);
            }
        }
        return hashPassword(value);
    };
    const perms = (names: string[]) => [...new Set(names.flatMap(name => roles[name] || []))];
    const restrictions = (user: AuthRecord): AuthRestriction[] => [...(securityPolicy.requireEmailVerification && !user.emailVerified ? ['verify-email' as const] : []), ...(securityPolicy.requireMfa && !user.totpSecret ? ['enroll-mfa' as const] : [])];
    const principal = (user: AuthRecord, session: SessionRecord): AuthPrincipal => { const pending = restrictions(user); return { id: user.id, email: user.email, emailVerified: user.emailVerified, roles: pending.length ? [] : [...user.roles], permissions: pending.length ? [] : session.impersonatorId ? perms(user.roles).filter(p => p !== '*' && !p.startsWith('auth.') && !p.startsWith('admin.')) : perms(user.roles), ...(pending.length ? { restrictions: pending } : {}), ...(session.impersonatorId ? { impersonatorId: session.impersonatorId } : {}), sessionId: session.id, authenticatedAt: session.authenticatedAt }; };
    const sessionFor = (accountId: string, device?: AuthDevice) => {
        if (device && (!validToken(device.id) || device.label !== undefined && (typeof device.label !== 'string' || device.label.length > 160 || /[\x00-\x1f\x7f]/.test(device.label))))
            fail(400, 'invalid_device');
        const raw = token(), created = now();
        return { raw, value: { id: randomUUID(), hash: digest(raw), accountId, created, authenticatedAt: created, expires: created + ttl, ...(device ? { deviceHash: digest(device.id), deviceLabel: device.label ?? 'Browser' } : {}) } };
    };
    const seal = (value: string, context: string) => { const nonce = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, nonce); cipher.setAAD(Buffer.from(context)); const bytes = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]); return activeKey + '.' + Buffer.concat([nonce, cipher.getAuthTag(), bytes]).toString('base64url'); };
    const unseal = (value: string, context: string) => {
        try {
            const parts = value.split('.'), keyId = parts.length === 2 ? parts[0]! : 'legacy', secretKey = keys[keyId];
            if (!secretKey)
                throw new Error();
            const bytes = Buffer.from(parts.at(-1)!, 'base64url');
            if (bytes.length < 29)
                throw new Error();
            const cipher = createDecipheriv('aes-256-gcm', secretKey, bytes.subarray(0, 12));
            cipher.setAuthTag(bytes.subarray(12, 28));
            cipher.setAAD(Buffer.from(context));
            return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8');
        }
        catch {
            return fail(503, 'auth_secret_unavailable');
        }
    };
    const lookupSession = async (raw: string, fresh = false, enrollment = false) => {
        check();
        if (!validToken(raw))
            return fail(401, 'invalid_credentials');
        const value = await store.call<{
            user: AuthRecord;
            session: SessionRecord;
        } | null>('authenticate', { hash: digest(raw), now: now() });
        if (!value)
            return fail(401, 'invalid_credentials');
        if (value.session.impersonatorId && fresh)
            fail(403, 'impersonation_restricted');
        if (fresh && now() - value.session.authenticatedAt > 300000)
            fail(401, 'fresh_authentication_required');
        if (fresh) {
            const pending = restrictions(value.user);
            if (pending.length && (!enrollment || pending.includes('verify-email')))
                fail(403, 'enrollment_required');
        }
        return value;
    };
    const attempt = async (value: string) => { const attemptKey = createHash('sha256').update('urlcode-auth-attempt:' + value).digest('hex'); await store.call('attempt', { key: attemptKey, now: now() }); return attemptKey; };
    const counter = (secret: string, code: string, accountId: string) => {
        if (typeof code !== 'string' || !/^\d{6}$/.test(code))
            return fail(401, 'invalid_credentials');
        const totp = new TOTP({ secret: unseal(secret, 'totp:' + accountId), algorithm: 'SHA1', digits: 6, period: 30 });
        const timestamp = now(), delta = totp.validate({ token: code, window: 1, timestamp });
        if (delta === null)
            return fail(401, 'invalid_credentials');
        return Math.floor(timestamp / 30000) + delta;
    };
    const factor = (user: AuthRecord, input: {
        totp?: string;
        recoveryCode?: string;
    }): Record<string, unknown> => {
        if (!user.totpSecret)
            return {};
        if (input.recoveryCode) {
            if (!/^[A-Za-z0-9_-]{22}$/.test(input.recoveryCode))
                fail(401, 'invalid_credentials');
            return { recoveryHash: digest(input.recoveryCode) };
        }
        return { counter: counter(user.totpSecret, input.totp ?? '', user.id) };
    };
    const create = async (input: {
        email: string;
        password: string;
        invitationToken?: string;
        device?: AuthDevice;
        profile?: RegistrationInput;
    }, bootstrap = false) => {
        check();
        if (!bootstrap && (mode === 'off' || mode === 'waitlist' || mode === 'invite-only' && !validToken(input.invitationToken)))
            fail(403, 'registration_unavailable');
        const email = permittedEmail(input.email), passwordHash = await newPassword(input.password), created = now(), accountId = randomUUID();
        let assigned = [defaultRole];
        if (bootstrap) {
            const admin = Object.keys(roles).find(name => roles[name]!.includes('*'));
            if (!admin)
                fail(400, 'administrator_role_required');
            assigned = [admin!];
        }
        const user: AuthRecord = { id: accountId, email, emailVerified: false, status: 'active', roles: assigned, created, passwordHash, version: 1, totpCounter: -1, ...(!bootstrap && (options.registrationPolicy || input.profile) ? { profile: validateProfile(input.profile ?? {}) } : {}) }, session = sessionFor(accountId, input.device);
        const stored = await store.call<AuthRecord>('create', { user, session: session.value, bootstrap, ...(!bootstrap && mode === 'invite-only' ? { invitationHash: digest(input.invitationToken!) } : {}), now: now() });
        lifecycle({ type: 'sign-up', accountId: stored.id });
        return { user: publicUser(stored), token: session.raw, principal: principal(stored, session.value), ...(stored.newDevice ? { newDevice: true } : {}) };
    };
    const login = async (input: AuthCredentials, oldToken?: string) => {
        check();
        const email = normalizeEmail(input.email), attemptKey = await attempt('login:' + email), user = await store.call<AuthRecord | null>('email', { email });
        const verified = await verifyPassword(input.password, user?.passwordHash);
        if (!verified || !user || user.status !== 'active')
            return fail(401, 'invalid_credentials');
        const fact = factor(user, input), session = sessionFor(user.id, input.device), upgradedHash = !user.passwordHash.startsWith('scrypt-v1$') ? await hashPassword(input.password, false) : undefined;
        const stored = await store.call<AuthRecord>('login', { accountId: user.id, version: user.version, passwordHash: user.passwordHash, ...(upgradedHash ? { upgradedHash } : {}), ...fact, session: session.value, attemptKey, ...(oldToken ? { oldHash: digest(oldToken) } : {}), now: now() });
        return { user: publicUser(stored), token: session.raw, principal: principal(stored, session.value), ...(stored.newDevice ? { newDevice: true } : {}) };
    };
    const pagination = (options: {
        limit?: number;
        after?: string;
    } = {}) => {
        const limit = options.limit ?? 50;
        if (!Number.isInteger(limit) || limit < 1 || limit > 100 || typeof (options.after ?? '') !== 'string' || (options.after?.length ?? 0) > 256)
            fail(400, 'invalid_page');
        return { limit, after: options.after ?? '' };
    };
    const reason = (value: string | undefined) => {
        if (value !== undefined && (typeof value !== 'string' || value.length > 256 || /[\x00-\x1f\x7f]/.test(value)))
            fail(400, 'invalid_reason');
        return value ?? '';
    };
    const external = (provider: string, subject: string) => {
        if (!/^[a-z][a-z0-9_-]{0,63}$/.test(provider) || typeof subject !== 'string' || !subject || subject.length > 512 || /[\x00-\x1f\x7f]/.test(subject))
            fail(400, 'invalid_external_identity');
    };
    const validateProof = (value: AuthProof, method: string): AuthProof => {
        if (!value || value.kind !== method || !Number.isSafeInteger(value.version) || value.version < 1)
            fail(400, 'invalid_auth_proof');
        if (value.kind === 'oidc')
            external(value.provider, value.subject);
        else if (value.kind === 'passkey') {
            if (typeof value.credentialId !== 'string' || !value.credentialId || value.credentialId.length > 2048 || !(/^[a-f0-9]{64}$/.test(value.publicKeyHash)) || ![value.expectedCounter, value.newCounter].every(counter => Number.isSafeInteger(counter) && counter >= 0 && counter <= 4294967295) || !(value.expectedCounter === 0 && value.newCounter === 0) && value.newCounter <= value.expectedCounter)
                fail(400, 'invalid_auth_proof');
        }
        else
            fail(400, 'invalid_auth_proof');
        return structuredClone(value);
    };
    const service: AuthService = {
        register: input => create(input), bootstrapAdmin: input => create(input, true), login,
        async stepUp(input) {
            const value = await lookupSession(input.token);
            if (value.session.impersonatorId)
                fail(403, 'impersonation_restricted');
            return login({ email: value.user.email, password: input.password, ...(input.totp ? { totp: input.totp } : {}), ...(input.recoveryCode ? { recoveryCode: input.recoveryCode } : {}) }, input.token);
        },
        async authenticate(raw) {
            check();
            if (!validToken(raw))
                return null;
            const value = await store.call<{
                user: AuthRecord;
                session: SessionRecord;
            } | null>('authenticate', { hash: digest(raw), now: now() });
            return value ? principal(value.user, value.session) : null;
        },
        async logout(raw) {
            check();
            if (validToken(raw))
                await store.call('logout', { hash: digest(raw), now: now() });
        },
        async revokeSessions(accountId) { check(); await store.call('revoke', { accountId: id(accountId), now: now() }); },
        async listUsers(options) {
            check();
            const page = pagination(options);
            if (options?.query !== undefined && (typeof options.query !== 'string' || options.query.length > 254) || options?.status !== undefined && !['active', 'locked', 'pending-delete'].includes(options.status) || options?.role !== undefined && !Object.hasOwn(roles, options.role))
                fail(400, 'invalid_filter');
            const rows = await store.call<AuthRecord[]>('users', { ...page, query: options?.query ?? '', status: options?.status ?? '', role: options?.role ?? '' });
            return { users: rows.map(publicUser), ...(rows.length === page.limit ? { next: rows.at(-1)!.id } : {}) };
        },
        async getUser(accountId) { check(); const row = await store.call<AuthRecord | null>('account', { id: id(accountId) }); return row ? publicUser(row) : null; }, getRoles: () => structuredClone(roles),
        async listDevices(accountId) {
            check();
            return store.call<{
                id: string;
                label: string;
                lastSeen: number;
            }[]>('devices', { accountId: id(accountId) });
        },
        async listSessions(accountId) { check(); return store.call<AuthSession[]>('sessions', { accountId: id(accountId), now: now() }); },
        async listAudit(options) {
            check();
            const page = pagination(options);
            if (page.after && !/^\d{1,16}$/.test(page.after))
                fail(400, 'invalid_page');
            for (const value of [options?.actor, options?.subject, options?.action])
                if (value !== undefined && (typeof value !== 'string' || value.length > 256 || /[\x00-\x1f]/.test(value)))
                    fail(400, 'invalid_filter');
            for (const value of [options?.from, options?.to])
                if (value !== undefined && (!Number.isSafeInteger(value) || value < 0))
                    fail(400, 'invalid_filter');
            if (options?.from !== undefined && options?.to !== undefined && options.from > options.to)
                fail(400, 'invalid_filter');
            const rows = await store.call<AuthAuditEvent[]>('audit', { ...page, actor: options?.actor ?? '', subject: options?.subject ?? '', action: options?.action ?? '', from: options?.from ?? 0, to: options?.to ?? Number.MAX_SAFE_INTEGER });
            return { events: rows, ...(rows.length === page.limit ? { next: String(rows.at(-1)!.id) } : {}) };
        },
        async issueToken(input) {
            check();
            if (!['verify-email', 'reset-password'].includes(input.purpose))
                fail(400, 'invalid_token_purpose');
            const email = normalizeEmail(input.email);
            await attempt('token:' + email);
            const raw = token(), issued = await store.call<boolean>('issueToken', { email, purpose: input.purpose, hash: digest(raw), now: now() });
            return { token: issued ? raw : null };
        },
        async consumeVerification(raw) {
            check();
            if (!validToken(raw))
                fail(400, 'invalid_token');
            return publicUser(await store.call<AuthRecord>('consumeToken', { hash: digest(raw), purpose: 'verify-email', now: now() }));
        },
        async resetPassword(input) {
            check();
            if (!validToken(input.token))
                fail(400, 'invalid_token');
            const passwordHash = await newPassword(input.password);
            return publicUser(await store.call<AuthRecord>('consumeToken', { hash: digest(input.token), purpose: 'reset-password', passwordHash, now: now() }));
        },
        async beginTotp(raw) { const { user } = await lookupSession(raw, true, true); await attempt('totp:' + user.id); const secret = new Secret({ size: 20 }), totp = new TOTP({ issuer: 'URLCode', label: user.email, secret }); await store.call('totpBegin', { hash: digest(raw), secret: seal(secret.base32, 'totp:' + user.id), now: now() }); return { secret: secret.base32, otpauthUrl: totp.toString() }; },
        async confirmTotp(input) {
            const { user } = await lookupSession(input.token, true, true);
            await attempt('totp:' + user.id);
            if (!user.totpPending)
                fail(400, 'invalid_totp_setup');
            const step = counter(user.totpPending!, input.code, user.id), recoveryCodes = Array.from({ length: 10 }, () => randomBytes(16).toString('base64url'));
            await store.call('totpConfirm', { hash: digest(input.token), version: user.version, counter: step, recoveryHashes: recoveryCodes.map(digest), now: now() });
            return { recoveryCodes };
        },
        async disableTotp(input) {
            const { user } = await lookupSession(input.token, true);
            await attempt('totp:' + user.id);
            if (user.passwordHash && !await verifyPassword(input.password, user.passwordHash) || !user.totpSecret)
                fail(401, 'invalid_credentials');
            const step = counter(user.totpSecret!, input.code, user.id);
            await store.call('totpDisable', { hash: digest(input.token), version: user.version, counter: step, now: now() });
        },
        async adminSetRoles(input) {
            check();
            if (!validToken(input.actorToken) || !Array.isArray(input.roles) || !input.roles.length || input.roles.length > 32 || input.roles.some(name => !Object.hasOwn(roles, name)))
                fail(400, 'invalid_roles');
            return publicUser(await store.call<AuthRecord>('admin', { hash: digest(input.actorToken), accountId: id(input.accountId), roles: [...new Set(input.roles)], reason: reason(input.reason), now: now() }));
        },
        async adminSetStatus(input) {
            check();
            if (!validToken(input.actorToken) || !['active', 'locked'].includes(input.status))
                fail(400, 'invalid_account_status');
            return publicUser(await store.call<AuthRecord>('admin', { hash: digest(input.actorToken), accountId: id(input.accountId), status: input.status, reason: reason(input.reason), now: now() }));
        },
        async adminRevokeSessions(input) {
            check();
            if (!validToken(input.actorToken))
                fail(401, 'invalid_credentials');
            await store.call('adminRevoke', { hash: digest(input.actorToken), accountId: id(input.accountId), reason: reason(input.reason), now: now() });
        },
        async putFlow(input) {
            check();
            id(input.id);
            id(input.kind);
            const data = JSON.stringify(input.data);
            if (typeof data !== 'string' || Buffer.byteLength(data) > 16384 || !Number.isSafeInteger(input.expires) || input.expires <= now() || input.expires > now() + 600000)
                fail(400, 'invalid_auth_flow');
            await store.call('putFlow', { id: input.id, kind: input.kind, data: seal(data, 'flow:' + input.id + ':' + input.kind), expires: input.expires, now: now() });
        },
        async consumeFlow(flowId, kind) { check(); id(flowId); id(kind); const value = await store.call<string | null>('consumeFlow', { id: flowId, kind, now: now() }); return value === null ? null : JSON.parse(unseal(value, 'flow:' + flowId + ':' + kind)) as unknown; },
        async findExternal(provider, subject) { check(); external(provider, subject); const row = await store.call<AuthRecord | null>('external', { provider, subject }); return row ? publicUser(row) : null; },
        async linkExternal(input) {
            check();
            external(input.provider, input.subject);
            if (!validToken(input.actorToken))
                fail(401, 'invalid_credentials');
            await store.call('linkExternal', { hash: digest(input.actorToken), provider: input.provider, subject: input.subject, now: now() });
        },
        async createExternalAccount(input) {
            check();
            if (mode !== 'open')
                fail(403, 'registration_unavailable');
            external(input.provider, input.subject);
            if (input.emailVerified !== true)
                fail(400, 'verified_provider_email_required');
            const user: AuthRecord = { id: randomUUID(), email: permittedEmail(input.email), emailVerified: true, status: 'active', roles: [defaultRole], created: now(), passwordHash: '', version: 1, totpCounter: -1, ...(options.registrationPolicy || input.profile ? { profile: validateProfile(input.profile ?? {}) } : {}) };
            const saved = await store.call<AuthRecord>('createExternal', { user, provider: input.provider, subject: input.subject, now: now() });
            lifecycle({ type: 'sign-up', accountId: saved.id });
            return publicUser(saved);
        },
        async getExternalProof(provider, subject) { check(); external(provider, subject); const user = await store.call<AuthRecord | null>('external', { provider, subject }); return user ? { user: publicUser(user), proof: { kind: 'oidc', version: user.version, provider, subject } } : null; },
        async issueSession(accountId, input) {
            check();
            const proof = validateProof(input.proof, input.method);
            if (!['passkey', 'oidc'].includes(input.method))
                fail(400, 'invalid_auth_method');
            const user = await store.call<AuthRecord | null>('account', { id: id(accountId) });
            if (!user || user.status !== 'active')
                fail(401, 'invalid_credentials');
            const attemptKey = await attempt('login:' + user!.email), fact = factor(user!, input), session = sessionFor(accountId, input.device);
            const stored = await store.call<AuthRecord>('login', { accountId, proof, version: user!.version, passwordHash: user!.passwordHash, ...fact, session: session.value, attemptKey, now: now() });
            return { user: publicUser(stored), token: session.raw, principal: principal(stored, session.value), ...(stored.newDevice ? { newDevice: true } : {}) };
        },
        async addPasskey(input) {
            check();
            if (!validToken(input.actorToken) || !input.credential || typeof input.credential.id !== 'string' || input.credential.id.length > 2048 || !input.credential.id || typeof input.credential.publicKey !== 'string' || input.credential.publicKey.length > 8192 || !Number.isSafeInteger(input.credential.counter) || input.credential.counter < 0 || (input.credential.transports && (input.credential.transports.length > 8 || input.credential.transports.some(t => !['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'].includes(t)))))
                fail(400, 'invalid_passkey');
            await store.call('addPasskey', { hash: digest(input.actorToken), credential: input.credential, now: now() });
        },
        async getPasskey(credentialId) {
            check();
            if (typeof credentialId !== 'string' || credentialId.length > 2048)
                fail(400, 'invalid_passkey');
            return store.call<{
                accountId: string;
                credential: Omit<AuthPasskey, 'accountId'>;
                proof: Omit<PasskeyAuthProof, 'newCounter'>;
            } | null>('getPasskey', { id: credentialId });
        },
        async listPasskeys(accountId) { check(); return store.call<Omit<AuthPasskey, 'accountId'>[]>('listPasskeys', { accountId: id(accountId) }); },
        async advancePasskeyCounter(input) {
            check();
            if (typeof input.id !== 'string' || !input.id || input.id.length > 2048 || !Number.isSafeInteger(input.expectedCounter) || input.expectedCounter < 0 || !Number.isSafeInteger(input.newCounter) || input.newCounter < 0 || !(input.expectedCounter === 0 && input.newCounter === 0) && input.newCounter <= input.expectedCounter)
                fail(400, 'invalid_passkey_counter');
            await store.call('advancePasskey', { ...input, now: now() });
        },
        async changePassword(input) {
            const { user } = await lookupSession(input.token, true);
            await attempt('login:' + user.email);
            if (!await verifyPassword(input.currentPassword, user.passwordHash))
                fail(401, 'invalid_credentials');
            const fact = factor(user, input), passwordHash = await newPassword(input.password);
            await store.call('changePassword', { hash: digest(input.token), version: user.version, passwordHash, ...fact, now: now() });
        },
        async exportAccount(raw) {
            const { user } = await lookupSession(raw, true);
            return { user: publicUser(user), sessions: await service.listSessions(user.id), passkeys: (await service.listPasskeys(user.id)).map(({ id, transports }) => ({ id, ...(transports ? { transports } : {}) })), identities: await store.call<{
                    provider: string;
                    subject: string;
                }[]>('identities', { accountId: user.id }) };
        },
        async deleteAccount(input) {
            const { user } = await lookupSession(input.token, true);
            await attempt('login:' + user.email);
            if (user.passwordHash && !await verifyPassword(input.password ?? '', user.passwordHash))
                fail(401, 'invalid_credentials');
            const cancelToken = token();
            const deleted = await store.call<{
                deleteAfter: number;
            }>('deleteAccount', { hash: digest(input.token), cancelHash: digest(cancelToken), version: user.version, ...factor(user, input), now: now() });
            return { cancelToken, deleteAfter: deleted.deleteAfter };
        },
        async cancelDeletion(raw) {
            check();
            if (!validToken(raw))
                fail(400, 'invalid_token');
            await store.call('cancelDeletion', { hash: digest(raw), now: now() });
        },
        async purgeDeleted(options = {}) {
            check();
            const limit = options.limit ?? 100;
            if (!Number.isInteger(limit) || limit < 1 || limit > 100)
                fail(400, 'invalid_page');
            const result = await store.call<{
                purged: number;
                deleted: string[];
            }>('purgeDeleted', { limit, now: now() });
            for (const accountId of result.deleted)
                lifecycle({ type: 'delete', accountId });
            return { purged: result.purged };
        },
        async issueEmailCode(input) { check(); const email = normalizeEmail(input.email); await attempt('token:' + email); const flowId = token(), code = String(randomInt(1000000)).padStart(6, '0'); const issued = await store.call<boolean>('issueEmailCode', { email, hash: digest(flowId), codeHash: digest(flowId + ':' + code), now: now() }); return { flowId, code: issued ? code : null }; },
        async consumeEmailCode(input) {
            check();
            if (!validToken(input.flowId) || typeof input.code !== 'string' || !/^\d{6}$/.test(input.code))
                fail(400, 'invalid_code');
            const user = await store.call<AuthRecord | null>('checkEmailCode', { hash: digest(input.flowId), codeHash: digest(input.flowId + ':' + input.code), now: now() });
            if (!user)
                fail(400, 'invalid_code');
            const session = sessionFor(user!.id, input.device);
            const stored = await store.call<AuthRecord>('codeLogin', { hash: digest(input.flowId), codeHash: digest(input.flowId + ':' + input.code), version: user!.version, ...factor(user!, input), session: session.value, now: now() });
            return { user: publicUser(stored), token: session.raw, principal: principal(stored, session.value), ...(stored.newDevice ? { newDevice: true } : {}) };
        },
        async createCase(input) {
            check();
            const why = reason(input.reason);
            if (!why.trim() || !validToken(input.actorToken) || !['reset-factors', 'lock', 'unlock', 'roles'].includes(input.action) || input.action === 'roles' && (!Array.isArray(input.roles) || !input.roles.length || input.roles.length > 32 || input.roles.some(name => !Object.hasOwn(roles, name))))
                fail(400, 'invalid_case');
            return store.call<AuthCase>('createCase', { hash: digest(input.actorToken), accountId: id(input.accountId), action: input.action, ...(input.roles ? { roles: input.roles } : {}), reason: why, id: randomUUID(), now: now() });
        },
        async listCases(options) { check(); const page = pagination(options), cases = await store.call<AuthCase[]>('cases', page); return { cases, ...(cases.length === page.limit ? { next: cases.at(-1)!.id } : {}) }; },
        async getCase(caseId) { check(); return store.call<AuthCase | null>('case', { id: id(caseId) }); },
        async approveCase(input) {
            check();
            const why = reason(input.reason);
            if (!why.trim() || !validToken(input.actorToken))
                fail(400, 'invalid_case');
            return store.call<AuthCase>('approveCase', { hash: digest(input.actorToken), id: id(input.caseId), reason: why, now: now() });
        },
        async createImpersonation(input) {
            check();
            const why = reason(input.reason);
            if (options.allowImpersonation !== true || !why.trim() || !validToken(input.actorToken))
                fail(403, 'impersonation_denied');
            const session = sessionFor(id(input.accountId));
            session.value.expires = now() + 600000;
            session.value.authenticatedAt = 0;
            const result = await store.call<{
                user: AuthRecord;
                session: SessionRecord;
            }>('impersonate', { hash: digest(input.actorToken), accountId: input.accountId, session: session.value, reason: why, now: now() });
            return { user: publicUser(result.user), token: session.raw, principal: principal(result.user, result.session) };
        },
        async adminBulk(input) {
            check();
            const why = reason(input.reason);
            if (!validToken(input.actorToken) || !why.trim() || !['lock', 'unlock', 'revoke-sessions'].includes(input.action) || !Array.isArray(input.accountIds) || input.accountIds.length < 1 || input.accountIds.length > 50 || new Set(input.accountIds).size !== input.accountIds.length)
                fail(400, 'invalid_bulk_action');
            const accountIds = input.accountIds.map(id);
            return store.call<{
                affected: number;
            }>('adminBulk', { hash: digest(input.actorToken), accountIds, action: input.action, reason: why, now: now() });
        },
        async dashboard() {
            check();
            return store.call<{
                users: number;
                active: number;
                locked: number;
                pendingDeletion: number;
                sessions: number;
                waitlist: number;
                daily: AuthDailyMetric[];
            }>('dashboard', { now: now() });
        },
        async listAllSessions(options) {
            check();
            const page = pagination(options), sessions = await store.call<(AuthSession & {
                accountId: string;
                email: string;
            })[]>('allSessions', { ...page, now: now() });
            return { sessions, ...(sessions.length === page.limit ? { next: sessions.at(-1)!.id } : {}) };
        },
        async importUsers(users) {
            check();
            if (!Array.isArray(users) || !users.length || users.length > 100)
                fail(400, 'invalid_import');
            const rows = users.map(input => {
                if (!input || !validPasswordHash(input.passwordHash) || input.emailVerified !== undefined && typeof input.emailVerified !== 'boolean')
                    fail(400, 'invalid_import');
                return { id: randomUUID(), email: permittedEmail(input.email), emailVerified: input.emailVerified ?? false, status: 'active', roles: [defaultRole], created: now(), passwordHash: input.passwordHash, version: 1, totpCounter: -1 };
            });
            const result = await store.call<{
                imported: number;
            }>('importUsers', { users: rows, now: now() });
            for (const user of rows)
                lifecycle({ type: 'sign-up', accountId: user.id });
            return result;
        },
        async getProfile(raw) { const { user } = await lookupSession(raw, true); return profilePolicy.publicProfile(user.profile ?? { metadata: {} }); },
        async updateProfile(input) { const { user } = await lookupSession(input.token, true), profile = validateProfile(input.profile, user.profile); await store.call('updateProfile', { hash: digest(input.token), profile, version: user.version, now: now() }); return profilePolicy.publicProfile(profile); },
        async getConfigurationRevision() { check(); return store.call<string>('configurationRevision'); },
        getSecurityPolicy: () => ({ ...securityPolicy }),
        getHookStats: () => ({ ...hookStats }),
        getRegistrationSchema: () => profilePolicy.publicSchema(),
        getRegistrationMode: () => mode,
        async requestRegistration(input) {
            check();
            if (mode !== 'waitlist')
                fail(403, 'registration_unavailable');
            const email = permittedEmail(input.email), passwordHash = await newPassword(input.password);
            return store.call<{
                id: string;
            }>('requestRegistration', { id: randomUUID(), email, passwordHash, ...(options.registrationPolicy || input.profile ? { profile: validateProfile(input.profile ?? {}) } : {}), now: now() });
        },
        async listRegistrationRequests(options) {
            check();
            const page = pagination(options), requests = await store.call<{
                id: string;
                email: string;
                created: number;
            }[]>('registrationRequests', page);
            return { requests, ...(requests.length === page.limit ? { next: requests.at(-1)!.id } : {}) };
        },
        async approveRegistration(input) {
            check();
            if (mode !== 'waitlist' || !validToken(input.actorToken))
                fail(403, 'registration_unavailable');
            const user = await store.call<AuthRecord>('approveRegistration', { hash: digest(input.actorToken), requestId: id(input.requestId), reason: reason(input.reason), now: now() });
            lifecycle({ type: 'sign-up', accountId: user.id });
            return publicUser(user);
        },
        async invite(input) {
            check();
            if (mode !== 'invite-only' || !validToken(input.actorToken))
                fail(403, 'registration_unavailable');
            const raw = token();
            await store.call('invite', { actorHash: digest(input.actorToken), email: permittedEmail(input.email), hash: digest(raw), now: now() });
            return { token: raw };
        },
        async completeStepUp(input) {
            const proof = validateProof(input.proof, input.method), { user, session: previous } = await lookupSession(input.token);
            if (input.method !== 'passkey' || user.id !== input.accountId)
                fail(403, 'step_up_denied');
            if (previous.impersonatorId)
                fail(403, 'impersonation_restricted');
            const attemptKey = await attempt('login:' + user.email), fact = factor(user, input), session = sessionFor(user.id);
            const stored = await store.call<AuthRecord>('login', { accountId: user.id, proof, version: user.version, passwordHash: user.passwordHash, ...fact, session: session.value, oldHash: digest(input.token), attemptKey, now: now() });
            return { user: publicUser(stored), token: session.raw, principal: principal(stored, session.value) };
        },
        async removePasskey(input) {
            check();
            if (!validToken(input.token) || typeof input.credentialId !== 'string' || !input.credentialId || input.credentialId.length > 2048)
                fail(400, 'invalid_passkey');
            await store.call('removeMethod', { hash: digest(input.token), credentialId: input.credentialId, now: now() });
        },
        async unlinkExternal(input) {
            check();
            external(input.provider, input.subject);
            if (!validToken(input.token))
                fail(401, 'invalid_credentials');
            await store.call('removeMethod', { hash: digest(input.token), provider: input.provider, subject: input.subject, now: now() });
        },
        async closeCase(input) {
            check();
            const why = reason(input.reason);
            if (!why.trim() || !validToken(input.actorToken))
                fail(400, 'invalid_case');
            return store.call<AuthCase>('caseEdit', { hash: digest(input.actorToken), id: id(input.caseId), reason: why, close: true, now: now() });
        },
        async addCaseNote(input) {
            check();
            const note = reason(input.note);
            if (!note.trim() || !validToken(input.actorToken))
                fail(400, 'invalid_case');
            return store.call<AuthCase>('caseEdit', { hash: digest(input.actorToken), id: id(input.caseId), reason: note, now: now() });
        },
        async cleanup(options = {}) {
            check();
            const limit = options.limit ?? 100;
            if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
                fail(400, 'invalid_page');
            return store.call<{
                removed: number;
            }>('cleanup', { limit, now: now() });
        },
        async requestEmailChange(input) {
            const { user } = await lookupSession(input.token, true);
            await attempt('login:' + user.email);
            if (user.passwordHash && !await verifyPassword(input.password ?? '', user.passwordHash))
                fail(401, 'invalid_credentials');
            const email = permittedEmail(input.email), verificationToken = token(), cancelToken = token(), activateAfter = now() + 86400000;
            await store.call('requestEmailChange', { hash: digest(input.token), version: user.version, email, verificationHash: digest(verificationToken), cancelHash: digest(cancelToken), ...factor(user, input), now: now() });
            return { oldEmail: user.email, newEmail: email, verificationToken, cancelToken, activateAfter };
        },
        async confirmEmailChange(raw) {
            check();
            if (!validToken(raw))
                fail(400, 'invalid_token');
            return publicUser(await store.call<AuthRecord>('confirmEmailChange', { hash: digest(raw), now: now() }));
        },
        async cancelEmailChange(raw) {
            check();
            if (!validToken(raw))
                fail(400, 'invalid_token');
            await store.call('cancelEmailChange', { hash: digest(raw), now: now() });
        },
        async adminCreateUser(input) {
            check();
            const why = reason(input.reason);
            if (!why.trim() || !validToken(input.actorToken))
                fail(400, 'invalid_administration');
            const setupToken = token(), user: AuthRecord = { id: randomUUID(), email: permittedEmail(input.email), emailVerified: false, status: 'active', roles: [defaultRole], created: now(), passwordHash: '', version: 1, totpCounter: -1 };
            const saved = await store.call<AuthRecord>('adminCreateUser', { hash: digest(input.actorToken), user, setupHash: digest(setupToken), reason: why, now: now() });
            lifecycle({ type: 'sign-up', accountId: saved.id });
            return { user: publicUser(saved), setupToken };
        },
        async revokeSession(input) {
            check();
            if (!validToken(input.token))
                fail(401, 'invalid_credentials');
            await store.call('revokeSession', { hash: digest(input.token), sessionId: id(input.sessionId), now: now() });
        },
        async adminRevokeSession(input) {
            check();
            const why = reason(input.reason);
            if (!why.trim() || !validToken(input.actorToken))
                fail(400, 'invalid_administration');
            await store.call('revokeSession', { hash: digest(input.actorToken), sessionId: id(input.sessionId), admin: true, reason: why, now: now() });
        },
        async adminExport(input) {
            check();
            const why = reason(input.reason);
            if (!why.trim() || !validToken(input.actorToken))
                fail(400, 'invalid_administration');
            const result = await store.call<{
                user: AuthRecord;
                sessions: AuthSession[];
                identities: {
                    provider: string;
                    subject: string;
                }[];
            }>('adminExport', { hash: digest(input.actorToken), accountId: id(input.accountId), reason: why, now: now() });
            return { ...result, user: publicUser(result.user) };
        },
        async rotateEncryptionKey() {
            check();
            const rows = await store.call<{
                type: string;
                id: string;
                field: string;
                value: string;
                context: string;
            }[]>('rotationRows', { activeKey });
            const replacements = rows.map(row => ({ ...row, replacement: seal(unseal(row.value, row.context), row.context) }));
            return store.call<{
                changed: number;
                remaining: number;
            }>('rotationApply', { activeKey, replacements, now: now() });
        },
        async close() {
            if (closed)
                return;
            closed = true;
            for (const controller of hookControllers)
                controller.abort();
            await store.close();
            for (const value of Object.values(keys))
                value.fill(0);
        },
    };
    const withFailureMetric = async <T>(method: string, run: () => Promise<T>): Promise<T> => {
        try {
            return await run();
        }
        catch (error) {
            if (error instanceof AuthError && [400, 401, 429].includes(error.status)) {
                try {
                    await store.call('signInFailure', { method, now: now() });
                }
                catch { /* Observability cannot change the authentication result. */ }
            }
            throw error;
        }
    };
    const passwordLogin = service.login, externalLogin = service.issueSession, codeLogin = service.consumeEmailCode;
    service.login = input => withFailureMetric('password', () => passwordLogin(input));
    service.issueSession = (accountId, input) => withFailureMetric(input.method === 'passkey' ? 'passkey' : 'oidc', () => externalLogin(accountId, input));
    service.consumeEmailCode = input => withFailureMetric('email-code', () => codeLogin(input));
    return service;
}
