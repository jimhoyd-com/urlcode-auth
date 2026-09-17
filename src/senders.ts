import { SESv2Client, SendEmailCommand } from '@aws-sdk/client-sesv2';
import type { SESv2ClientConfig } from '@aws-sdk/client-sesv2';
import { randomUUID } from 'node:crypto';
import { open, realpath, stat, readdir } from 'node:fs/promises';
import { join, relative, isAbsolute } from 'node:path';
import { normalizeEmail } from './auth-core.ts';
export interface TokenMessage {
    email: string;
    token: string;
    purpose: 'verify-email' | 'reset-password' | 'cancel-deletion' | 'invitation' | 'verify-email-change' | 'cancel-email-change';
    signal: AbortSignal;
}
export interface EmailCodeMessage {
    email: string;
    flowId: string;
    code: string;
    signal: AbortSignal;
}
export type TokenSender = (message: TokenMessage) => Promise<void>;
export interface SecurityNotice {
    email: string;
    event: 'new-device' | 'password-changed' | 'email-changed';
    signal: AbortSignal;
}
/** A callable sendToken adapter; notify carries no credential or arbitrary markup. */
export interface EmailSender extends TokenSender {
    sendEmailCode(message: EmailCodeMessage): Promise<void>;
    notify(message: SecurityNotice): Promise<void>;
    close(): void;
}
interface Delivery {
    email: string;
    subject: string;
    text: string;
}
interface SenderLocation {
    origin: string;
    authMount: string;
}
const events = { 'new-device': 'A new device signed in to your account.', 'password-changed': 'Your account password changed.', 'email-changed': 'Your account email address changed.' } as const;
function location(options: SenderLocation, development = false): {
    origin: string;
    mount: string;
} {
    const origin = new URL(options.origin);
    if (origin.origin !== options.origin || origin.username || origin.password || !(origin.protocol === 'https:' || development && origin.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(origin.hostname)))
        throw new Error('Sender requires a canonical HTTPS origin');
    if (!/^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(options.authMount) || options.authMount.length > 256)
        throw new Error('Sender requires an explicit auth mount');
    return { origin: origin.origin, mount: options.authMount };
}
function sender(where: {
    origin: string;
    mount: string;
}, deliver: (message: Delivery, signal: AbortSignal) => Promise<void>, cleanup = () => { }): EmailSender {
    let closed = false, active = 0;
    async function send(message: Delivery, signal: AbortSignal) {
        if (closed)
            throw new Error('Sender is closed');
        if (active >= 4)
            throw new Error('Sender is busy');
        signal.throwIfAborted();
        active++;
        const controller = new AbortController(), abort = () => controller.abort(), timer = setTimeout(abort, 5000);
        signal.addEventListener('abort', abort, { once: true });
        let rejectAbort: () => void = () => { };
        try {
            await Promise.race([deliver(message, controller.signal), new Promise<never>((_resolve, reject) => {
                    rejectAbort = () => reject(new Error('Email delivery aborted'));
                    controller.signal.addEventListener('abort', rejectAbort, { once: true });
                    if (controller.signal.aborted)
                        rejectAbort();
                })]);
        }
        finally {
            clearTimeout(timer);
            signal.removeEventListener('abort', abort);
            controller.signal.removeEventListener('abort', rejectAbort);
            active--;
        }
    }
    const result: EmailSender = Object.assign(async (message: TokenMessage) => {
        if (!message || !['verify-email', 'reset-password', 'cancel-deletion', 'invitation', 'verify-email-change', 'cancel-email-change'].includes(message.purpose) || typeof message.token !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(message.token))
            throw new Error('Invalid token delivery');
        const change = message.purpose === 'verify-email-change' || message.purpose === 'cancel-email-change';
        const email = normalizeEmail(message.email), verify = message.purpose === 'verify-email', title = change ? (message.purpose === 'verify-email-change' ? 'Verify your new email address' : 'Cancel an email address change') : verify ? 'Verify your email address' : message.purpose === 'cancel-deletion' ? 'Cancel account deletion' : message.purpose === 'invitation' ? 'Create your invited account' : 'Reset your password', url = new URL(where.mount + (change ? '/' + message.purpose : verify ? '/verify' : message.purpose === 'cancel-deletion' ? '/cancel-deletion' : message.purpose === 'invitation' ? '/register' : '/reset'), where.origin);
        url.searchParams.set('token', message.token);
        await send({ email, subject: title, text: `${title} by opening this link:\n\n${url.href}\n\n${message.purpose === 'verify-email-change' ? 'Verification confirms the new address. The change only activates after the 24-hour cooldown.' : message.purpose === 'cancel-email-change' ? 'A change to your account email was requested. Use this cancellation link before completion if this was not you.' : message.purpose === 'cancel-deletion' ? 'Account deletion was requested. If you did not request this, use this link to cancel the deletion before the grace period ends.' : 'If you did not request this, ignore this email.'} Never share this link.` }, message.signal);
    }, { async sendEmailCode(message: EmailCodeMessage) {
            if (!message || typeof message.code !== 'string' || !/^\d{6}$/.test(message.code) || typeof message.flowId !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(message.flowId))
                throw new Error('Invalid email code delivery');
            const url = new URL(where.mount + '/email-code', where.origin);
            url.searchParams.set('flowId', message.flowId);
            await send({ email: normalizeEmail(message.email), subject: 'Your sign-in code', text: `Your sign-in code is: ${message.code}\n\nEnter it at ${url.href}\n\nIf you did not request this, ignore this email. Never share this code.` }, message.signal);
        }, async notify(message: SecurityNotice) {
            if (!message || !Object.hasOwn(events, message.event))
                throw new Error('Invalid security notice');
            await send({ email: normalizeEmail(message.email), subject: 'Account security notification', text: `${events[message.event]}\n\nReview your account at ${where.origin}${where.mount}/account. If this was not you, contact the account operator.` }, message.signal);
        }, close() {
            if (closed)
                return;
            closed = true;
            cleanup();
        } });
    return result;
}
export interface SesSenderOptions extends SenderLocation {
    region: string;
    from: string;
    credentials?: SESv2ClientConfig['credentials'];
    /** Trusted injection for tests; production uses the AWS SDK with bounded retries. */
    transport?: (command: SendEmailCommand, options: {
        abortSignal: AbortSignal;
    }) => Promise<unknown>;
}
export function createSesSender(options: SesSenderOptions): EmailSender {
    const where = location(options), from = normalizeEmail(options.from);
    if (!/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(options.region))
        throw new Error('Invalid SES region');
    const client = options.transport ? undefined : new SESv2Client({ region: options.region, maxAttempts: 2, ...(options.credentials ? { credentials: options.credentials } : {}) });
    return sender(where, async (message, signal) => { await (options.transport ?? ((command, init) => client!.send(command, init)))(new SendEmailCommand({ FromEmailAddress: from, Destination: { ToAddresses: [message.email] }, Content: { Simple: { Subject: { Data: message.subject, Charset: 'UTF-8' }, Body: { Text: { Data: message.text, Charset: 'UTF-8' } } } } }), { abortSignal: signal }); }, () => client?.destroy());
}
export type DevelopmentSenderOptions = SenderLocation & {
    allowDevelopment: true;
    maxMessages?: number;
} & ({
    directory: string;
    projectRoot: string;
    allowConsoleTokens?: never;
    write?: never;
} | {
    allowConsoleTokens: true;
    write?: (message: string) => void;
    directory?: never;
    projectRoot?: never;
});
/** Development only. File output uses exclusive 0600 notices in an existing private directory outside the project. */
export async function createDevelopmentSender(options: DevelopmentSenderOptions): Promise<EmailSender> {
    if (options.allowDevelopment !== true)
        throw new Error('Development delivery requires explicit allowDevelopment');
    const where = location(options, true), maximum = options.maxMessages ?? 100;
    if (!Number.isInteger(maximum) || maximum < 1 || maximum > 1000)
        throw new Error('Invalid development notice limit');
    let directory: string | undefined;
    if (options.directory !== undefined) {
        directory = await realpath(options.directory);
        const project = await realpath(options.projectRoot!);
        const rel = relative(project, directory);
        if (!rel || !isAbsolute(rel) && rel !== '..' && !rel.startsWith('..' + (process.platform === 'win32' ? '\\' : '/')))
            throw new Error('Development notices must be outside the project');
        const info = await stat(directory);
        if (!info.isDirectory() || process.platform !== 'win32' && (info.mode & 0o077) !== 0)
            throw new Error('Development notice directory must be private');
    }
    else if (options.allowConsoleTokens !== true)
        throw new Error('Console tokens require explicit allowConsoleTokens');
    let count = 0;
    return sender(where, async (message, signal) => {
        signal.throwIfAborted();
        if (count >= maximum)
            throw new Error('Development notice limit reached');
        count++;
        const text = JSON.stringify({ development: true, ...message }) + '\n';
        if (Buffer.byteLength(text) > 4096)
            throw new Error('Development notice too large');
        if (directory) {
            if ((await readdir(directory)).length >= maximum)
                throw new Error('Development notice directory limit reached');
            signal.throwIfAborted();
            const file = await open(join(directory, randomUUID() + '.json'), 'wx', 0o600);
            try {
                await file.writeFile(text);
                await file.sync();
            }
            finally {
                await file.close();
            }
        }
        else {
            signal.throwIfAborted();
            (options.write ?? console.log)(text);
        }
    });
}
