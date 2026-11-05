import { fileURLToPath } from 'node:url';
import { test, expect } from 'bun:test';
import { randomUUID, randomBytes, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	ApiError,
	type JsonObject,
	VaultwardenClient,
	VaultService,
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	createSsoAuthorization,
	ssoCredentialsFromCallback,
	loginWithSso,
	setupSsoAccount,
	unlockAccount,
	refreshAccount,
	object,
	text,
	field,
	totp,
} from '@kjanat/vaultwarden';

const server = process.env.VW_TEST_SERVER,
	provider = process.env.VW_TEST_OIDC,
	control = process.env.VW_OIDC_CONTROL,
	mailbox = process.env.VW_TEST_MAILPIT;
const live = server && provider && control ? test : test.skip;
for (const kdf of [{ type: 0, iterations: 600000 }, { type: 1, iterations: 3, memory: 64, parallelism: 2 }] as const) {
	live(`real Vaultwarden: SSO OIDC (${kdf.type === 0 ? 'PBKDF2' : 'Argon2id'})`, async () => {
		for (const address of [server!, provider!]) {
			const url = new URL(address);
			if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
				throw new Error('SSO fixtures require disposable loopback services.');
			}
		}
		const email = `sso-${randomUUID()}@example.com`,
			password = 'Synthetic-SSO-master-password-123!',
			key = randomBytes(64);
		const master = await deriveMasterKey(password, email, kdf),
			hash = await masterPasswordHash(master, password),
			stretched = stretchKey(master),
			wrapped = encrypt(key, stretched);
		master.fill(0);
		stretched.fill(0);
		const directory = await mkdtemp(join(tmpdir(), 'vw-live-sso-'));
		let jitDirectory: string | undefined;
		async function browser(address: string): Promise<string> {
			const start = await fetch(address, { redirect: 'manual' });
			if (![302, 307].includes(start.status)) {
				throw new Error('SSO authorization did not redirect to the fixture provider.');
			}
			const cookies = start.headers.getSetCookie().map(v => v.split(';')[0]).join('; ');
			const location = start.headers.get('location')!;
			if (new URL(location).origin !== provider) throw new Error('Unexpected SSO provider redirect.');
			const signedIn = await fetch(location, { redirect: 'manual' });
			expect(signedIn.status).toBe(302);
			const callback = signedIn.headers.get('location')!;
			if (new URL(callback).origin !== server) throw new Error('Unexpected provider callback.');
			const completed = await fetch(callback, { headers: { Cookie: cookies }, redirect: 'manual' });
			if (![302, 307].includes(completed.status)) throw new Error('Vaultwarden rejected the provider callback.');
			return completed.headers.get('location')!;
		}
		async function run(args: string[], appDataDir = directory) {
			const child = Bun.spawn(['node', fileURLToPath(import.meta.resolve('#main')), ...args], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: appDataDir, VW_PASSWORD: password },
				stdin: 'ignore',
				stdout: 'pipe',
				stderr: 'pipe',
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			return { code, stdout, stderr };
		}
		async function runSsoLogin(appDataDir: string, extraArgs: string[] = []): Promise<string> {
			const child = Bun.spawn([
				'node',
				fileURLToPath(import.meta.resolve('#main')),
				'--pretty',
				'login',
				'--sso',
				'fixture-organization',
				'--nointeraction',
				...extraArgs,
				'--raw',
			], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: appDataDir, VW_PASSWORD: password },
				stdin: 'ignore',
				stdout: 'pipe',
				stderr: 'pipe',
			});
			const ready = Promise.withResolvers<string>();
			let diagnostic = '';
			const stderr = (async () => {
				for await (const chunk of child.stderr) {
					diagnostic += new TextDecoder().decode(chunk);
					const found = diagnostic.match(/(http:\/\/127\.0\.0\.1:\d+\/identity\/connect\/authorize\?[^\r\n]+)\r?\n/);
					if (found) ready.resolve(found[1]!);
				}
			})();
			void child.exited.then(() => ready.reject(new Error('SSO CLI exited before authorization.')));
			const stdout = new Response(child.stdout).text(),
				deadline = setTimeout(() => ready.reject(new Error('SSO CLI authorization did not start.')), 15000);
			try {
				const callback = await browser(await ready.promise);
				expect((await fetch(callback)).status).toBe(200);
				const code = await child.exited;
				await stderr;
				if (code !== 0) throw new Error('Compiled SSO login failed.');
				const session = (await stdout).trim();
				expect(session).not.toBe('');
				expect(diagnostic).not.toContain(password);
				for (let index = 0; index < extraArgs.length; index++) {
					if (extraArgs[index] === '--code') {
						expect(diagnostic).not.toContain(extraArgs[index + 1]);
					}
				}
				return session;
			} finally {
				clearTimeout(deadline);
				child.kill('SIGTERM');
				await child.exited;
				await stderr;
				await stdout;
			}
		}
		try {
			const subject = randomUUID();
			expect(
				(await fetch(`${provider}/__test/identity`, {
					method: 'PUT',
					headers: { Authorization: `Bearer ${control}`, 'Content-Type': 'application/json' },
					body: JSON.stringify({ email, sub: subject }),
				})).status,
			).toBe(200);
			const verification = await fetch(`${server}/identity/accounts/register/send-verification-email`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ email, name: 'SSO fixture' }),
			});
			expect(verification.status).toBe(200);
			const raw = await verification.text();
			let token: unknown;
			try {
				token = JSON.parse(raw);
			} catch {
				token = raw;
			}
			const pair = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			try {
				const registered = await fetch(`${server}/identity/accounts/register/finish`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/json' },
					body: JSON.stringify({
						email,
						name: 'SSO fixture',
						masterPasswordHash: hash,
						key: wrapped,
						keys: { publicKey: pair.publicKey.toString('base64'), encryptedPrivateKey: encrypt(pair.privateKey, key) },
						kdf: kdf.type,
						kdfIterations: kdf.iterations,
						...(kdf.type === 1 ? { kdfMemory: kdf.memory, kdfParallelism: kdf.parallelism } : {}),
						emailVerificationToken: token,
					}),
				});
				expect(registered.status).toBe(200);
			} finally {
				pair.privateKey.fill(0);
			}
			const client = new VaultwardenClient(server!);
			const authorization = await createSsoAuthorization(client, 'http://localhost:8065');
			const credentials = ssoCredentialsFromCallback(authorization, await browser(authorization.url));
			const account = await loginWithSso(client, credentials);
			if (!account.encryptedUserKey) throw new Error('Expected initialized SSO account fixture.');
			expect(account.auth).toBe('sso');
			expect(account.email).toBe(email);
			expect(account.kdf).toEqual(kdf);
			const unwrapped = await unlockAccount(account, password);
			try {
				expect(unwrapped.equals(key)).toBe(true);
			} finally {
				unwrapped.fill(0);
			}
			const renewed = await refreshAccount(client, account);
			expect(renewed.auth).toBe('sso');

			const jitEmail = `jit-${randomUUID()}@example.com`;
			expect(
				(await fetch(`${provider}/__test/identity`, {
					method: 'PUT',
					headers: { Authorization: `Bearer ${control}`, 'Content-Type': 'application/json' },
					body: JSON.stringify({ email: jitEmail, sub: randomUUID() }),
				})).status,
			).toBe(200);
			const jitAuthorization = await createSsoAuthorization(client, 'http://localhost:8065');
			const jitCredentials = ssoCredentialsFromCallback(jitAuthorization, await browser(jitAuthorization.url));
			const jitPending = await loginWithSso(client, jitCredentials);
			expect(jitPending.email).toBe(jitEmail);
			expect(jitPending.encryptedUserKey).toBeUndefined();
			const jitAccount = await setupSsoAccount(client, jitPending, password);
			const jitKey = await unlockAccount(jitAccount, password);
			try {
				expect(jitKey).toHaveLength(64);
			} finally {
				jitKey.fill(0);
			}
			const cliJitEmail = `cli-jit-${randomUUID()}@example.com`;
			expect(
				(await fetch(`${provider}/__test/identity`, {
					method: 'PUT',
					headers: { Authorization: `Bearer ${control}`, 'Content-Type': 'application/json' },
					body: JSON.stringify({ email: cliJitEmail, sub: randomUUID() }),
				})).status,
			).toBe(200);
			jitDirectory = await mkdtemp(join(tmpdir(), 'vw-live-sso-jit-cli-'));
			expect((await run(['config', 'server', server!], jitDirectory)).code).toBe(0);
			const jitSession = await runSsoLogin(jitDirectory);
			expect(JSON.parse((await run(['status', '--session', jitSession], jitDirectory)).stdout).status).toBe('unlocked');
			expect((await run(['logout'], jitDirectory)).code).toBe(0);

			expect(
				(await fetch(`${provider}/__test/identity`, {
					method: 'PUT',
					headers: { Authorization: `Bearer ${control}`, 'Content-Type': 'application/json' },
					body: JSON.stringify({ email, sub: subject }),
				})).status,
			).toBe(200);

			const snapshot = await client.sync(renewed.accessToken),
				vault = new VaultService(client, renewed.accessToken, snapshot, key);
			let itemId: string;
			try {
				itemId = text(
					(await vault.createItem({
						type: 1,
						name: 'SSO compatibility',
						login: { username: 'synthetic', password: '  SSO-owned secret  ' },
					})).id,
				);
			} finally {
				vault.dispose();
			}
			expect((await run(['config', 'server', server!])).code).toBe(0);
			const session = await runSsoLogin(directory);
			expect((await run(['get', 'password', itemId!, '--session', session!])).stdout).toBe('  SSO-owned secret  ');
			expect((await run(['sync', '--force'])).code).toBe(0);
			expect((await run(['sync'])).code).toBe(0);
			const lastSync = await run(['sync', '--last']);
			expect(lastSync.code).toBe(0);
			expect(lastSync.stdout.trim()).toBe(JSON.parse((await run(['status'])).stdout).lastSync);
			expect(JSON.parse((await run(['status', '--session', session!])).stdout).status).toBe('unlocked');
			expect((await run(['logout'])).code).toBe(0);
			const bad = await createSsoAuthorization(client, 'http://localhost:8065');
			const badCredentials = ssoCredentialsFromCallback(bad, await browser(bad.url));
			await expect(loginWithSso(client, { ...badCredentials, codeVerifier: 'x'.repeat(64) })).rejects.toBeInstanceOf(
				ApiError,
			);
			const setup = await client.api(renewed.accessToken, 'POST', '/two-factor/get-authenticator', {
				masterPasswordHash: hash,
			});
			const secret = text(field(object(setup.authenticator ?? setup), 'key'));
			const enrollmentTime = Date.now();
			await client.api(renewed.accessToken, 'PUT', '/two-factor/authenticator', {
				key: secret,
				token: totp(secret, enrollmentTime),
				userVerificationToken: setup.userVerificationToken,
				masterPasswordHash: hash,
			});
			// Enrollment consumes this counter. Wait for a fresh code instead of enrolling
			// with the previous interval, which can expire while the request is in flight.
			const nextInterval = (Math.floor(enrollmentTime / 30000) + 1) * 30000;
			while (Date.now() < nextInterval) await Bun.sleep(Math.max(1, nextInterval - Date.now()));
			const challenged = await createSsoAuthorization(client, 'http://localhost:8065');
			let callbacks = 0;
			const twoFactor = await loginWithSso(
				client,
				ssoCredentialsFromCallback(challenged, await browser(challenged.url)),
				undefined,
				{
					onTwoFactor: async challenge => {
						callbacks++;
						expect(challenge.providers).toContain(0);
						return { provider: 0, token: totp(secret) };
					},
				},
			);
			expect(callbacks).toBe(1);
			expect(twoFactor.email).toBe(email);
			const recovery = await client.api(twoFactor.accessToken, 'POST', '/two-factor/get-recover', {
				masterPasswordHash: hash,
			});
			const recoveryCode = text(field(recovery, 'code'));
			const recoverySession = await runSsoLogin(directory, ['--method', '8', '--code', recoveryCode]);
			expect(JSON.parse((await run(['status', '--session', recoverySession])).stdout).status).toBe('unlocked');
			const methods = await client.api(twoFactor.accessToken, 'GET', '/two-factor');
			expect(field(methods, 'data')).toEqual([]);
			if (mailbox) {
				const mailboxUrl = new URL(mailbox);
				if (mailboxUrl.protocol !== 'http:' || mailboxUrl.hostname !== '127.0.0.1') {
					throw new Error('SSO email tests require a disposable loopback SMTP receiver.');
				}
				const recipient = `sso-secondfactor-${randomUUID()}@example.com`;
				async function messages(): Promise<JsonObject[]> {
					const response = await fetch(`${mailbox}/api/v1/messages`);
					if (!response.ok) throw new Error('SMTP receiver API is unavailable.');
					const data = object(await response.json());
					if (!Array.isArray(data.messages)) throw new Error('SMTP receiver returned an invalid message list.');
					return data.messages.map(object).filter(message =>
						Array.isArray(message.To)
						&& message.To.some(to => object(to).Address === recipient)
					);
				}
				const seen = async () => new Set((await messages()).map(message => message.ID));
				async function delivered(before: Set<unknown>): Promise<string> {
					const deadline = Date.now() + 10000;
					while (Date.now() < deadline) {
						const fresh = (await messages()).find(message => !before.has(message.ID));
						if (fresh) {
							const response = await fetch(
								`${mailbox}/api/v1/message/${encodeURIComponent(String(fresh.ID))}`,
							);
							if (!response.ok) throw new Error('Could not read captured SSO email factor.');
							const message = object(await response.json());
							const codes = new Set(String(message.Text ?? '').match(/(?<!\d)\d{6}(?!\d)/g) ?? []);
							if (codes.size !== 1) throw new Error('Captured SSO email has no unique six-digit code.');
							return [...codes][0]!;
						}
						await Bun.sleep(50);
					}
					throw new Error('SSO email factor was not delivered to the disposable SMTP receiver.');
				}
				const setup = await client.api(twoFactor.accessToken, 'POST', '/two-factor/get-email', {
					masterPasswordHash: hash,
				});
				const beforeEnrollment = await seen();
				await client.api(twoFactor.accessToken, 'POST', '/two-factor/send-email', {
					email: recipient,
					masterPasswordHash: hash,
					userVerificationToken: setup.userVerificationToken,
				});
				const enrollmentCode = await delivered(beforeEnrollment);
				await client.api(twoFactor.accessToken, 'PUT', '/two-factor/email', {
					email: recipient,
					token: enrollmentCode,
					masterPasswordHash: hash,
					userVerificationToken: setup.userVerificationToken,
				});
				const emailAuthorization = await createSsoAuthorization(client, 'http://localhost:8065');
				let emailCallbacks = 0;
				const emailAccount = await loginWithSso(
					client,
					ssoCredentialsFromCallback(emailAuthorization, await browser(emailAuthorization.url)),
					undefined,
					{
						onTwoFactor: async challenge => {
							emailCallbacks++;
							expect(challenge.providers).toContain(1);
							const beforeCode = await seen();
							await challenge.requestEmail();
							return { provider: 1, token: await delivered(beforeCode) };
						},
					},
				);
				expect(emailCallbacks).toBe(1);
				expect(emailAccount.email).toBe(email);
				if (!emailAccount.encryptedUserKey) throw new Error('Expected initialized SSO account fixture.');
				const emailKey = await unlockAccount(emailAccount, password);
				try {
					expect(emailKey.equals(key)).toBe(true);
				} finally {
					emailKey.fill(0);
				}
			}
		} finally {
			key.fill(0);
			if (jitDirectory) await rm(jitDirectory, { recursive: true, force: true });
			await rm(directory, { recursive: true, force: true });
		}
	}, 180000);
}
