import { test, expect } from 'bun:test';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { VaultwardenClient, ApiError } from '#client';
import {
	createSsoAuthorization,
	ssoCredentialsFromCallback,
	loginWithSso,
	setupSsoAccount,
	SsoAuthorizationDeclinedError,
} from '#sso';
import { refreshAccount, unlockAccount } from '#account';
import { deriveMasterKey, stretchKey, encrypt, decrypt } from '#crypto';

const key = Buffer.alloc(64, 21), email = 'sso@example.com', password = 'synthetic-master-password';
const kdf = { type: 0, iterations: 10000 } as const;
const master = await deriveMasterKey(password, email, kdf),
	stretched = stretchKey(master),
	wrapped = encrypt(key, stretched);
master.fill(0);
stretched.fill(0);
const credentials = { code: 'synthetic-sso-code', codeVerifier: 'v'.repeat(64), redirectUri: 'http://localhost:8065' };
test('SSO authorization uses random state, S256 PKCE and the configured identity endpoint', async () => {
	const client = new VaultwardenClient('https://vault.example/prefix', {
		services: { identity: 'https://identity.example/auth' },
		fetch: (async (url: unknown) => {
			expect(String(url)).toBe('https://identity.example/auth/sso/prevalidate');
			return Response.json({ token: 'synthetic-prevalidation-token' });
		}) as unknown as typeof fetch,
	});
	const first = await createSsoAuthorization(client, credentials.redirectUri, 'organization'),
		second = await createSsoAuthorization(client, credentials.redirectUri);
	expect(first.state).not.toBe(second.state);
	expect(first.codeVerifier).not.toBe(second.codeVerifier);
	const url = new URL(first.url);
	expect(url.pathname).toBe('/auth/connect/authorize');
	expect(url.searchParams.get('code_challenge')).toBe(
		createHash('sha256').update(first.codeVerifier).digest('base64url'),
	);
	expect(url.searchParams.get('code_challenge_method')).toBe('S256');
	expect(url.searchParams.get('domain_hint')).toBe('organization');
	expect(first.url).not.toContain(first.codeVerifier);
	const callback = new URL(credentials.redirectUri);
	callback.search = new URLSearchParams({ state: first.state, code: 'synthetic-code', iss: first.issuer }).toString();
	expect(ssoCredentialsFromCallback(first, callback.href)).toEqual({
		code: 'synthetic-code',
		codeVerifier: first.codeVerifier,
		redirectUri: credentials.redirectUri,
	});
});
test('callback state, issuer, destination, duplicate parameters and OAuth errors are checked before exchange', async () => {
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async () => Response.json({ token: 'synthetic' })) as unknown as typeof fetch,
	});
	const authorization = await createSsoAuthorization(client, credentials.redirectUri);
	const valid = `${credentials.redirectUri}/?state=${authorization.state}&code=synthetic`;
	for (
		const callback of [
			valid.replace(authorization.state, 'wrong'),
			valid.replace('localhost', 'attacker.example'),
			`${valid}&state=${authorization.state}`,
			`${valid}&code=duplicate`,
			`${valid}&iss=https://wrong.example`,
			valid.replace('/?', '/other?'),
			`${valid}#fragment`,
		]
	) {
		expect(() => ssoCredentialsFromCallback(authorization, callback)).toThrow();
	}
	expect(() => ssoCredentialsFromCallback(authorization, `${valid}&error=access_denied`)).toThrow(
		SsoAuthorizationDeclinedError,
	);
	await expect(createSsoAuthorization(client, 'http://localhost:9000')).rejects.toThrow('8065');
});
test('disabled SSO has an actionable error while rate limits return their status without retries', async () => {
	for (const status of [400, 429]) {
		let requests = 0;
		const client = new VaultwardenClient('https://vault.example', {
			fetch: (async () => {
				requests++;
				return Response.json({ error: 'synthetic-private-provider-detail' }, { status });
			}) as unknown as typeof fetch,
		});
		const error = await createSsoAuthorization(client, credentials.redirectUri).catch((error: unknown) => error);
		expect(error).toBeInstanceOf(Error);
		expect(String(error)).not.toContain('synthetic-private-provider-detail');
		if (status === 400) {
			expect((error as Error).message).toContain('not enabled');
			expect((error as Error).cause).toBeInstanceOf(ApiError);
		} else {
			expect(error).toBeInstanceOf(ApiError);
			expect((error as ApiError).status).toBe(429);
		}
		expect(requests).toBe(1);
	}
});
test('SSO login resolves email/KDF from authenticated data, omits grant parameters and refreshes without a password grant', async () => {
	const grants: URLSearchParams[] = [];
	const client = new VaultwardenClient('https://vault.example', {
		deviceId: 'fixture-device',
		fetch: (async (url: unknown, init: RequestInit) => {
			if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email: 'SSO@Example.COM' });
			const body = new URLSearchParams(String(init.body));
			grants.push(body);
			if (body.get('grant_type') === 'refresh_token') {
				return Response.json({ access_token: 'renewed', refresh_token: 'renewed-refresh', expires_in: 3600 });
			}
			expect(body.get('grant_type')).toBe('authorization_code');
			expect(body.get('scope')).toBe('api offline_access');
			expect(body.get('code_verifier')).toBe(credentials.codeVerifier);
			expect(body.get('redirect_uri')).toBe(credentials.redirectUri);
			expect(body.has('password')).toBe(false);
			return Response.json({
				access_token: 'access',
				refresh_token: 'refresh',
				expires_in: 3600,
				key: wrapped,
				kdf: 0,
				kdfIterations: 10000,
			});
		}) as unknown as typeof fetch,
	});
	const account = await loginWithSso(client, credentials);
	if (!account.encryptedUserKey) throw new Error('Expected initialized SSO account fixture.');
	expect(account.auth).toBe('sso');
	expect(account.email).toBe(email);
	expect(account.kdf).toEqual(kdf);
	expect(JSON.stringify(account)).not.toContain(credentials.code);
	expect(JSON.stringify(account)).not.toContain(credentials.codeVerifier);
	const unlocked = await unlockAccount(account, password);
	try {
		expect(unlocked).toEqual(key);
	} finally {
		unlocked.fill(0);
	}
	expect((await refreshAccount(client, account)).accessToken).toBe('renewed');
	expect(grants.map(g => g.get('grant_type'))).toEqual(['authorization_code', 'refresh_token']);
});
test('SSO email 2FA retries the same code once and requests delivery using the pending device only', async () => {
	let grants = 0, callbacks = 0, emailRequests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		deviceId: 'fixture-device',
		fetch: (async (url: unknown, init: RequestInit) => {
			if (String(url).endsWith('/api/config')) {
				return Response.json({ environment: { vault: 'https://web.example.net/vault' } });
			}
			if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email });
			if (String(url).endsWith('/send-email-login')) {
				emailRequests++;
				expect(JSON.parse(String(init.body))).toEqual({ deviceIdentifier: 'fixture-device' });
				return Response.json({});
			}
			grants++;
			const body = new URLSearchParams(String(init.body));
			expect(body.get('code')).toBe(credentials.code);
			expect(body.get('code_verifier')).toBe(credentials.codeVerifier);
			if (grants === 1) {
				return Response.json(
					{
						twoFactorProviders: [1, 7],
						twoFactorProviders2: {
							'7': {
								challenge: 'Y2hhbGxlbmdl',
								rpId: 'vault.example',
								allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
							},
						},
					},
					{ status: 400 },
				);
			}
			expect(body.get('twoFactorProvider')).toBe('1');
			expect(body.get('twoFactorToken')).toBe('123456');
			return Response.json({
				access_token: 'access',
				refresh_token: 'refresh',
				expires_in: 3600,
				userDecryptionOptions: {
					masterPasswordUnlock: { masterKeyWrappedUserKey: wrapped, kdf: { kdfType: 0, iterations: 10000 } },
				},
			});
		}) as unknown as typeof fetch,
	});
	const account = await loginWithSso(client, credentials, undefined, {
		onTwoFactor: async challenge => {
			callbacks++;
			expect(challenge.providers).toEqual([1, 7]);
			expect(challenge.webAuthnOptions).toEqual({
				challenge: 'Y2hhbGxlbmdl',
				rpId: 'vault.example',
				allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
			});
			expect(challenge.webAuthnOrigin).toBe('https://web.example.net');
			await challenge.requestEmail();
			return { provider: 1, token: '123456' };
		},
	});
	expect(account.kdf).toEqual(kdf);
	expect(callbacks).toBe(1);
	expect(grants).toBe(2);
	expect(emailRequests).toBe(1);
});
test('SSO login accepts an explicitly selected recovery code absent from Vaultwarden advertised providers', async () => {
	let grants = 0;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init: RequestInit) => {
			if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email });
			expect(String(url)).toBe('https://vault.example/identity/connect/token');
			const body = new URLSearchParams(String(init.body));
			expect(body.get('grant_type')).toBe('authorization_code');
			expect(body.get('code')).toBe(credentials.code);
			expect(body.get('code_verifier')).toBe(credentials.codeVerifier);
			if (++grants === 1) {
				return Response.json({ TwoFactorProviders: ['0'], TwoFactorProviders2: { '0': null } }, { status: 400 });
			}
			expect(body.get('twoFactorProvider')).toBe('8');
			expect(body.get('twoFactorToken')).toBe('synthetic-recovery-code');
			return Response.json({
				access_token: 'access',
				refresh_token: 'refresh',
				expires_in: 3600,
				Key: wrapped,
				Kdf: 0,
				KdfIterations: 10000,
			});
		}) as unknown as typeof fetch,
	});
	const account = await loginWithSso(client, credentials, undefined, {
		onTwoFactor: async challenge => {
			expect(challenge.providers).toEqual([0]);
			return { provider: 8, token: '  SYNTHETIC-RECOVERY- CODE  ' };
		},
	});
	expect(account.email).toBe(email);
	expect(grants).toBe(2);
});
test('SSO errors never fall back to password login or repeat grants', async () => {
	for (const scenario of ['cancel', 'invalid-provider', 'retry-failed']) {
		let grants = 0;
		const client = new VaultwardenClient('https://vault.example', {
			fetch: (async (url: unknown) => {
				if (String(url).endsWith('/profile')) return Response.json({ id: 'user', email });
				grants++;
				return Response.json({ twoFactorProviders: [0] }, { status: 400 });
			}) as unknown as typeof fetch,
		});
		const operation = loginWithSso(client, credentials, undefined, {
			onTwoFactor: async () => {
				if (scenario === 'cancel') throw new Error('Cancelled');
				return { provider: scenario === 'invalid-provider' ? 1 : 0, token: 'wrong' };
			},
		});
		if (scenario === 'cancel') await expect(operation).rejects.toThrow('Cancelled');
		else if (scenario === 'invalid-provider') await expect(operation).rejects.toThrow('Invalid two-factor answer.');
		else await expect(operation).rejects.toBeInstanceOf(ApiError);
		expect(grants).toBe(scenario === 'retry-failed' ? 2 : 1);
	}
});

test('new SSO accounts set a master password and upload wrapped vault and asymmetric keys', async () => {
	const body: Record<string, unknown>[] = [];
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init?: RequestInit) => {
			const path = String(url);
			if (path.endsWith('/connect/token')) {
				return Response.json({ access_token: 'access', refresh_token: 'refresh', expires_in: 3600 });
			}
			if (path.endsWith('/profile')) return Response.json({ id: 'user', email });
			if (path.endsWith('/prelogin')) return Response.json({ kdf: 0, kdfIterations: 100000 });
			if (path.endsWith('/accounts/set-password')) {
				expect(new Headers(init?.headers).get('authorization')).toBe('Bearer access');
				body.push(JSON.parse(String(init?.body)) as Record<string, unknown>);
				return Response.json({});
			}
			throw new Error(`Unexpected request: ${path}`);
		}) as unknown as typeof fetch,
	});
	const pending = await loginWithSso(client, credentials);
	expect(pending.encryptedUserKey).toBeUndefined();
	const account = await setupSsoAccount(client, pending, password);
	expect(account.encryptedUserKey).toMatch(/^2\./);
	expect(body).toHaveLength(1);
	expect(body[0]).toMatchObject({ kdf: 0, kdfIterations: 100000 });
	expect(body[0]!.masterPasswordHash).not.toBe(password);
	const keys = body[0]!.keys as Record<string, unknown>;
	expect(keys.publicKey).toMatch(/^[A-Za-z0-9+/]+=*$/);
	expect(String(keys.encryptedPrivateKey)).toMatch(/^2\./);
	const recovered = await unlockAccount(account, password);
	let privateDer: Buffer | undefined;
	try {
		expect(recovered).toHaveLength(64);
		privateDer = decrypt(String(keys.encryptedPrivateKey), recovered);
		const publicDer = createPublicKey(createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' }))
			.export({ format: 'der', type: 'spki' });
		expect(Buffer.from(publicDer).toString('base64')).toBe(String(keys.publicKey));
	} finally {
		recovered.fill(0);
		privateDer?.fill(0);
	}
});
