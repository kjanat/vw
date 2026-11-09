import {
	accountUserId,
	loginWithApiKey,
	loginWithPassword,
	type PasswordAccount,
	refreshAccount,
	unlockAccount,
} from '#account';
import { VaultwardenClient } from '#client';
import { deriveMasterKey, encrypt, stretchKey } from '#crypto';
import { expect, test } from 'bun:test';

const id = '00000000-0000-0000-0000-000000000001';
const credentials = { clientId: `user.${id}`, clientSecret: 'synthetic-api-secret' };
const base = { access_token: 'access-token', expires_in: 3600, Key: 'wrapped-key', Kdf: 0, KdfIterations: 10000 };
test('account user ID can be read from an access-token subject without a synced profile', () => {
	const token = `header.${Buffer.from(JSON.stringify({ sub: id })).toString('base64url')}.signature`;
	expect(accountUserId({ accessToken: token })).toBe(id);
	for (const accessToken of ['opaque-token', 'header.e30.signature', 'header.invalid.signature']) {
		expect(accountUserId({ accessToken })).toBeUndefined();
	}
});
test('password challenge resumes one grant, requests email explicitly, and never exposes password material to the callback', async () => {
	const email = 'fixture@example.com', password = 'synthetic-password';
	const master = await deriveMasterKey(password, email, { type: 0, iterations: 10000 });
	const stretched = stretchKey(master), userKey = Buffer.alloc(64, 9);
	const wrapped = encrypt(userKey, stretched);
	master.fill(0);
	stretched.fill(0);
	const requests: string[] = [];
	let grants = 0;
	const api = new VaultwardenClient('https://example.com', {
		deviceId: 'synthetic-device',
		fetch: transport((url, init) => {
			requests.push(url);
			if (url.endsWith('/prelogin')) return Response.json({ kdf: 0, kdfIterations: 10000 });
			if (url.endsWith('/api/config')) {
				return Response.json({ environment: { vault: 'https://web.example.net/vault' } });
			}
			if (url.endsWith('/send-email-login')) {
				const body = JSON.parse(String(init.body));
				expect(body.email).toBe(email);
				expect(body.deviceIdentifier).toBe('synthetic-device');
				expect(body.masterPasswordHash).not.toBe(password);
				expect(body.masterPasswordHash).toHaveLength(44);
				expect(new Headers(init.headers).has('Authorization')).toBe(false);
				return new Response(null, { status: 200 });
			}
			const body = new URLSearchParams(String(init.body));
			if (++grants === 1) {
				return Response.json(
					{
						TwoFactorProviders: [1, 2, 7],
						TwoFactorProviders2: {
							'1': { Email: 'untrusted' },
							'2': { AuthUrl: 'https://api-test.duosecurity.com/oauth/v1/authorize?request=short-lived' },
							'7': {
								challenge: 'Y2hhbGxlbmdl',
								rpId: 'example.com',
								allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
							},
						},
					},
					{ status: 400 },
				);
			}
			expect(body.get('twoFactorProvider')).toBe('1');
			expect(body.get('twoFactorToken')).toBe('123456');
			return Response.json({ ...base, refresh_token: 'refresh-token', Key: wrapped });
		}),
	});
	let challenges = 0;
	const result = await loginWithPassword(api, email, password, undefined, {
		onTwoFactor: async challenge => {
			challenges++;
			expect(challenge.providers).toEqual([1, 2, 7]);
			expect(challenge.duoAuthUrl).toBe('https://api-test.duosecurity.com/oauth/v1/authorize?request=short-lived');
			expect(challenge.webAuthnOptions).toEqual({
				challenge: 'Y2hhbGxlbmdl',
				rpId: 'example.com',
				allowCredentials: [{ id: 'Y3JlZGVudGlhbA', type: 'public-key' }],
			});
			expect(challenge.webAuthnOrigin).toBe('https://web.example.net');
			expect(Object.keys(challenge).sort()).toEqual([
				'duoAuthUrl',
				'providers',
				'requestEmail',
				'webAuthnOptions',
				'webAuthnOrigin',
			]);
			expect(Object.isFrozen(challenge.providers)).toBe(true);
			await challenge.requestEmail();
			return { provider: 1, token: '123456' };
		},
	});
	expect(result.email).toBe(email);
	expect(challenges).toBe(1);
	expect(grants).toBe(2);
	expect(requests.filter(url => url.endsWith('/send-email-login'))).toHaveLength(1);
});
test('password login accepts an explicitly selected recovery code absent from Vaultwarden advertised providers', async () => {
	const email = 'recovery@example.com', password = 'synthetic-password';
	const master = await deriveMasterKey(password, email, { type: 0, iterations: 10000 });
	const stretched = stretchKey(master), userKey = Buffer.alloc(64, 11);
	const wrapped = encrypt(userKey, stretched);
	master.fill(0);
	stretched.fill(0);
	let grants = 0;
	const api = new VaultwardenClient('https://vault.example.com', {
		fetch: transport((_url, init) => {
			if (String(_url).endsWith('/prelogin')) return Response.json({ kdf: 0, kdfIterations: 10000 });
			const body = new URLSearchParams(String(init.body));
			if (++grants === 1) {
				return Response.json({ TwoFactorProviders: ['0'], TwoFactorProviders2: { '0': null } }, { status: 400 });
			}
			expect(body.get('twoFactorProvider')).toBe('8');
			expect(body.get('twoFactorToken')).toBe('recovery-token');
			return Response.json({ ...base, refresh_token: 'refresh-token', Key: wrapped });
		}),
	});
	const account = await loginWithPassword(api, email, password, undefined, {
		onTwoFactor: async challenge => {
			expect(challenge.providers).toEqual([0]);
			return { provider: 8, token: '  RECOVERY- TOKEN  ' };
		},
	});
	expect(account.email).toBe(email);
	expect(grants).toBe(2);
});
test('challenge cancellation, invalid provider and rejected retry do not loop or send unsolicited email', async () => {
	for (const scenario of ['cancel', 'invalid', 'retry', 'no-callback', 'email-unavailable']) {
		let grants = 0, challenges = 0;
		const api = new VaultwardenClient('https://example.com', {
			fetch: transport(url => {
				if (url.endsWith('/prelogin')) return Response.json({ kdf: 0, kdfIterations: 10000 });
				expect(url.endsWith('/connect/token')).toBe(true);
				grants++;
				return Response.json({ twoFactorProviders: [0] }, { status: 400 });
			}),
		});
		await expect(loginWithPassword(api, 'fixture@example.com', 'synthetic-password', undefined, {
			onTwoFactor: scenario === 'no-callback' ? undefined : async challenge => {
				challenges++;
				if (scenario === 'cancel') throw new Error('Cancelled');
				if (scenario === 'email-unavailable') await challenge.requestEmail();
				return { provider: scenario === 'invalid' ? 1 : 0, token: '123456' };
			},
		})).rejects.toThrow();
		expect(grants).toBe(scenario === 'retry' ? 2 : 1);
		expect(challenges).toBe(scenario === 'no-callback' ? 0 : 1);
	}
});
function transport(handler: (url: string, init: RequestInit) => Response) {
	return ((url: unknown, init?: RequestInit) =>
		Promise.resolve(handler(String(url), init!))) as unknown as typeof fetch;
}
test('API-key login accepts a token without a refresh token, validates the principal and uses only its own grant', async () => {
	const grants: string[] = [];
	const api = new VaultwardenClient('https://example.com/prefix', {
		deviceId: 'stable-device',
		fetch: transport((url, init) => {
			if (url.endsWith('/identity/connect/token')) {
				const data = new URLSearchParams(String(init.body));
				grants.push(data.get('grant_type')!);
				expect(data.get('client_id')).toBe(credentials.clientId);
				expect(data.get('client_secret') === credentials.clientSecret).toBe(true);
				expect(data.get('scope')).toBe('api');
				expect(data.get('deviceIdentifier')).toBe('stable-device');
				expect(data.has('password')).toBe(false);
				return Response.json(base);
			}
			expect(url).toBe('https://example.com/prefix/api/accounts/profile');
			expect(init.headers).toMatchObject({ Authorization: 'Bearer access-token' });
			expect(init.body).toBeUndefined();
			return Response.json({ id, email: 'User@Example.COM' });
		}),
	});
	const account = await loginWithApiKey(api, credentials);
	expect(account.auth).toBe('api-key');
	expect(account.email).toBe('user@example.com');
	expect('refreshToken' in account).toBe(false);
	const renewed = await refreshAccount(api, account);
	expect(renewed.auth).toBe('api-key');
	expect(grants).toEqual(['client_credentials', 'client_credentials']);
});
test('modern wrapped-key/KDF API responses can be unlocked locally with a master password', async () => {
	const kdf = { type: 0, iterations: 10000 } as const;
	const master = await deriveMasterKey('fixture-master', 'user@example.com', kdf);
	const stretched = stretchKey(master), userKey = Buffer.alloc(64, 7);
	const wrapped = encrypt(userKey, stretched);
	master.fill(0);
	stretched.fill(0);
	const api = new VaultwardenClient('https://example.com', {
		fetch: transport(url =>
			url.endsWith('/profile')
				? Response.json({ id, email: 'user@example.com' })
				: Response.json({
					access_token: 'access-token',
					expires_in: 3600,
					UserDecryptionOptions: {
						MasterPasswordUnlock: {
							Kdf: { KdfType: 0, Iterations: 10000 },
							MasterKeyWrappedUserKey: wrapped,
						},
					},
				})
		),
	});
	const account = await loginWithApiKey(api, credentials);
	const unlocked = await unlockAccount(account, 'fixture-master');
	try {
		expect(unlocked.equals(userKey)).toBe(true);
	} finally {
		unlocked.fill(0);
	}
	await expect(unlockAccount(account, 'incorrect')).rejects.toThrow('authentication');
});
test('API-key login rejects organization keys, mismatched principals and invalid token responses without echoing credentials', async () => {
	let calls = 0;
	const api = new VaultwardenClient('https://example.com', {
		fetch: transport(() => {
			calls++;
			return Response.json(base);
		}),
	});
	await expect(api.loginWithApiKey({ ...credentials, clientId: `organization.${id}` })).rejects.toThrow(
		'personal user',
	);
	expect(calls).toBe(0);
	for (const response of [{ ...base, expires_in: 0 }, { ...base, Key: undefined }]) {
		const broken = new VaultwardenClient('https://example.com', {
			fetch: transport(url =>
				url.endsWith('/profile') ? Response.json({ id, email: 'user@example.com' }) : Response.json(response)
			),
		});
		await expect(loginWithApiKey(broken, credentials)).rejects.toThrow();
	}
	const mismatch = new VaultwardenClient('https://example.com', {
		fetch: transport(url =>
			url.endsWith('/profile') ? Response.json({ id: 'other-user', email: 'other@example.com' }) : Response.json(base)
		),
	});
	await expect(loginWithApiKey(mismatch, credentials)).rejects.toThrow('identity');
	const rejected = new VaultwardenClient('https://example.com', {
		fetch: transport(() => Response.json({ error: credentials.clientSecret }, { status: 400 })),
	});
	try {
		await loginWithApiKey(rejected, credentials);
	} catch (error) {
		expect(String(error).includes(credentials.clientSecret)).toBe(false);
	}
});
test('password accounts follow refresh-token renewal semantics', async () => {
	const account: PasswordAccount = {
		accessToken: 'old',
		refreshToken: 'refresh',
		expiresAt: 0,
		email: 'user@example.com',
		kdf: { type: 0, iterations: 10000 },
		encryptedUserKey: 'wrapped',
	};
	const api = new VaultwardenClient('https://example.com', {
		fetch: transport((_url, init) => {
			const body = new URLSearchParams(String(init.body));
			expect(body.get('grant_type')).toBe('refresh_token');
			expect(body.get('refresh_token')).toBe('refresh');
			return Response.json({ access_token: 'new', refresh_token: 'rotated', expires_in: 3600 });
		}),
	});
	const renewed = await refreshAccount(api, account);
	expect(renewed.accessToken).toBe('new');
	expect((renewed as PasswordAccount).refreshToken).toBe('rotated');
	expect(renewed.encryptedUserKey).toBe('wrapped');
});
