// Disposable loopback-only OIDC provider. Every identity, signing key and token is synthetic.
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
const control = process.env.VW_OIDC_CONTROL;
if (!control) throw new Error('A fixture control token is required.');
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'fixture-key', use: 'sig', alg: 'RS256' };
let identity: { email: string; sub: string } = { email: 'unconfigured@example.com', sub: randomUUID() };
type Grant = { identity: typeof identity; nonce: string; challenge: string; redirect: string };
const codes = new Map<string, Grant>(),
	accessTokens = new Map<string, Grant>(),
	refreshTokens = new Map<string, Grant>();
let issuer = '';
const server = Bun.serve({
	hostname: '127.0.0.1',
	port: 0,
	async fetch(request) {
		const url = new URL(request.url), json = (value: unknown, status = 200) => Response.json(value, { status });
		if (url.pathname === '/__test/identity') {
			if (request.headers.get('Authorization') !== `Bearer ${control}` || request.method !== 'PUT') {
				return json({}, 403);
			}
			const data = await request.json() as { email?: unknown; sub?: unknown };
			if (
				typeof data.email !== 'string' || !data.email.endsWith('@example.com') || typeof data.sub !== 'string'
			) return json({}, 400);
			identity = { email: data.email, sub: data.sub };
			return json({ configured: true });
		}
		if (url.pathname === '/.well-known/openid-configuration') {
			return json({
				issuer,
				authorization_endpoint: `${issuer}/authorize`,
				token_endpoint: `${issuer}/token`,
				userinfo_endpoint: `${issuer}/userinfo`,
				jwks_uri: `${issuer}/jwks`,
				response_types_supported: ['code'],
				subject_types_supported: ['public'],
				id_token_signing_alg_values_supported: ['RS256'],
				token_endpoint_auth_methods_supported: ['client_secret_basic'],
				grant_types_supported: ['authorization_code', 'refresh_token'],
				scopes_supported: ['openid', 'email', 'profile'],
			});
		}
		if (url.pathname === '/jwks') return json({ keys: [jwk] });
		if (url.pathname === '/authorize') {
			const redirect = url.searchParams.get('redirect_uri') ?? '';
			if (
				url.searchParams.get('client_id') !== 'fixture-client'
				|| url.searchParams.get('code_challenge_method') !== 'S256'
				|| !/^http:\/\/127\.0\.0\.1:\d+\/identity\/connect\/oidc-signin$/.test(redirect)
			) return json({ error: 'invalid_request' }, 400);
			const code = randomUUID();
			codes.set(code, {
				identity: { ...identity },
				nonce: url.searchParams.get('nonce') ?? '',
				challenge: url.searchParams.get('code_challenge') ?? '',
				redirect,
			});
			const callback = new URL(redirect);
			callback.search = new URLSearchParams({ code, state: url.searchParams.get('state') ?? '' }).toString();
			return Response.redirect(callback.href, 302);
		}
		if (url.pathname === '/token' && request.method === 'POST') {
			if (
				request.headers.get('Authorization')
				!== `Basic ${Buffer.from('fixture-client:synthetic-oidc-secret').toString('base64')}`
			) return json({ error: 'invalid_client' }, 401);
			const body = new URLSearchParams(await request.text()),
				code = body.get('code') ?? '',
				refresh = body.get('refresh_token') ?? '';
			const grant = body.get('grant_type') === 'refresh_token' ? refreshTokens.get(refresh) : codes.get(code);
			if (!grant) return json({ error: 'invalid_grant' }, 400);
			if (body.get('grant_type') === 'authorization_code') {
				if (
					body.get('redirect_uri') !== grant.redirect
					|| createHash('sha256').update(body.get('code_verifier') ?? '').digest('base64url') !== grant.challenge
				) return json({ error: 'invalid_grant' }, 400);
				codes.delete(code);
			} else if (body.get('grant_type') === 'refresh_token') refreshTokens.delete(refresh);
			else return json({ error: 'unsupported_grant_type' }, 400);
			const access = randomUUID(), nextRefresh = randomUUID(), now = Math.floor(Date.now() / 1000);
			accessTokens.set(access, grant);
			refreshTokens.set(nextRefresh, grant);
			const claims = {
				iss: issuer,
				aud: 'fixture-client',
				sub: grant.identity.sub,
				email: grant.identity.email,
				email_verified: true,
				nonce: grant.nonce,
				iat: now,
				exp: now + 3600,
			};
			const message = `${
				Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'fixture-key', typ: 'JWT' })).toString('base64url')
			}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
			return json({
				access_token: access,
				refresh_token: nextRefresh,
				token_type: 'Bearer',
				expires_in: 3600,
				id_token: `${message}.${sign('RSA-SHA256', Buffer.from(message), pair.privateKey).toString('base64url')}`,
			});
		}
		if (url.pathname === '/userinfo') {
			const grant = accessTokens.get(request.headers.get('Authorization')?.replace(/^Bearer /, '') ?? '');
			return grant
				? json({
					sub: grant.identity.sub,
					email: grant.identity.email,
					email_verified: true,
					preferred_username: 'Synthetic SSO fixture',
				})
				: json({ error: 'invalid_token' }, 401);
		}
		return json({}, 404);
	},
});
issuer = server.url.href.replace(/\/$/, '');
console.log(issuer);
