import { test, expect } from 'bun:test';
import { VaultwardenClient, ApiError, type JsonObject } from '#client';
import { encrypt, decrypt, encryptAttachment } from '#crypto';
import { MultipleResultsError } from '#search';
import { sendObjectResponse } from '#local-api-models';
import {
	deriveSendKey,
	hashSendPassword,
	assertSendFileSize,
	SendService,
	receiveSend,
	SendPasswordRequired,
	SendMutationFailure,
} from '#sends';

const accountKey = Buffer.alloc(64, 3);
const seed = Buffer.from(Array.from({ length: 16 }, (_, i) => i));
const key = deriveSendKey(seed);
const accessId = Buffer.alloc(16, 9).toString('base64url');
const link = `https://vault.example/prefix/#/send/${accessId}/${seed.toString('base64url')}`;
function encryptedSend(): JsonObject {
	return {
		id: 'send-id',
		accessId,
		type: 0,
		key: encrypt(seed, accountKey),
		name: encrypt(Buffer.from('Secret send'), key),
		notes: encrypt(Buffer.from('Private notes'), key),
		text: { text: encrypt(Buffer.from('Payload'), key), hidden: true },
		deletionDate: new Date(Date.now() + 86400000).toISOString(),
		disabled: false,
		password: 'server-only-hash',
	};
}
test('Send HKDF and password proof match independent Python stdlib vectors', () => {
	expect(key.toString('hex')).toBe(
		'063a955a1c01b4e1aacb7cd359c919b2cb61041c0c05c94c0eb76fb9a9e144b3fbeca074de1437a1a2330ad2833138abf3be2561a3a30ae1f33e15e1a2f7ca04',
	);
	expect(Buffer.from(hashSendPassword('synthetic-password', seed), 'base64').toString('hex')).toBe(
		'0f80ecb32361e1f1e6f3bee07f74bd853216c8c4c3eeacc5149ecaa709d2c512',
	);
	expect(() => deriveSendKey(Buffer.alloc(32))).toThrow('seed');
});
test('owner reads decrypt with the wrapped Send seed, expose access URL, and omit server password hash', () => {
	const service = new SendService(new VaultwardenClient('https://vault.example/prefix'), 'owner-token', {
		sends: [encryptedSend()],
	}, accountKey);
	const result = service.get('secret');
	expect(result.text).toEqual({ text: 'Payload', hidden: true });
	expect(result.notes).toBe('Private notes');
	expect(result.accessUrl).toBe(link);
	expect(result.passwordSet).toBe(true);
	expect(result.password).toBeUndefined();
});
test('Send lookup resolves UUIDs without regard to letter case', () => {
	const id = 'aabbccdd-1111-2222-3333-445566778899';
	const service = new SendService(new VaultwardenClient('https://vault.example'), 'owner-token', {
		sends: [{ ...encryptedSend(), id }],
	}, accountKey);
	expect(service.get(id.toUpperCase()).id).toBe(id);
});
test('text-only Send lookup filters before resolving exact IDs and ambiguous names', () => {
	const fileSend: JsonObject = {
		...encryptedSend(),
		id: 'file-send-id',
		type: 1,
		file: { id: 'file-id', fileName: encrypt(Buffer.from('secret.txt'), key), size: 6 },
	};
	delete fileSend.text;
	const service = new SendService(new VaultwardenClient('https://vault.example'), 'owner-token', {
		sends: [encryptedSend(), fileSend],
	}, accountKey);
	expect(service.get('Secret', 0).id).toBe('send-id');
	expect(service.get('send-id', 0).type).toBe(0);
	expect(() => service.get('file-send-id', 0)).toThrow('Not found.');
});
test('ambiguous Send name lookup reports each matching ID', () => {
	const second = { ...encryptedSend(), id: 'second-send-id' };
	const service = new SendService(new VaultwardenClient('https://vault.example/prefix'), 'owner-token', {
		sends: [encryptedSend(), second],
	}, accountKey);
	try {
		service.get('Secret');
		throw new Error('Expected ambiguous lookup to fail.');
	} catch (error) {
		expect(error).toBeInstanceOf(MultipleResultsError);
		expect((error as MultipleResultsError).message).toContain(
			'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nsend-id\nsecond-send-id',
		);
		expect((error as MultipleResultsError).ids).toEqual(['send-id', 'second-send-id']);
	}
});
test('Bitwarden file Send creation and edits require premium before mutation', async () => {
	const requests: string[] = [];
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown) => {
			requests.push(String(url));
			if (String(url).endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const fileSend = {
		...encryptedSend(),
		type: 1,
		file: { id: 'file-id', fileName: encrypt(Buffer.from('payload.bin'), key) },
	};
	const service = new SendService(client, 'owner-token', { sends: [fileSend] }, accountKey);
	await expect(service.assertCanCreate(1)).rejects.toThrow('Premium status is required');
	await expect(service.create(
		{ type: 1, name: 'File', file: { fileName: 'payload.bin' } },
		Buffer.from('payload'),
	)).rejects.toThrow('Premium status is required');
	await expect(service.edit('send-id', { name: 'Renamed' })).rejects.toThrow('Premium status is required');
	expect(requests).toEqual(['https://vault.example/api/config']);
});
test('Vaultwarden file Sends bypass the Bitwarden premium gate for create and edit', async () => {
	const paths: string[] = [];
	const existing = {
		...encryptedSend(),
		type: 1,
		text: null,
		file: { id: 'existing-file', fileName: encrypt(Buffer.from('existing.bin'), key) },
	};
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init: RequestInit) => {
			const path = String(url);
			paths.push(path);
			if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
			if (path.endsWith('/api/sends/file/v2')) {
				const data = JSON.parse(String(init.body));
				return Response.json({
					fileUploadType: 0,
					sendResponse: {
						...data,
						id: 'created-send',
						accessId,
						file: { ...data.file, id: 'created-file' },
					},
				});
			}
			if (path.endsWith('/api/sends/created-send/file/created-file')) return new Response(null, { status: 204 });
			if (path.endsWith('/api/sends/send-id')) {
				const data = JSON.parse(String(init.body));
				return Response.json({ ...existing, ...data, file: existing.file });
			}
			throw new Error(`Unexpected request: ${path}`);
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', {
		profile: { premiumPersonally: false, premiumFromOrganization: false },
		sends: [existing],
	}, accountKey);
	await service.assertCanCreate(1);
	const created = await service.create(
		{ type: 1, name: 'Created on Vaultwarden', file: { fileName: 'created.bin' } },
		Buffer.from('payload'),
	);
	expect(created.name).toBe('Created on Vaultwarden');
	expect((await service.edit('send-id', { name: 'Renamed on Vaultwarden' })).name)
		.toBe('Renamed on Vaultwarden');
	expect(paths).toEqual([
		'https://vault.example/api/config',
		'https://vault.example/api/sends/file/v2',
		'https://vault.example/api/sends/created-send/file/created-file',
		'https://vault.example/api/sends/send-id',
	]);
});
test('Bitwarden file Sends upload encrypted contents to Azure without account credentials', async () => {
	let uploaded = false, renewed = false;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init: RequestInit) => {
			const path = String(url);
			if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
			if (path.endsWith('/api/sends/file/v2')) {
				const data = JSON.parse(String(init.body));
				return Response.json({
					fileUploadType: 1,
					url: 'https://storage.example/blob?sv=2023-11-03&se=2000-01-01T00%3A00%3A00Z&sig=expired',
					sendResponse: {
						...data,
						id: 'created-send',
						accessId,
						file: { ...data.file, id: 'created-file' },
					},
				});
			}
			if (path.endsWith('/sends/created-send/file/created-file')) {
				expect(init.method).toBe('GET');
				renewed = true;
				return Response.json({ url: 'https://storage.example/blob?sv=2023-11-03&sig=renewed' });
			}
			expect(path).toBe('https://storage.example/blob?sv=2023-11-03&sig=renewed');
			expect(init.method).toBe('PUT');
			expect(new Headers(init.headers).get('Authorization')).toBeNull();
			expect(Buffer.from(init.body as Buffer).includes(Buffer.from('synthetic payload'))).toBe(false);
			uploaded = true;
			return new Response(null, { status: 201 });
		}) as unknown as typeof fetch,
	});
	const service = new SendService(
		client,
		'owner-token',
		{ profile: { premiumPersonally: true }, sends: [] },
		accountKey,
	);
	const result = await service.create(
		{ type: 1, name: 'Azure Send', file: { fileName: 'payload.bin' } },
		Buffer.from('synthetic payload'),
	);
	expect(result.name).toBe('Azure Send');
	expect(uploaded).toBe(true);
	expect(renewed).toBe(true);
});
test('failed Azure Send upload removes the incomplete Send and hides the signed URL', async () => {
	const methods: string[] = [];
	const signedUrl = 'https://storage.example/blob?sv=2023-11-03&se=2099-01-01T00%3A00%3A00Z&sig=synthetic-secret';
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init: RequestInit) => {
			const path = String(url);
			methods.push(init.method!);
			if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
			if (path.endsWith('/api/sends/file/v2')) {
				const data = JSON.parse(String(init.body));
				return Response.json({
					fileUploadType: 1,
					url: signedUrl,
					sendResponse: {
						...data,
						id: 'created-send',
						accessId,
						file: { ...data.file, id: 'created-file' },
					},
				});
			}
			if (path === signedUrl) {
				expect(new Headers(init.headers).get('Authorization')).toBeNull();
				return new Response(null, { status: 500 });
			}
			expect(path).toBe('https://vault.example/api/sends/created-send');
			expect(init.method).toBe('DELETE');
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const service = new SendService(
		client,
		'owner-token',
		{ profile: { premiumPersonally: true }, sends: [] },
		accountKey,
	);
	await expect(service.create(
		{ type: 1, name: 'Azure Send', file: { fileName: 'payload.bin' } },
		Buffer.from('synthetic payload'),
	)).rejects.toThrow('Send file upload failed; incomplete Send removed.');
	expect(methods).toEqual(['POST', 'PUT', 'DELETE']);
});
test('Send creation rejects a deletion date that is not in the future before network access', async () => {
	let requests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async () => {
			requests++;
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [] }, accountKey);
	await expect(service.create({
		type: 0,
		name: 'Expired Send',
		text: { text: 'payload' },
		deletionDate: new Date(Date.now() - 1000).toISOString(),
	})).rejects.toMatchObject({ message: 'Must specify a valid deletion date after the current time' });
	expect(requests).toBe(0);
});
test('Send creation rejects malformed recipient lists before network access', async () => {
	let requests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async () => {
			requests++;
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [] }, accountKey);
	for (const emails of ['', {}, 0, [''], ['bad,delimiter@example.com']]) {
		await expect(service.create({
			type: 0,
			name: 'Email Send',
			text: { text: 'payload' },
			emails: emails as string[],
		})).rejects.toThrow('Invalid Send recipient email list.');
	}
	expect(requests).toBe(0);
});
test('Send response email defaults round-trip through create and edit without enabling email verification', async () => {
	let requests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init?: RequestInit) => {
			requests++;
			if (String(url).endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
			const body = JSON.parse(String(init!.body));
			expect(Object.hasOwn(body, 'emails')).toBe(false);
			expect(Object.hasOwn(body, 'authType')).toBe(false);
			return Response.json({ ...encryptedSend(), ...body });
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [encryptedSend()] }, accountKey);
	const created = await service.create({ type: 0, name: 'Created', text: { text: 'payload' }, emails: [] });
	expect(created.name).toBe('Created');
	// The public Send response contains emails: [] even when Vaultwarden has no email-restricted Send.
	const displayed = sendObjectResponse(service.get('send-id'));
	expect(displayed.emails).toEqual([]);
	expect((await service.edit('send-id', { ...displayed, name: 'Renamed' })).name).toBe('Renamed');
	await expect(service.edit('send-id', { emails: ['recipient@example.com'] })).rejects.toThrow('email-verification');
	expect(requests).toBe(3);
});
test('Bitwarden Cloud email-restricted Sends serialize recipients and omit password authentication', async () => {
	const requests: Array<{ path: string; body?: JsonObject }> = [];
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init?: RequestInit) => {
			const path = String(url);
			if (init?.method === 'POST') {
				const body = JSON.parse(String(init.body)) as JsonObject;
				requests.push({ path, body });
				return Response.json({ ...encryptedSend(), ...body, emails: 'alice@example.com,bob@example.com' });
			}
			requests.push({ path });
			if (path.endsWith('/api/config')) return Response.json({ server: { name: 'Bitwarden' } });
			throw new Error(`Unexpected request: ${path}`);
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [] }, accountKey);
	const result = await service.create({
		type: 0,
		name: 'Restricted Send',
		text: { text: 'payload' },
		emails: [' Alice@Example.com ', 'BOB@example.com'],
		password: '',
	});
	expect(result.emails).toEqual(['alice@example.com', 'bob@example.com']);
	expect(requests.map(request => request.path)).toEqual([
		'https://vault.example/api/config',
		'https://vault.example/api/sends',
	]);
	expect(requests[1]?.body?.emails).toBe('alice@example.com,bob@example.com');
	expect(requests[1]?.body?.password).toBeNull();
});
test('Send file size limits match Bitwarden and Vaultwarden wire payload limits', () => {
	const fiveHundredMiB = 500 * 1024 * 1024;
	expect(() => assertSendFileSize(fiveHundredMiB, false)).not.toThrow();
	expect(() => assertSendFileSize(fiveHundredMiB + 1, false)).toThrow('500 MiB');
	const maxVaultwardenPlaintext = Math.floor((550_502_400 - 49) / 16) * 16 - 1;
	expect(() => assertSendFileSize(maxVaultwardenPlaintext, true)).not.toThrow();
	expect(() => assertSendFileSize(maxVaultwardenPlaintext + 1, true)).toThrow('525 MiB');
});
test('editing leaves the seed unchanged, omits unchanged password proofs, and never transmits plaintext', async () => {
	let requests = 0;
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (url: unknown, init?: RequestInit) => {
			requests++;
			expect(String(url)).toEndWith('/api/sends/send-id');
			const data = JSON.parse(String(init!.body));
			expect(data.password).toBeUndefined();
			const unwrapped = decrypt(data.key, accountKey);
			expect(unwrapped).toEqual(seed);
			expect(decrypt(data.name, deriveSendKey(unwrapped)).toString()).toBe('Renamed');
			expect(String(init!.body)).not.toContain('Payload');
			return Response.json({ ...encryptedSend(), ...data });
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [encryptedSend()] }, accountKey);
	expect((await service.edit('send-id', { name: 'Renamed' })).name).toBe('Renamed');
	await expect(service.edit('send-id', { type: 1 })).rejects.toThrow('type');
	expect(requests).toBe(1);
});
test('Send edits accept deletion dates in the past like the Vaultwarden update API', async () => {
	const deletionDate = new Date(Date.now() - 60_000).toISOString();
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async (_url: unknown, init?: RequestInit) => {
			const data = JSON.parse(String(init!.body));
			expect(data.deletionDate).toBe(deletionDate);
			return Response.json({ ...encryptedSend(), ...data });
		}) as unknown as typeof fetch,
	});
	const service = new SendService(client, 'owner-token', { sends: [encryptedSend()] }, accountKey);
	await service.edit('send-id', { deletionDate });
});
test('recipient access isolates Send credentials and excludes fragment keys from the wire', async () => {
	const calls: { url: string; init: RequestInit }[] = [];
	const raw = encryptedSend();
	delete raw.key;
	delete raw.notes;
	delete raw.password;
	const transport = (async (url: unknown, init: RequestInit) => {
		calls.push({ url: String(url), init });
		if (String(url).endsWith('/identity/connect/token')) return Response.json({ access_token: 'send-only-token' });
		return Response.json(raw);
	}) as unknown as typeof fetch;
	const result = await receiveSend(link, { password: 'synthetic-password', fetch: transport });
	expect(result.send.text).toMatchObject({ text: 'Payload' });
	expect(result.send.key).toBeUndefined();
	const body = new URLSearchParams(String(calls[0]!.init.body));
	expect(body.get('grant_type')).toBe('send_access');
	expect(body.get('password_hash_b64')).toBe(hashSendPassword('synthetic-password', seed));
	expect(calls[1]!.init.headers).toMatchObject({ Authorization: 'Bearer send-only-token' });
	for (const call of calls) {
		expect(call.url).not.toContain('#');
		expect(String(call.init.body)).not.toContain(seed.toString('base64url'));
		expect(String(call.init.body)).not.toContain('synthetic-password');
	}
});
test('recipient file decrypts authenticated binary data and omits credentials on signed download', async () => {
	const bytes = Buffer.from([0, 255, 128, 1, 0, 10]);
	const raw = { ...encryptedSend(), type: 1, file: { id: 'file-id', fileName: encrypt(Buffer.from('file.bin'), key) } };
	const transport = (async (url: unknown, init: RequestInit) => {
		const path = String(url);
		if (path.endsWith('/identity/connect/token')) return Response.json({ access_token: 'send-only-token' });
		if (path.endsWith('/api/sends/access')) return Response.json(raw);
		if (path.endsWith('/access/file/file-id')) return Response.json({ url: 'https://files.example/signed' });
		expect(path).toBe('https://files.example/signed');
		expect(init.headers).toBeUndefined();
		expect(init.redirect).toBe('error');
		return new Response(new Uint8Array(encryptAttachment(bytes, key)));
	}) as unknown as typeof fetch;
	const result = await receiveSend(link, { fetch: transport });
	expect(result.contents).toEqual(bytes);
	expect(result.fileName).toBe('file.bin');
});
test('invalid fragment URLs fail without requests, and password errors do not expose server text', async () => {
	let count = 0;
	const transport = (async () => {
		count++;
		return Response.json(
			{ send_access_error_type: 'password_hash_b64_required', secret: 'never echo' },
			{ status: 400 },
		);
	}) as unknown as typeof fetch;
	await expect(receiveSend('http://remote.example/#/send/id/key', { fetch: transport })).rejects.toThrow('HTTPS');
	await expect(receiveSend(link.replace(seed.toString('base64url'), 'bad'), { fetch: transport })).rejects.toThrow(
		'fragment',
	);
	expect(count).toBe(0);
	await expect(receiveSend(link, { fetch: transport })).rejects.toBeInstanceOf(SendPasswordRequired);
	expect(count).toBe(1);
	const client = new VaultwardenClient('https://vault.example', {
		fetch: (async () =>
			Response.json(
				{ send_access_error_type: 'server-controlled-secret' },
				{ status: 400 },
			)) as unknown as typeof fetch,
	});
	try {
		await client.sendAccessToken(accessId);
	} catch (error) {
		expect(error).toBeInstanceOf(ApiError);
		expect(String(error)).not.toContain('server-controlled-secret');
	}
});
for (const file of [false, true]) {
	test(`legacy anonymous Send ${file ? 'file' : 'text'} fallback sends proofs without account tokens or fragment keys`, async () => {
		const calls: { path: string; init: RequestInit }[] = [];
		const contents = Buffer.from([0, 255, 128, 10]);
		const raw = file
			? { ...encryptedSend(), type: 1, file: { id: 'file-id', fileName: encrypt(Buffer.from('legacy.bin'), key) } }
			: encryptedSend();
		const transport = (async (url: unknown, init: RequestInit) => {
			const path = String(url);
			calls.push({ path, init });
			if (path.endsWith('/identity/connect/token')) {
				return Response.json({ message: 'Invalid type', object: 'error' }, { status: 400 });
			}
			if (path === 'https://files.example/legacy') {
				expect(init.headers).toBeUndefined();
				expect(init.redirect).toBe('error');
				return new Response(new Uint8Array(encryptAttachment(contents, key)));
			}
			expect(init.headers).not.toHaveProperty('Authorization');
			expect(JSON.parse(String(init.body))).toEqual({ password: hashSendPassword('synthetic-password', seed) });
			if (path.endsWith(`/api/sends/access/${accessId}`)) return Response.json(raw);
			expect(path).toEndWith('/api/sends/send-id/access/file/file-id');
			return Response.json({ url: 'https://files.example/legacy' });
		}) as unknown as typeof fetch;
		const received = await receiveSend(link, { password: 'synthetic-password', fetch: transport });
		if (file) {
			expect(received.contents).toEqual(contents);
			expect(received.fileName).toBe('legacy.bin');
		} else expect(received.send.text).toMatchObject({ text: 'Payload' });
		expect(calls).toHaveLength(file ? 4 : 2);
		for (const call of calls) {
			expect(call.path).not.toContain('#');
			expect(String(call.init.body)).not.toContain('synthetic-password');
			expect(String(call.init.body)).not.toContain(seed.toString('base64url'));
		}
	});
}
test('legacy password challenges remain distinct and unrelated token failures never trigger fallback', async () => {
	for (
		const [status, message, incorrect] of [
			[401, 'Password not provided', false],
			[400, 'Invalid password', true],
		] as const
	) {
		let count = 0;
		const transport = (async () => {
			count++;
			return count === 1
				? Response.json({ message: 'Invalid type' }, { status: 400 })
				: Response.json({ message }, { status });
		}) as unknown as typeof fetch;
		try {
			await receiveSend(link, { fetch: transport });
			throw new Error('Expected challenge.');
		} catch (error) {
			expect(error).toBeInstanceOf(SendPasswordRequired);
			expect((error as SendPasswordRequired).incorrect).toBe(incorrect);
		}
		expect(count).toBe(2);
	}
	for (const status of [400, 401, 429, 500]) {
		let count = 0;
		const transport = (async () => {
			count++;
			return Response.json({ message: 'unrelated synthetic secret' }, { status });
		}) as unknown as typeof fetch;
		await expect(receiveSend(link, { fetch: transport })).rejects.toThrow(`HTTP ${status}`);
		expect(count).toBe(1);
	}
});
test('failed Send file upload rolls back metadata, and failed rollback is distinguished', async () => {
	for (const failDelete of [false, true]) {
		const paths: string[] = [];
		let encryptedName: string;
		const client = new VaultwardenClient('https://vault.example', {
			fetch: (async (url: unknown, init?: RequestInit) => {
				const path = String(url);
				paths.push(path);
				if (path.endsWith('/file/v2')) {
					const data = JSON.parse(String(init!.body));
					encryptedName = data.file.fileName;
					return Response.json({
						fileUploadType: 0,
						sendResponse: { ...data, id: 'new-id', accessId, file: { ...data.file, id: 'file-id' } },
					});
				}
				if (init!.body instanceof FormData) expect((init!.body.get('data') as File).name).toBe(encryptedName);
				if (init!.method === 'DELETE' && !failDelete) return new Response(null, { status: 204 });
				return Response.json({}, { status: 500 });
			}) as unknown as typeof fetch,
		});
		const service = new SendService(
			client,
			'owner-token',
			{ profile: { premiumPersonally: true }, sends: [] },
			accountKey,
		);
		const operation = service.create(
			{ type: 1, name: 'File', file: { fileName: 'payload.bin' } },
			Buffer.from('payload'),
		);
		if (failDelete) await expect(operation).rejects.toBeInstanceOf(SendMutationFailure);
		else await expect(operation).rejects.toThrow('incomplete Send removed');
		expect(paths.at(-1)).toEndWith('/api/sends/new-id');
	}
});
