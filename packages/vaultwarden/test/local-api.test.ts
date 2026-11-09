import { type JsonObject, VaultwardenClient } from '#client';
import { encrypt } from '#crypto';
import { generateSecret } from '#generator';
import { encryptItem } from '#item-codec';
import { createLocalApiHandler, type LocalApiBackend } from '#local-api';
import { deriveSendKey } from '#sends';
import { VaultService } from '#vault-service';
import { expect, test } from 'bun:test';

const id = '00000000-0000-0000-0000-000000000001';
function fixture(fetcher?: typeof fetch) {
	const key = Buffer.alloc(64, 7);
	const snapshot: JsonObject = {
		profile: { id, organizations: [] },
		folders: [],
		collections: [],
		sends: [],
		ciphers: [
			encryptItem(
				{ id, type: 1, name: 'Café fixture', login: { username: 'alice', password: '  secret  ', uris: [] } },
				key,
			),
		],
	};
	let locked = false, calls = 0;
	const syncForces: boolean[] = [];
	const backend: LocalApiBackend = {
		status: async () => ({ status: locked ? 'locked' : 'unlocked' }),
		sync: async force => {
			syncForces.push(force);
			calls++;
		},
		lock: async () => {
			locked = true;
		},
		unlock: async password => {
			if (password === null) {
				throw new Error(
					'Master password is required. Try again in interactive mode or provide a password file or environment variable.',
				);
			}
			if (password !== 'fixture-password') throw new Error('Invalid password.');
			locked = false;
			return 'synthetic-session';
		},
		generate: async options => generateSecret(options),
		run: async (_mutate, operation) => {
			calls++;
			if (locked) throw new Error('Vault is locked.');
			const client = new VaultwardenClient('https://example.com', { fetch: fetcher ?? fetch });
			const vault = new VaultService(client, 'synthetic-access', snapshot, key);
			try {
				return await operation(vault);
			} finally {
				vault.dispose();
			}
		},
	};
	const handler = createLocalApiHandler(backend, { hostname: '127.0.0.1', port: 8087 });
	const request = (path: string, init: RequestInit = {}) => {
		const headers = new Headers(init.headers);
		if (!headers.has('Host')) headers.set('Host', '127.0.0.1:8087');
		return handler(new Request(`http://localhost:8087${path}`, { ...init, headers }));
	};
	return { backend, request, handler, calls: () => calls, syncForces, snapshot, key };
}
test('local API rejects Origin and rebinding Host headers before invoking the backend', async () => {
	const f = fixture();
	const forbidden: Record<string, string>[] = [
		{ Origin: 'https://attacker.example' },
		{ Origin: '' },
		{ Host: 'attacker.example:8087' },
	];
	for (const headers of forbidden) {
		const response = await f.request('/status', { headers });
		expect(response.status).toBe(403);
		expect(response.headers.get('content-type')).toBe('text/plain; charset=utf-8');
		expect(await response.text()).toBe('Forbidden');
	}
	const missingHost = await f.handler(new Request('http://localhost:8087/status'));
	expect(missingHost.status).toBe(403);
	expect(await missingHost.text()).toBe('Forbidden');
	expect(f.calls()).toBe(0);
	for (const host of ['localhost:8087', '127.0.0.1:8087', '[::1]:8087', 'LOCALHOST:8087']) {
		expect((await f.request('/status', { headers: { Host: host } })).status).toBe(200);
	}
	const all = createLocalApiHandler(f.backend, { hostname: 'all' });
	expect((await all(new Request('http://10.0.0.2:8087/status', { headers: { Host: '10.0.0.2:8087' } }))).status).toBe(
		200,
	);
	expect((await all(new Request('http://10.0.0.2:8087/status', { headers: { Origin: 'null' } }))).status).toBe(403);
});
test('local API wraps lists and strings without trimming secret whitespace', async () => {
	const { request } = fixture();
	const response = await request('/list/object/items?search=fixture');
	expect(await response.json()).toMatchObject({
		success: true,
		data: { object: 'list', data: [{ id, name: 'Café fixture' }] },
	});
	expect(await (await request('/list/object/ITEMS?search=fixture')).json()).toMatchObject({
		success: true,
		data: { object: 'list', data: [{ id, name: 'Café fixture' }] },
	});
	expect(await (await request('/LIST/OBJECT/ITEMS/?search=fixture')).json()).toMatchObject({
		success: true,
		data: { object: 'list', data: [{ id, name: 'Café fixture' }] },
	});
	expect((await request('/STATUS/')).status).toBe(200);
	expect((await request('/%73tatus')).status).toBe(404);
	expect(await (await request(`/object/password/${id}`)).json()).toEqual({
		success: true,
		data: { object: 'string', data: '  secret  ' },
	});
	expect(await (await request(`/object/ITEM/${id.toUpperCase()}`)).json()).toMatchObject({
		success: true,
		data: { object: 'item', id },
	});
	const unknown = await request('/unknown');
	expect(unknown.status).toBe(404);
	expect(unknown.headers.get('content-type')).toMatch(/text\/plain/);
	expect(await unknown.text()).toBe('Not Found');
	expect((await request('/object/item/%ZZ')).status).toBe(400);
	for (const value of ['garbage', '1']) {
		expect(await (await request(`/list/object/items?trash=${value}`)).json()).toMatchObject({
			data: { data: [{ id }] },
		});
	}
	expect(await (await request('/list/object/items?trash=TRUE')).json()).toMatchObject({ data: { data: [] } });
	const generated = await (await request('/generate?length=32&number=true')).json();
	expect(generated.data.data).toHaveLength(32);
	const unambiguous = await (await request(
		'/generate?length=256&number=true&uppercase=false&lowercase=false&special=false&ambiguous=true',
	)).json();
	expect(unambiguous.data.data).toMatch(/^[2-9]{256}$/);
	const fractional = await (await request('/generate?length=5.9&number=true&minNumber=2.9')).json();
	expect(fractional.data.data).toHaveLength(5);
	expect(fractional.data.data.match(/\d/g)!.length).toBeGreaterThanOrEqual(2);
	const malformed = await (await request('/generate?length=invalid')).json();
	expect(malformed.data.data).toHaveLength(14);
	const excessive = await request('/generate?length=9007199254740991');
	expect(excessive.status).toBe(400);
	expect(await excessive.json()).toEqual({ success: false, message: 'Invalid password length.' });
});
test('local API ignores whitespace-only URL filters like bw serve', async () => {
	const f = fixture(), calls: string[] = [];
	f.backend.run = async (_mutate, operation) =>
		operation({
			listItems: () => {
				calls.push('list');
				return [];
			},
			listItemsForUrl: (url: string) => {
				calls.push(`url:${url}`);
				return [];
			},
		} as unknown as VaultService);
	const whitespace = await f.request('/list/object/items?url=%20%20%20');
	expect(whitespace.status).toBe(200);
	const valid = await f.request('/list/object/items?url=https%3A%2F%2Fexample.test');
	expect(valid.status).toBe(200);
	expect(calls).toEqual(['list', 'url:https://example.test']);
});
test('get uri returns a whitespace-only first URI like the pinned CLI', async () => {
	const f = fixture();
	const uriItemId = '00000000-0000-0000-0000-000000000002';
	f.snapshot.ciphers = [
		encryptItem({ id: uriItemId, type: 1, name: 'Whitespace URI', login: { uris: [{ uri: '   ' }] } }, f.key),
	];
	const response = await f.request(`/object/uri/${uriItemId}`);
	expect(response.status).toBe(200);
	expect(await response.json()).toEqual({ success: true, data: { object: 'string', data: '   ' } });
});
test('Vaultwarden move rejects inaccessible collection IDs before mutation with the pinned CLI error', async () => {
	const fetcher = (async input => {
		if (new URL(input instanceof Request ? input.url : input).pathname === '/api/config') {
			return Response.json({ server: { name: 'Vaultwarden' } });
		}
		throw new Error('Unexpected Vaultwarden request.');
	}) as typeof fetch;
	const f = fixture(fetcher);
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const collectionId = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
	f.snapshot.profile = { id, organizations: [{ id: organizationId, type: 2 }] };
	f.snapshot.collections = [{
		id: collectionId,
		organizationId,
		readOnly: true,
		manage: false,
	}];
	for (const invalidId of [123, collectionId.toUpperCase()]) {
		const response = await f.request(`/move/${id}/${organizationId}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify([invalidId]),
		});
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({
			success: false,
			message: 'You do not have permission to add items to this collection.',
		});
	}
});
test('local API list search matches bw name-only and ignores whitespace-only queries', async () => {
	const f = fixture();
	const organizationId = '11111111-1111-1111-1111-111111111111';
	f.snapshot.profile = {
		id,
		organizations: [{ id: organizationId, status: 2, name: 'Example organization', email: 'billing@example.test' }],
	};
	const byName = await f.request('/list/object/organizations?search=example');
	expect(await byName.json()).toMatchObject({ data: { data: [{ name: 'Example organization' }] } });
	const byEmail = await f.request('/list/object/organizations?search=billing%40example.test');
	expect(await byEmail.json()).toMatchObject({ data: { data: [] } });
	const whitespace = await f.request('/list/object/organizations?search=%20%20%20');
	expect(await whitespace.json()).toMatchObject({
		data: { data: [{ name: 'Example organization' }] },
	});
});
test('local API item search follows bw per-term display, URI-hostname, and notes matching', async () => {
	const f = fixture();
	const secondId = 'abcdefab-0000-0000-0000-000000000002';
	(f.snapshot.ciphers as JsonObject[]).push(encryptItem({
		id: secondId,
		type: 1,
		name: 'Alpha',
		notes: 'notes-only-marker',
		login: { username: 'Beta', password: 'secret', uris: [{ uri: 'https://example.test/path-only-marker' }] },
	}, f.key));
	const search = async (query: string) => {
		const response = await f.request(`/list/object/items?search=${encodeURIComponent(query)}`);
		return (await response.json()).data.data.map((item: JsonObject) => item.id);
	};
	expect(await search('cafe')).toEqual([id]);
	expect(await search('   ')).toEqual([id, secondId]);
	expect(await search('\u0301')).toEqual([]);
	expect(await search('Alpha')).toEqual([secondId]);
	expect(await search('notes-only-marker')).toEqual([secondId]);
	expect(await search('example.test')).toEqual([secondId]);
	expect(await search('path-only-marker')).toEqual([]);
	expect(await search('Alpha Beta')).toEqual([secondId]);
	expect(await search('Alpha notes-only-marker')).toEqual([secondId]);
	expect(await search('Alpha missing-term')).toEqual([]);
	expect(await search(secondId.slice(0, 8))).toEqual([secondId]);
});
test('local API object lookups use case-insensitive substring matching and report ambiguity', async () => {
	const f = fixture();
	f.snapshot.profile = {
		id,
		organizations: [{ id: '11111111-1111-1111-1111-111111111111', status: 2, name: 'Engineering Org' }],
	};
	f.snapshot.folders = [
		{ id: 'folder-one', name: encrypt(Buffer.from('Engineering Folder'), f.key) },
		{ id: 'folder-two', name: encrypt(Buffer.from('Engineering Archive'), f.key) },
	];
	f.snapshot.collections = [{
		id: 'collection-one',
		name: encrypt(Buffer.from('Engineering Collection'), f.key),
	}];
	const folder = await (await f.request('/object/folder/FOLDER')).json();
	expect(folder).toMatchObject({
		success: true,
		data: { object: 'folder', id: 'folder-one', name: 'Engineering Folder' },
	});
	const collection = await (await f.request('/object/collection/COLLECTION')).json();
	expect(collection).toMatchObject({
		success: true,
		data: { object: 'collection', id: 'collection-one', name: 'Engineering Collection' },
	});
	const organization = await (await f.request('/object/organization/engineering')).json();
	expect(organization).toMatchObject({ success: true, data: { object: 'organization', name: 'Engineering Org' } });
	const ambiguous = await f.request('/object/folder/engineering');
	expect(ambiguous.status).toBe(400);
	expect(await ambiguous.json()).toMatchObject({
		success: false,
		message: 'More than one result was found. Try getting a specific object by `id` instead. '
			+ 'The following objects were found:\nfolder-one\nfolder-two',
	});
});
test('local API Send object lookup requires a GUID like bw serve', async () => {
	const f = fixture();
	const response = await f.request('/object/send/Shared%20Send');
	expect(response.status).toBe(400);
	expect(await response.json()).toMatchObject({
		success: false,
		message: '`Shared Send` is not a GUID.',
	});
});
test('local API reports the reference unknown-object message across object routes', async () => {
	const f = fixture();
	const requests: [string, RequestInit?][] = [
		['/list/object/missing'],
		['/object/missing/id'],
		['/object/missing', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }],
		['/object/missing/id', { method: 'DELETE' }],
		['/archive/missing/id', { method: 'POST' }],
	];
	for (const [path, init] of requests) {
		const response = await f.request(path, init);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ success: false, message: 'Unknown object.' });
	}
});
test('local API maps missing object and secret lookups to the bw Serve not-found response', async () => {
	const f = fixture();
	for (
		const path of [
			'/object/item/00000000-0000-0000-0000-000000000099',
			'/object/password/00000000-0000-0000-0000-000000000099',
			'/object/folder/no-such-folder',
			'/object/collection/no-such-collection',
			'/object/organization/no-such-organization',
		]
	) {
		const response = await f.request(path);
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ success: false, message: 'Not found.' });
	}
	const restricted = await f.request('/object/password/not-an-item');
	expect(await restricted.json()).toEqual({ success: false, message: 'Not found.' });
});
test('local API secret reads return hidden-field errors and enforce TOTP entitlement', async () => {
	const f = fixture();
	f.snapshot.profile = {
		id,
		premium: false,
		premiumPersonally: false,
		premiumFromOrganization: false,
		organizations: [],
	};
	const profile = f.snapshot.profile as JsonObject;
	f.snapshot.ciphers = [{
		...encryptItem(
			{ type: 1, name: 'Hidden', login: { password: 'hidden-password', totp: 'JBSWY3DPEHPK3PXP' } },
			f.key,
		),
		id: 'hidden-item',
		viewPassword: false,
	}, {
		...encryptItem({ type: 1, name: 'TOTP', login: { totp: 'JBSWY3DPEHPK3PXP' } }, f.key),
		id: 'totp-item',
	}];
	for (
		const [field, message] of [
			['password', 'No password available for this login.'],
			['totp', 'No TOTP available for this login.'],
			['exposed', 'No password available for this login.'],
		] as const
	) {
		const response = await f.request(`/object/${field}/hidden-item`);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ success: false, message });
	}
	const denied = await f.request('/object/totp/totp-item');
	expect(denied.status).toBe(400);
	expect(await denied.json()).toMatchObject({
		success: false,
		message: 'Premium status is required to use this feature.',
	});
	profile.premiumPersonally = true;
	const allowed = await f.request('/object/totp/totp-item');
	expect(allowed.status).toBe(200);
	expect((await allowed.json()).data.data).toMatch(/^\d{6}$/);
});
test('local API accepts bw camelCase ID query aliases and returns IDs for ambiguous lookups', async () => {
	const f = fixture();
	const ciphers = f.snapshot.ciphers as JsonObject[];
	ciphers[0]!.folderId = 'folder-id';
	ciphers[0]!.collectionIds = ['collection-id'];
	const list = await (await f.request(
		'/list/object/items?folderId=folder-id&collectionId=collection-id',
	)).json();
	expect(list.data.data).toHaveLength(1);

	ciphers.push(encryptItem({
		id: '00000000-0000-0000-0000-000000000002',
		type: 1,
		name: 'Café fixture duplicate',
		login: { username: 'bob', password: 'other-secret', uris: [] },
	}, f.key));
	const ambiguous = await f.request('/object/item/Café%20fixture');
	expect(ambiguous.status).toBe(400);
	expect(await ambiguous.json()).toEqual({
		success: false,
		message: 'More than one result was found. Try getting a specific object by `id` instead. '
			+ 'The following objects were found:\n00000000-0000-0000-0000-000000000001\n00000000-0000-0000-0000-000000000002',
		data: ['00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002'],
	});
});
test('local API mutation responses omit undefined data like bw Serve', async () => {
	const f = fixture();
	f.backend.run = async (_mutate, operation) =>
		operation({
			deleteItem: async () => {},
			restoreItem: async () => {},
			archiveItem: async () => {},
			confirmMember: async () => {},
		} as unknown as VaultService);
	for (
		const [path, init] of [
			[`/object/item/${id}`, { method: 'DELETE' }],
			[`/restore/item/${id}`, { method: 'POST' }],
			[`/archive/item/${id}`, { method: 'POST' }],
			[`/confirm/org-member/${id}?organizationid=${id}`, { method: 'POST' }],
		] as const
	) {
		const response = await f.request(path, init);
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ success: true });
	}
});
test('local API list filters match bw object-specific behavior', async () => {
	const f = fixture();
	f.snapshot.ciphers = [{
		...encryptItem({ type: 1, name: 'Folder filter item', login: { username: 'alice' } }, f.key),
		id: 'folder-filter-item',
		folderId: 'folder-one',
	}];
	f.snapshot.profile = {
		id,
		organizations: [{ id: 'org-one', status: 2, name: 'First' }, { id: 'org-two', status: 2, name: 'Second' }],
	};
	f.snapshot.folders = [{ id: 'folder', name: encrypt(Buffer.from('Private folder'), f.key) }];
	const matchedFolder = await (await f.request('/list/object/items?folderid=folder-one')).json();
	expect(matchedFolder.data.data.map((value: JsonObject) => value.id)).toEqual(['folder-filter-item']);
	const repeatedFolder = await (await f.request('/list/object/items?folderid=folder-one&folderid=other')).json();
	expect(repeatedFolder.data.data).toEqual([]);
	const camelFallback = await (await f.request('/list/object/items?folderid=&folderId=folder-one')).json();
	expect(camelFallback.data.data.map((value: JsonObject) => value.id)).toEqual(['folder-filter-item']);
	const folders = await (await f.request('/list/object/folders?organizationid=missing')).json();
	expect(folders.data.data.map((value: JsonObject) => value.name)).toEqual(['Private folder']);
	const organizations = await (await f.request('/list/object/organizations?organizationid=org-one')).json();
	expect(organizations.data.data).toHaveLength(2);
	f.backend.run = async (_mutate, operation) =>
		operation({
			listCollections: () => [
				{ id: 'first', organizationId: 'org-one', name: 'First collection' },
				{ id: 'second', organizationId: 'org-two', name: 'Second collection' },
			],
		} as unknown as VaultService);
	const collections = await (await f.request('/list/object/collections?organizationid=org-one')).json();
	expect(collections.data.data.map((value: JsonObject) => value.id)).toEqual(['first']);
	const uppercaseCollections = await (await f.request('/list/object/collections?organizationid=ORG-ONE')).json();
	expect(uppercaseCollections.data.data).toEqual([]);
});
test('local API lists Sends through both reference Serve routes', async () => {
	const f = fixture();
	for (const path of ['/list/object/send', '/send/list']) {
		expect(await (await f.request(path)).json()).toMatchObject({
			success: true,
			data: { object: 'list', data: [] },
		});
	}
	const uppercaseObject = await f.request('/list/object/SEND');
	expect(uppercaseObject.status).toBe(400);
	expect(await uppercaseObject.json()).toEqual({ success: false, message: 'Unknown object.' });
});
test('local API only dispatches exact lowercase Send object routes to Send commands', async () => {
	const f = fixture();
	let sendCalls = 0;
	const sends = {
		get: () => {
			sendCalls++;
			return { id, name: 'Synthetic Send' };
		},
		create: () => {
			sendCalls++;
			return { id, name: 'Synthetic Send' };
		},
		edit: () => {
			sendCalls++;
			return { id, name: 'Synthetic Send' };
		},
		delete: () => {
			sendCalls++;
		},
	};
	f.backend.run = async (_mutate, operation) => operation({ sends } as unknown as VaultService);
	const json = { headers: { 'Content-Type': 'application/json' } };
	const requests: [string, RequestInit][] = [
		[`/object/SEND/${id}`, { method: 'GET' }],
		[
			'/object/SEND',
			{ ...json, method: 'POST', body: JSON.stringify({ type: 0, deletionDate: new Date(Date.now() + 86400000) }) },
		],
		[`/object/SEND/${id}`, { ...json, method: 'PUT', body: '{}' }],
		[`/object/SEND/${id}`, { method: 'DELETE' }],
	];
	for (const [path, init] of requests) {
		const response = await f.request(path, init);
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ success: false, message: 'Unknown object.' });
	}
	expect(sendCalls).toBe(0);
	expect((await f.request(`/object/send/${id}`)).status).toBe(200);
	expect(sendCalls).toBe(1);
});
test('local API Send search includes secondary fields after name matches', async () => {
	const f = fixture();
	const makeSend = (id: string, name: string, notes: string, payload: string): JsonObject => {
		const seed = Buffer.alloc(16, id.length), key = deriveSendKey(seed);
		try {
			return {
				id,
				accessId: 'send-access-id',
				type: 0,
				key: encrypt(seed, f.key),
				name: encrypt(Buffer.from(name), key),
				notes: encrypt(Buffer.from(notes), key),
				text: { text: encrypt(Buffer.from(payload), key), hidden: false },
				deletionDate: new Date(Date.now() + 86400000).toISOString(),
				disabled: false,
			};
		} finally {
			key.fill(0);
			seed.fill(0);
		}
	};
	f.snapshot.sends = [
		makeSend('named-send', 'Needle named', 'unrelated', 'unrelated'),
		makeSend('secondary-send', 'Other name', 'Needle in notes', 'Needle in text'),
	];
	const response = await f.request('/send/list?search=needle');
	expect(response.status).toBe(200);
	const result = await response.json();
	expect(result.data.data.map((send: JsonObject) => send.id)).toEqual(['named-send', 'secondary-send']);
});
test('local API Send search matches UUID prefixes regardless of letter case', async () => {
	const f = fixture();
	const sendId = 'ABCDEF00-0000-0000-0000-000000000001';
	const seed = Buffer.alloc(16, 4), key = deriveSendKey(seed);
	try {
		f.snapshot.sends = [{
			id: sendId,
			accessId: 'send-access-id',
			type: 0,
			key: encrypt(seed, f.key),
			name: encrypt(Buffer.from('Mixed-case ID'), key),
			text: { text: encrypt(Buffer.from('payload'), key), hidden: false },
			deletionDate: new Date(Date.now() + 86400000).toISOString(),
			disabled: false,
		}];
	} finally {
		key.fill(0);
		seed.fill(0);
	}
	const response = await f.request('/send/list?search=abcdef00');
	expect(response.status).toBe(200);
	expect((await response.json()).data.data.map((send: JsonObject) => send.id)).toEqual([sendId]);
});
test('local API unlocks from JSON and serializes lock/unlock/read ordering', async () => {
	const f = fixture();
	const { backend, request } = f;
	const lastSync = '2026-10-21T12:00:00.000Z';
	backend.status = async () => ({ status: 'unlocked', lastSync });
	const lock = await request('/lock', { method: 'POST' });
	expect(await lock.json()).toMatchObject({
		success: true,
		data: { object: 'message', title: 'Your vault is locked.', message: null, noColor: false },
	});
	expect((await request('/list/object/items')).status).toBe(400);
	expect(
		(await request('/unlock?passwordEnv=HOME&passwordFile=/etc/passwd', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{}',
		})).status,
	).toBe(400);
	const unlock = request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password: 'fixture-password' }),
	});
	const list = request('/list/object/items');
	expect(await (await unlock).json()).toMatchObject({
		success: true,
		data: {
			object: 'message',
			title: 'Your vault is now unlocked!',
			message: expect.stringContaining('$ bw list items --session synthetic-session'),
			raw: 'synthetic-session',
		},
	});
	expect((await list).status).toBe(200);
	expect(await (await request('/status')).json()).toMatchObject({
		data: { object: 'template', template: { status: 'unlocked' } },
	});
	const last = await request('/sync?last=true', { method: 'POST' });
	expect(await last.json()).toEqual({
		success: true,
		data: { object: 'string', data: lastSync },
	});
	expect(f.syncForces).toEqual([]);
	const syncMessage = await request('/sync', { method: 'POST' });
	expect(await syncMessage.json()).toMatchObject({
		success: true,
		data: { object: 'message', title: 'Syncing complete.', message: null, noColor: false },
	});
	const forcedSync = await request('/sync?force=true', { method: 'POST' });
	expect(forcedSync.status).toBe(200);
	await request('/sync?force=garbage', { method: 'POST' });
	expect(f.syncForces).toEqual([false, true, false]);
	backend.sync = async () => {
		throw new Error('synthetic sync failure');
	};
	const failedSync = await request('/sync', { method: 'POST' });
	expect(failedSync.status).toBe(400);
	expect((await failedSync.json()).message).toBe('Syncing failed: synthetic sync failure');
});
test('local API rejects non-string unlock passwords before calling the backend', async () => {
	const f = fixture();
	let unlockCalls = 0;
	f.backend.unlock = async () => {
		unlockCalls++;
		return 'synthetic-session';
	};
	const response = await f.request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({ password: { value: 'not a password string' } }),
	});
	expect(response.status).toBe(400);
	expect(await response.json()).toEqual({ success: false, message: 'Invalid request.' });
	expect(unlockCalls).toBe(0);
});
test('local API parses URL-encoded form bodies like the pinned Serve body parser', async () => {
	const { request } = fixture();
	const response = await request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ password: 'fixture-password' }),
	});
	expect(response.status).toBe(200);
	expect(await response.json()).toMatchObject({
		success: true,
		data: {
			object: 'message',
			title: 'Your vault is now unlocked!',
			message: expect.stringContaining('$ bw list items --session synthetic-session'),
		},
	});
});
test('local API reads form keys beyond the qs nesting depth as literal keys', async () => {
	const f = fixture();
	let received: unknown;
	f.backend.run = async (_mutate, operation) =>
		operation({
			createCollection: async (_organizationId: string, input: JsonObject) => {
				received = input;
				return input;
			},
		} as unknown as VaultService);
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const response = await f.request(`/object/org-collection?organizationid=${organizationId}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: 'name=Deep&groups%5B0%5D%5B1%5D%5B2%5D%5B3%5D%5B4%5D%5B5%5D%5B6%5D=value',
	});
	expect(response.status).toBe(200);
	expect(JSON.stringify(received)).toContain('"[5][6]":"value"');
});
test('local API treats qs arrayLimit as an inclusive index boundary', async () => {
	const f = fixture();
	let received: unknown;
	f.backend.run = async (_mutate, operation) =>
		operation({
			createCollection: async (_organizationId: string, input: JsonObject) => {
				received = input;
				return input;
			},
		} as unknown as VaultService);
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const response = await f.request(`/object/org-collection?organizationid=${organizationId}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: 'name=Indexed&groups%5B20%5D%5Bid%5D=group-id',
	});
	expect(response.status).toBe(200);
	expect((received as JsonObject).groups).toEqual([{ id: 'group-id' }]);
	const aboveLimit = await f.request(`/object/org-collection?organizationid=${organizationId}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: 'name=Indexed&groups%5B21%5D%5Bid%5D=group-id',
	});
	expect(aboveLimit.status).toBe(200);
	expect((received as JsonObject).groups).toEqual({ '21': { id: 'group-id' } });
});
test('local API compacts sparse form arrays like qs', async () => {
	const f = fixture();
	let received: unknown;
	f.backend.run = async (_mutate, operation) =>
		operation({
			createCollection: async (_organizationId: string, input: JsonObject) => {
				received = input;
				return input;
			},
		} as unknown as VaultService);
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const response = await f.request(`/object/org-collection?organizationid=${organizationId}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: 'groups%5B2%5D%5Bid%5D=third&groups%5B0%5D%5Bid%5D=first',
	});
	expect(response.status).toBe(200);
	expect((received as JsonObject).groups).toEqual([{ id: 'first' }, { id: 'third' }]);
});
test('local API form parsing drops Object prototype keys but accepts the ordinary prototype key', async () => {
	const f = fixture();
	let received: unknown;
	f.backend.run = async (_mutate, operation) =>
		operation({
			createCollection: async (_organizationId: string, input: JsonObject) => {
				received = input;
				return input;
			},
		} as unknown as VaultService);
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const response = await f.request(`/object/org-collection?organizationid=${organizationId}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: 'name=Indexed&prototype=allowed&toString=blocked&constructor=blocked&hasOwnProperty=blocked',
	});
	expect(response.status).toBe(200);
	const data = received as JsonObject;
	expect(data.prototype).toBe('allowed');
	expect(Object.hasOwn(data, 'toString')).toBe(false);
	expect(Object.hasOwn(data, 'constructor')).toBe(false);
	expect(Object.hasOwn(data, 'hasOwnProperty')).toBe(false);
});
test('local API applies the pinned body parser form limit before invoking unlock', async () => {
	const f = fixture();
	let unlockCalls = 0;
	f.backend.unlock = async () => {
		unlockCalls++;
		return 'synthetic-session';
	};
	const response = await f.request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: `password=${'a'.repeat(56 * 1024)}`,
	});
	expect(response.status).toBe(400);
	expect(unlockCalls).toBe(0);
});
test('local API treats repeated boolean query parameters as false like bw serve', async () => {
	const f = fixture();
	f.backend.status = async () => ({ status: 'unlocked', lastSync: '2026-01-02T03:04:05.000Z' });
	const response = await f.request('/sync?last=true&last=false', { method: 'POST' });
	expect(await response.json()).toMatchObject({
		success: true,
		data: { object: 'message', title: 'Syncing complete.' },
	});
	expect(f.syncForces).toEqual([false]);
	expect(f.calls()).toBe(1);
});

test('local API accepts the JSON media types supported by bw serve', async () => {
	const { request } = fixture();
	for (
		const contentType of [
			'application/json-patch+json',
			'application/vnd.api+json',
			'application/csp-report',
			'application/scim+json',
		]
	) {
		const response = await request('/unlock', {
			method: 'POST',
			headers: { 'Content-Type': contentType },
			body: JSON.stringify({ password: 'fixture-password' }),
		});
		expect(response.status).toBe(200);
	}
	const empty = await request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
	});
	expect(empty.status).toBe(400);
	expect(await empty.json()).toMatchObject({
		success: false,
		message:
			'Master password is required. Try again in interactive mode or provide a password file or environment variable.',
	});
});
test('local API ignores text/plain bodies like the default koa-bodyparser configuration', async () => {
	const { request } = fixture();
	const response = await request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'text/plain' },
		body: JSON.stringify({ password: 'fixture-password' }),
	});
	expect(response.status).toBe(400);
	expect(await response.json()).toEqual({
		success: false,
		message:
			'Master password is required. Try again in interactive mode or provide a password file or environment variable.',
	});
});
test('malformed and oversized JSON fail without invoking mutations and do not poison the request queue', async () => {
	const f = fixture();
	for (const body of ['{"password":"synthetic-secret",', 'x'.repeat(1024 * 1024 + 1)]) {
		const result = await f.request('/object/item', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body,
		});
		expect(result.status).toBe(400);
		expect((await result.text()).includes('synthetic-secret')).toBe(false);
	}
	expect(f.calls()).toBe(0);
	expect((await f.request('/sync', { method: 'POST' })).status).toBe(200);
});
test('local API rejects scalar JSON bodies under koa-bodyparser strict mode', async () => {
	const f = fixture();
	const response = await f.request('/unlock', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify('synthetic-secret'),
	});
	expect(response.status).toBe(400);
	expect(await response.json()).toEqual({ success: false, message: 'Invalid request.' });
	expect(f.calls()).toBe(0);
});
test('local API organization collection mutations accept body organization IDs and reject conflicts', async () => {
	const f = fixture(), calls: { method: string; id?: string; organizationId: string }[] = [];
	let formInput: JsonObject | undefined;
	class CaptureVault extends VaultService {
		override async createCollection(organizationId: string, input: JsonObject): Promise<JsonObject> {
			calls.push({ method: 'POST', organizationId });
			if (input.name === 'Form collection') formInput = input;
			return { id: 'created' };
		}
		override async editCollection(organizationId: string, id: string, _input: JsonObject): Promise<JsonObject> {
			calls.push({ method: 'PUT', id, organizationId });
			return { id };
		}
		override async deleteCollection(organizationId: string, id: string): Promise<void> {
			calls.push({ method: 'DELETE', id, organizationId });
		}
	}
	f.backend.run = async (_mutate, operation) => {
		const vault = new CaptureVault(new VaultwardenClient('https://example.com'), 'synthetic-access', f.snapshot, f.key);
		try {
			return await operation(vault);
		} finally {
			vault.dispose();
		}
	};
	const organizationId = '11111111-1111-1111-1111-111111111111';
	const body = JSON.stringify({ organizationId, name: 'Collection' });
	const create = await f.request('/object/org-collection', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body,
	});
	expect(create.status).toBe(200);
	const uppercaseCreate = await f.request(`/object/org-collection?organizationid=${organizationId.toUpperCase()}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body,
	});
	expect(uppercaseCreate.status).toBe(200);
	const formCreate = await f.request(`/object/org-collection?organizationid=${organizationId}`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			name: 'Form collection',
			'groups[0][id]': 'group-id',
			'users[0][id]': 'member-id',
		}),
	});
	expect(formCreate.status).toBe(200);
	expect(formInput).toMatchObject({
		name: 'Form collection',
		groups: [{ id: 'group-id' }],
		users: [{ id: 'member-id' }],
	});
	const edit = await f.request('/object/org-collection/22222222-2222-2222-2222-222222222222', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json' },
		body,
	});
	expect(edit.status).toBe(200);
	const conflict = await f.request(
		`/object/org-collection/22222222-2222-2222-2222-222222222222?organizationId=33333333-3333-3333-3333-333333333333`,
		{ method: 'PUT', headers: { 'Content-Type': 'application/json' }, body },
	);
	expect(conflict.status).toBe(400);
	expect((await conflict.json()).message).toContain('does not match');
	for (
		const suffix of [
			'/object/org-collection/not-a-guid?organizationid=' + organizationId,
			'/object/org-collection/22222222-2222-2222-2222-222222222222?organizationId=not-a-guid',
		]
	) {
		const invalidDelete = await f.request(suffix, { method: 'DELETE' });
		expect(invalidDelete.status).toBe(400);
		expect((await invalidDelete.json()).message).toContain('is not a GUID.');
	}
	expect(calls).toEqual([
		{ method: 'POST', organizationId },
		{ method: 'POST', organizationId },
		{ method: 'POST', organizationId },
		{ method: 'PUT', id: '22222222-2222-2222-2222-222222222222', organizationId },
	]);
});
test('local API organization routes validate required GUID options with bw-compatible messages', async () => {
	const f = fixture(), collectionId = '22222222-2222-2222-2222-222222222222';
	for (const path of ['/list/object/org-collections', '/list/object/org-members']) {
		const response = await f.request(path);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ message: '`organizationid` option is required.' });
	}
	for (
		const path of [
			'/list/object/org-collections?organizationid=invalid',
			'/list/object/org-members?organizationid=invalid',
			`/object/org-collection/${collectionId}?organizationid=invalid`,
		]
	) {
		const response = await f.request(path);
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ message: '`invalid` is not a GUID.' });
	}
	const getWithoutOrganization = await f.request(`/object/org-collection/${collectionId}`);
	expect(await getWithoutOrganization.json()).toMatchObject({
		message: '`organizationid` option is required.',
	});
	const deleteWithoutOrganization = await f.request(`/object/org-collection/${collectionId}`, { method: 'DELETE' });
	expect(await deleteWithoutOrganization.json()).toMatchObject({
		message: '`organizationid` options is required.',
	});
});
test('local API attachment and member routes return bw required-option messages', async () => {
	const f = fixture();
	for (
		const [path, method, message] of [
			['/object/attachment/file-id', 'GET', '--itemid <itemid> required.'],
			['/object/attachment/file-id', 'DELETE', '`itemid` option is required.'],
			['/confirm/org-member/member-id', 'POST', '--organizationid <organizationid> required.'],
		] as const
	) {
		const response = await f.request(path, { method });
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ success: false, message });
	}
});
test('attachment downloads return their bytes after the vault buffer is wiped', async () => {
	const f = fixture(), contents = Buffer.alloc(131072, 171);
	let fileName = 'private/path/fixture\r\n.bin';
	class DownloadVault extends VaultService {
		override async getAttachment() {
			return { fileName, contents };
		}
	}
	f.backend.run = async (_mutate, action) =>
		action(new DownloadVault(new VaultwardenClient('https://example.com'), 'synthetic', f.snapshot, f.key));
	const response = await f.request(`/object/attachment/file-id?itemId=${id}`);
	expect(response.status).toBe(200);
	expect(response.headers.get('Content-Disposition')).toBe("attachment; filename*=UTF-8''fixture%0D%0A.bin");
	expect(response.headers.get('Content-Disposition')).not.toContain('private/path');
	expect(Buffer.from(await response.arrayBuffer()).equals(Buffer.alloc(131072, 171))).toBe(true);
	expect(contents.every(value => value === 0)).toBe(true);
	fileName = 'private/path/résumé 😀.bin';
	const unicode = await f.request(`/object/attachment/file-id?itemid=${id}`);
	expect(unicode.headers.get('Content-Disposition')).toBe(
		'attachment; filename="résumé ??.bin"; filename*=UTF-8\'\'r%C3%A9sum%C3%A9%20%F0%9F%98%80.bin',
	);
});
test('local API multipart parsing does not expand attacker-controlled array indices', async () => {
	let fetchCalls = 0;
	const fetcher = (async () => {
		fetchCalls++;
		throw new Error('The malformed upload must not reach the vault server.');
	}) as unknown as typeof fetch;
	const f = fixture(fetcher);
	const form = new FormData();
	form.append('file', new Blob(['synthetic attachment']), 'fixture.bin');
	form.append('cipher[999999999999999999999999999999]', 'synthetic value');
	const response = await f.request('/attachment', { method: 'POST', body: form });
	expect(response.status).toBe(400);
	expect(await response.json()).toEqual({
		success: false,
		message: '`itemid` option is required.',
	});
	expect(fetchCalls).toBe(0);
}, 2000);
test('local API accepts only one multipart upload named file', async () => {
	for (const names of [['file', 'file'], ['file', 'unexpected']] as const) {
		let fetchCalls = 0;
		const fetcher = (async () => {
			fetchCalls++;
			throw new Error('Invalid multipart uploads must not reach the vault server.');
		}) as unknown as typeof fetch;
		const f = fixture(fetcher), form = new FormData();
		for (const [index, name] of names.entries()) {
			form.append(name, new Blob([`synthetic attachment ${index}`]), `fixture-${index}.bin`);
		}
		const response = await f.request(`/attachment?itemid=${id}`, { method: 'POST', body: form });
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({
			success: false,
			message: 'Exactly one multipart file field named `file` is required.',
		});
		expect(fetchCalls).toBe(0);
	}
}, 2000);
test('local API uses native template envelopes, object discriminators, HEAD and OPTIONS semantics', async () => {
	const { request } = fixture();
	expect(await (await request('/status')).json()).toEqual({
		success: true,
		data: { object: 'template', template: { status: 'unlocked' } },
	});
	const pretty = await request('/status?pretty');
	expect(await pretty.text()).toBe(`{
  "success": true,
  "data": {
    "object": "template",
    "template": {
      "status": "unlocked"
    }
  }
}`);
	expect(await (await request('/object/template/item')).json()).toMatchObject({
		data: { object: 'template', template: { type: 1 } },
	});
	expect(await (await request(`/object/item/${id}`)).json()).toMatchObject({ data: { object: 'item', id } });
	const head = await request('/status', { method: 'HEAD' });
	expect(head.status).toBe(200);
	expect(await head.text()).toBe('');
	const options = await request(`/object/item/${id}`, { method: 'OPTIONS' });
	expect(options.status).toBe(200);
	expect(options.headers.get('Allow')).toBe('HEAD, GET, PUT, DELETE');
	const unsupported = await request('/status', { method: 'DELETE' });
	expect(unsupported.status).toBe(405);
	expect(unsupported.headers.get('Allow')).toBe('HEAD, GET');
	expect(await unsupported.text()).toBe('Method Not Allowed');
	const statusOptions = await request('/status', { method: 'OPTIONS' });
	expect(statusOptions.status).toBe(200);
	expect(statusOptions.headers.get('Allow')).toBe('HEAD, GET');
	expect(await statusOptions.text()).toBe('');
});
test('local API only returns new item templates when the connected Vaultwarden release supports them', async () => {
	for (const [version, supported] of [['1.36.0', false], ['1.37.4', true]] as const) {
		const fetcher = (async input => {
			const url = String(input);
			if (url.endsWith('/api/config')) return Response.json({ server: { name: 'Vaultwarden' } });
			if (url.endsWith('/api/version')) return Response.json(version);
			throw new Error(`Unexpected server request: ${url}`);
		}) as typeof fetch;
		const { request } = fixture(fetcher);
		const response = await request('/object/template/item.bankaccount');
		if (supported) {
			expect(response.status).toBe(200);
			expect(await response.json()).toMatchObject({
				data: { template: { accountNumber: '000123456789', bankName: 'Acme Bank' } },
			});
		} else {
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({
				success: false,
				message: 'Bank account item type is not available.',
			});
		}
	}
});
test('local API rejects file Send creation without making vault API requests', async () => {
	let fetchCalls = 0;
	const fetcher = (async () => {
		fetchCalls++;
		throw new Error('File Send requests must not reach the server.');
	}) as unknown as typeof fetch;
	const f = fixture(fetcher);
	const result = await f.request('/object/send', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify({
			type: 1,
			name: 'file',
			deletionDate: new Date(Date.now() + 86400000).toISOString(),
			file: { fileName: 'synthetic-path-that-must-not-be-opened' },
		}),
	});
	expect(result.status).toBe(400);
	expect(await result.json()).toEqual({
		success: false,
		message: 'Creating a file-based Send is unsupported through the `serve` command at this time.',
	});
	expect(fetchCalls).toBe(0);
});
test('local API projects item responses, normalizes dates and honors hidden-password metadata', async () => {
	const f = fixture();
	f.snapshot.ciphers = [encryptItem({
		id,
		type: 1,
		name: 'restricted',
		viewPassword: false,
		edit: true,
		permissions: { delete: true },
		creationDate: '2026-10-20T12:00:00.123456Z',
		login: { username: 'alice', password: 'synthetic-password', totp: 'synthetic-totp', uri: null, uris: [] },
		fields: [{ name: 'hidden', type: 1, value: 'synthetic-hidden' }],
		passwordHistory: [{ password: 'synthetic-old', lastUsedDate: '2026-10-19T12:00:00Z' }],
		attachments: [{ id: 'a', fileName: 'file', key: 'synthetic-wrapped-key', size: '12' }],
	}, f.key)];
	const result = await (await f.request(`/object/item/${id}`)).json();
	expect(result.data.object).toBe('item');
	expect(result.data.creationDate).toBe('2026-10-20T12:00:00.123Z');
	expect(result.data.login).toMatchObject({
		password: null,
		totp: null,
		fido2Credentials: [],
		passwordRevisionDate: null,
	});
	expect(result.data.fields[0].value).toBeNull();
	for (const field of ['key', 'edit', 'permissions', 'viewPassword', 'passwordHistory']) {
		expect(result.data).not.toHaveProperty(field);
	}
	expect(result.data.attachments[0]).not.toHaveProperty('key');
	expect(result.data.login).not.toHaveProperty('uri');
	expect((await f.request(`/object/password/${id}`)).status).toBe(400);
});
test('local API serves Bitwarden device-approval routes with matching response envelopes', async () => {
	const f = fixture();
	const organizationId = '00000000-0000-0000-0000-000000000002';
	const requestId = '00000000-0000-0000-0000-000000000003';
	const calls: string[] = [];
	const deviceApprovals = {
		list: async (organization: string) => {
			calls.push(`list:${organization}`);
			return [{ id: requestId, email: 'member@example.test' }];
		},
		approve: async (organization: string, request: string) => {
			calls.push(`approve:${organization}:${request}`);
		},
		deny: async (organization: string, request: string) => {
			calls.push(`deny:${organization}:${request}`);
		},
		approveAll: async (organization: string) => {
			calls.push(`approve-all:${organization}`);
			return true;
		},
		denyAll: async (organization: string) => {
			calls.push(`deny-all:${organization}`);
			return false;
		},
	};
	f.backend.run = async <T>(
		mutate: boolean,
		operation: (vault: VaultService) => T | Promise<T>,
		online?: boolean,
	): Promise<T> => {
		expect(mutate).toBe(false);
		expect(online).toBe(true);
		return operation({ deviceApprovals } as unknown as VaultService);
	};

	expect(await (await f.request(`/device-approval/${organizationId}`)).json()).toEqual({
		success: true,
		data: { object: 'list', data: [{ id: requestId, email: 'member@example.test' }] },
	});
	for (const action of ['approve', 'deny']) {
		expect(
			await (await f.request(`/device-approval/${organizationId}/${action}/${requestId}`, { method: 'POST' })).json(),
		).toEqual({ success: true });
	}
	expect(await (await f.request(`/device-approval/${organizationId}/approve-all`, { method: 'POST' })).json()).toEqual({
		success: true,
	});
	expect(await (await f.request(`/device-approval/${organizationId}/deny-all`, { method: 'POST' })).json()).toEqual({
		success: true,
		data: {
			object: 'message',
			title: 'No pending device authorization requests to deny.',
			message: null,
			noColor: false,
		},
	});
	expect(calls).toEqual([
		`list:${organizationId}`,
		`approve:${organizationId}:${requestId}`,
		`deny:${organizationId}:${requestId}`,
		`approve-all:${organizationId}`,
		`deny-all:${organizationId}`,
	]);
});
test('local API device-approval routes report Vaultwarden capability limits before organization requests', async () => {
	const paths: string[] = [];
	const fetcher = Object.assign(async (input: URL | RequestInfo) => {
		const path = new URL(String(input)).pathname;
		paths.push(path);
		if (path === '/api/config') return Response.json({ server: { name: 'Vaultwarden' } });
		if (path === '/api/version') return Response.json('1.37.4');
		return Response.json({}, { status: 404 });
	}, { preconnect: () => {} }) as typeof fetch;
	const f = fixture(fetcher);
	const response = await f.request(
		'/device-approval/00000000-0000-0000-0000-000000000002/approve/00000000-0000-0000-0000-000000000003',
		{ method: 'POST' },
	);
	expect(response.status).toBe(400);
	expect(await response.json()).toMatchObject({
		success: false,
		message: expect.stringContaining('Vaultwarden does not expose the organization SSO trusted-device approval API'),
	});
	expect(paths).toEqual(['/api/config', '/api/version']);
});
