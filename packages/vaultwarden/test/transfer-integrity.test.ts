import { expect, test } from 'bun:test';
import { zipSync } from 'fflate';
import { object, VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { importVault, ImportFailure } from '#transfer';
import { withImportSync } from '#test/import-server';

const key = Buffer.alloc(64, 11);
const entries: JsonObject[] = [
	{ id: 'old-first', type: 1, name: 'First', login: { password: 'synthetic-first' } },
	{ id: 'old-second', type: 1, name: 'Second', login: { password: 'synthetic-second' } },
];
entries[0] = {
	...entries[0]!,
	login: {
		username: 'synthetic-user',
		password: 'synthetic-first',
		uris: [{ uri: 'https://example.test', match: null }],
	},
};
const richEntries = entries.map(item => ({
	...item,
	notes: 'synthetic-notes',
	favorite: true,
	reprompt: 1,
	fields: [{ name: 'Custom', value: 'synthetic-custom', type: 1 }],
	passwordHistory: [{ password: 'synthetic-previous', lastUsedDate: '2026-01-01T00:00:00Z' }],
}));
const profile = { id: 'user', premium: true, organizations: [{ id: 'org', status: 2, type: 0 }] };

const sectionCases: [string, JsonObject, string][] = [
	['login', { username: 'user', password: 'secret' }, 'password'],
	['secureNote', { type: 0 }, 'type'],
	['card', { number: '4111111111111111', code: '123' }, 'code'],
	['identity', { firstName: 'Example', ssn: 'synthetic' }, 'ssn'],
	['sshKey', { privateKey: 'private', publicKey: 'public', fingerprint: 'fingerprint' }, 'privateKey'],
	['bankAccount', { bankName: 'Example', accountNumber: 'synthetic' }, 'accountNumber'],
	['driversLicense', { number: 'synthetic' }, 'number'],
	['passport', { number: 'synthetic' }, 'number'],
];
for (const [index, [section, data, field]] of sectionCases.entries()) {
	test(`import verifies saved ${section} content, including missing ${field}`, async () => {
		let dropField = false;
		const vault = new VaultService(
			new VaultwardenClient('https://example.test', {
				fetch: withImportSync((url, init) => {
					if (new URL(String(url)).pathname === '/api/config') return Response.json({ server: { name: 'Bitwarden' } });
					if (dropField) {
						const accepted = JSON.parse(String(init.body));
						delete accepted.ciphers[0][section][field];
						init.body = JSON.stringify(accepted);
					}
					return new Response(null, { status: 204 });
				}),
			}),
			'access',
			{ profile, ciphers: [] },
			key,
		);
		try {
			const input = JSON.stringify({ items: [{ type: index + 1, name: section, [section]: data }] });
			expect((await vault.importVault('bitwardenjson', input)).items).toBe(1);
			dropField = true;
			await expect(vault.importVault('bitwardenjson', input)).rejects.toThrow(
				`saved item content differs (${section})`,
			);
		} finally {
			vault.dispose();
		}
	});
}

test('every imported type requires its data section before any server mutation', async () => {
	let requests = 0;
	const vault = new VaultService(
		new VaultwardenClient('https://example.test', {
			fetch: (async () => {
				requests++;
				throw new Error('No request should be made.');
			}) as unknown as typeof fetch,
		}),
		'access',
		{ profile, ciphers: [] },
		key,
	);
	try {
		for (
			const [index, section] of [
				'login',
				'secureNote',
				'card',
				'identity',
				'sshKey',
				'bankAccount',
				'driversLicense',
				'passport',
			].entries()
		) {
			for (const value of [undefined, null, [], 'invalid']) {
				await expect(
					vault.importVault(
						'bitwardenjson',
						JSON.stringify({
							items: [entries[0], { type: index + 1, name: 'Invalid later record', [section]: value }],
						}),
					),
				)
					.rejects.toThrow(`missing its ${section} data`);
			}
		}
		expect(requests).toBe(0);
	} finally {
		vault.dispose();
	}
});

for (const organizationId of [undefined, 'org']) {
	for (
		const defect of [
			'missing-item',
			'wrong-key',
			'ambiguous-item',
			'duplicate-server-id',
			'missing-group',
			'malformed-record',
			'missing-password',
			'changed-password',
			'missing-field',
			'missing-history',
			'changed-uri',
			'wrong-assignment',
			'extra-assignment',
			'changed-group-name',
			'server-normalization',
			'sync-failure',
			'none',
		]
	) {
		test(`${organizationId ? 'organization' : 'personal'} import verifies saved records: ${defect}`, async () => {
			let submitted: JsonObject | undefined, mutations = 0, syncs = 0;
			const vault = new VaultService(
				new VaultwardenClient('https://example.test', {
					fetch: (async (url: unknown, init: RequestInit) => {
						const path = new URL(String(url)).pathname;
						if (path === '/api/config') return Response.json({ server: { name: 'Vaultwarden' } });
						if (path === '/api/version') {
							return Response.json('1.37.4');
						}
						if (path.startsWith('/api/ciphers/import') && init.method === 'POST') {
							submitted = JSON.parse(String(init.body));
							mutations++;
							return new Response(null, { status: 204 });
						}
						if (path !== '/api/sync' || !submitted) throw new Error('Unexpected request.');
						syncs++;
						if (defect === 'sync-failure') return Response.json({}, { status: 503 });
						if (defect === 'malformed-record') return Response.json({ profile, ciphers: [null] });
						let ciphers: JsonObject[] = (submitted.ciphers as JsonObject[]).map((cipher, index) => ({
							...cipher,
							id: `created-${index}`,
						}));
						if (defect === 'missing-item') ciphers = ciphers.slice(0, 1);
						if (defect === 'wrong-key') ciphers[1]!.key = 'different-encrypted-key';
						if (defect === 'ambiguous-item') ciphers.push({ ...ciphers[1]!, id: 'duplicate' });
						if (defect === 'duplicate-server-id') ciphers[1]!.id = ciphers[0]!.id;
						if (defect === 'missing-password') delete object(ciphers[0]!.login).password;
						if (defect === 'changed-password') object(ciphers[0]!.login).password = 'different-encrypted-value';
						if (defect === 'missing-field') ciphers[0]!.fields = [];
						if (defect === 'missing-history') ciphers[0]!.passwordHistory = [];
						if (defect === 'changed-uri') {
							(object(ciphers[0]!.login).uris as JsonObject[])[0]!.uri = 'different-encrypted-uri';
						}
						const kind = organizationId ? 'collections' : 'folders';
						const groups: JsonObject[] = defect === 'missing-group'
							? []
							: (submitted[kind] as JsonObject[]).map(group => ({
								...group,
								id: 'created-group',
								...(organizationId ? { organizationId } : {}),
							}));
						for (const cipher of ciphers) {
							if (organizationId) cipher.collectionIds = ['created-group'];
							else cipher.folderId = 'created-group';
						}
						if (defect === 'wrong-assignment') {
							if (organizationId) ciphers[0]!.collectionIds = [];
							else ciphers[0]!.folderId = null;
						}
						if (defect === 'extra-assignment') {
							if (organizationId) ciphers[0]!.collectionIds = ['created-group', 'unexpected-group'];
							else ciphers[0]!.folderId = 'unexpected-group';
						}
						if (defect === 'changed-group-name') groups[0]!.name = 'different-encrypted-name';
						if (defect === 'server-normalization') {
							for (const cipher of ciphers) {
								(cipher.passwordHistory as JsonObject[])[0]!.lastUsedDate = '2026-01-01T00:00:00.000000Z';
								object(cipher.login).serverMetadata = 'extra';
							}
						}
						return Response.json({ profile, ciphers, [kind]: groups });
					}) as typeof fetch,
				}),
				'access',
				{ profile, ciphers: [], collections: [] },
				key,
			);
			try {
				const input = JSON.stringify({
					items: richEntries.map(item => ({
						...item,
						...(organizationId ? { collectionIds: ['source-group'] } : { folderId: 'source-group' }),
					})),
					[organizationId ? 'collections' : 'folders']: [{ id: 'source-group', name: 'Group' }],
				});
				const operation = importVault(vault, { user: key, organization: () => key }, 'bitwardenjson', input, {
					organizationId,
				});
				if (defect === 'none' || defect === 'server-normalization') {
					expect(await operation).toMatchObject({
						items: 2,
						folders: organizationId ? 0 : 1,
						collections: organizationId ? 1 : 0,
					});
				} else {
					try {
						await operation;
						throw new Error('Unverified import reported success.');
					} catch (error) {
						expect(error).toBeInstanceOf(ImportFailure);
						expect((error as ImportFailure).serverMayHaveChanged).toBe(true);
					}
				}
				expect(mutations).toBe(1);
				expect(syncs).toBe(1);
			} finally {
				vault.dispose();
			}
		});
	}
}

for (const ids of [['duplicate', 'duplicate'], ['CASE-ID', 'case-id']]) {
	test(`ZIP duplicate source IDs are rejected before mutation: ${ids.join(', ')}`, async () => {
		let requests = 0;
		const vault = new VaultService(
			new VaultwardenClient('https://example.test', {
				fetch: (async () => {
					requests++;
					throw new Error('No request should be made.');
				}) as unknown as typeof fetch,
			}),
			'access',
			{ profile, ciphers: [] },
			key,
		);
		try {
			const zip = zipSync({
				'data.json': Buffer.from(
					JSON.stringify({ folders: [], items: entries.map((item, index) => ({ ...item, id: ids[index] })) }),
				),
				'attachments/First/first.txt': Buffer.from('first-file'),
				'attachments/Second/second.txt': Buffer.from('second-file'),
			});
			await expect(vault.importVault('bitwardenzip', zip)).rejects.toThrow('Duplicate ZIP item ID');
			expect(requests).toBe(0);
		} finally {
			vault.dispose();
		}
	});
}
