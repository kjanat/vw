import { withImportSync } from '#test/import-server';
import { test, expect } from 'bun:test';
import { generateKeyPairSync } from 'node:crypto';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { zipSync } from 'fflate';
import { parseOnePassword1Pux } from '#onepassword';
import { importSshPkcs8 } from '#ssh-import';
import { VaultService } from '#vault-service';
import { VaultwardenClient, type JsonObject } from '#client';
import { decrypt } from '#crypto';
import { transformItem } from '#item-codec';

const source = await readFile(new URL('../../../apps/cli/test/fixtures/onepassword/export.data', import.meta.url));
const fields = (id: string, title: string, value: unknown) => ({ id, title, value });
function document(category: string, sections: unknown[] = [], extra: JsonObject = {}): string {
	return JSON.stringify({
		accounts: [{
			vaults: [{
				items: [{
					uuid: 'fixture',
					categoryUuid: category,
					overview: { title: 'Synthetic fixture' },
					details: { sections: [{ fields: sections }], ...extra },
				}],
			}],
		}],
	});
}
test('1PUX corpus maps credentials, tags, identities, notes, history, archive, and skipped records', async () => {
	const parsed = await parseOnePassword1Pux(source), items = parsed.items as JsonObject[];
	expect(items).toHaveLength(11);
	expect(parsed.errors).toEqual([{ id: 'bad-ssh', reason: 'sshKeyParseFailed' }]);
	expect((parsed.folders as JsonObject[]).map(f => f.name)).toEqual(['Work/team', 'Work']);
	const login = items[0]!;
	expect(login).toMatchObject({
		favorite: true,
		reprompt: 1,
		login: { username: 'alice', password: '  synthetic-password  ' },
	});
	expect((login.login as JsonObject).uris).toEqual([
		{ uri: 'http://example.com/a,b', match: null },
		{ uri: 'https://second.example', match: null },
	]);
	expect(login.notes).toBe('Multiline: first\nsecond\n');
	expect(login.fields).toContainEqual({ name: 'checked', value: 'true', type: 2 });
	expect(login.fields).toContainEqual({ name: 'unchecked', value: 'false', type: 2 });
	expect(login.fields).toContainEqual({ name: 'guarded', value: 'synthetic-hidden', type: 1 });
	expect(login.passwordHistory).toEqual([
		{ password: 'newer synthetic password', lastUsedDate: '2023-11-14T22:13:21.000Z' },
		{ password: 'previous synthetic password', lastUsedDate: '2023-11-14T22:13:20.000Z' },
	]);
	expect(items[1]!.card).toEqual({
		number: '4111111111111111',
		brand: 'Visa',
		code: '123',
		cardholderName: 'Alice Example',
		expMonth: '6',
		expYear: '2030',
	});
	expect(items[2]!.identity).toMatchObject({
		firstName: 'Alice',
		middleName: 'Q',
		lastName: 'Example',
		country: 'NL',
		postalCode: '1234AB',
		email: 'alice@example.com',
	});
	expect(items[3]!.identity).toMatchObject({
		firstName: 'Alice',
		middleName: 'Q',
		lastName: 'Example',
		country: 'NL',
		passportNumber: 'SYNTHETIC',
	});
	expect(items[4]!.card).toEqual({ cardholderName: 'Alice Example' });
	expect(items[5]!.login).toMatchObject({
		password: 'synthetic-api-key',
		uris: [{ uri: 'http://api.example.com', match: null }],
	});
	expect(items[6]!.notes).toBe('  Notes\nsecond\tline');
	expect(items[7]!.archivedDate).toMatch(/^\d{4}-/);
});
test('1PUX archive reads only export.data and returns organization collection relations', async () => {
	const archive = zipSync({
		'export.data': source,
		'files/ignored.bin': new Uint8Array([1, 2, 3]),
		'../ignored': new Uint8Array([4]),
	});
	const parsed = await parseOnePassword1Pux(archive, true), groups = parsed.collections as JsonObject[];
	expect(parsed.folders).toBeUndefined();
	expect(groups.map(v => v.name)).toEqual(['Work/team', 'Work']);
	for (const item of parsed.items as JsonObject[]) {
		expect(item.folderId).toBeNull();
		expect(item.collectionIds).toEqual([groups[0]!.id]);
	}
});
test('1PUX imports combine source notes with long and multiline custom fields', async () => {
	const recovery = `first-line\n${'x'.repeat(220)}\nlast-line`;
	const parsed = await parseOnePassword1Pux(
		document('005', [fields('recovery', 'Recovery codes', { string: recovery })], {
			password: 'synthetic-password',
			notesPlain: 'Existing note',
		}),
	);
	const item = (parsed.items as JsonObject[])[0]!;
	expect(item.notes).toBe(`Existing note\nRecovery codes: ${recovery}\n`);
	expect(item.fields).toEqual([]);
});

test('1PUX keeps a TOTP-only login as a login item', async () => {
	const parsed = await parseOnePassword1Pux(
		document('005', [fields('TOTP_fixture', 'One-Time Password', { totp: 'ONEPASSWORD_TEST_SEED' })]),
	);
	expect((parsed.items as JsonObject[])[0]).toMatchObject({
		type: 1,
		login: { totp: 'ONEPASSWORD_TEST_SEED' },
	});
});

test('1PUX remaining category mappings and login-to-note conversion follow field semantics', async () => {
	const cases: [string, unknown[], string, JsonObject][] = [
		[
			'103',
			[fields('fullname', 'name', { string: 'Alice Example' }), fields('number', 'number', { string: 'LICENSE' })],
			'identity',
			{ firstName: 'Alice', lastName: 'Example', licenseNumber: 'LICENSE' },
		],
		[
			'104',
			[fields('name', 'name', { string: 'Alice Example' }), fields('state', 'state', { string: 'NH' })],
			'identity',
			{ firstName: 'Alice', lastName: 'Example', state: 'NH' },
		],
		[
			'105',
			[
				fields('member_name', 'name', { string: 'Alice Example' }),
				fields('org_name', 'org', { string: 'Example' }),
				fields('phone', 'phone', { phone: '123' }),
			],
			'identity',
			{ firstName: 'Alice', lastName: 'Example', company: 'Example', phone: '123' },
		],
		[
			'107',
			[
				fields('member_name', 'name', { string: 'Alice Example' }),
				fields('company_name', 'company', { string: 'Example' }),
			],
			'identity',
			{ firstName: 'Alice', lastName: 'Example', company: 'Example' },
		],
		[
			'108',
			[fields('name', 'name', { string: 'Alice Example' }), fields('number', 'ssn', { concealed: 'SYNTHETIC-SSN' })],
			'identity',
			{ firstName: 'Alice', lastName: 'Example', ssn: 'SYNTHETIC-SSN' },
		],
		['110', [fields('url', 'url', { url: 'server.example.com' })], 'login', {
			uris: [{ uri: 'http://server.example.com', match: null }],
		}],
	];
	for (const [category, sectionFields, key, expected] of cases) {
		expect(((await parseOnePassword1Pux(document(category, sectionFields))).items as JsonObject[])[0]![key])
			.toMatchObject(
				expected,
			);
	}
	for (const category of ['001', '006', '100', '102', '109', '111', '113', 'unknown']) {
		expect(((await parseOnePassword1Pux(document(category))).items as JsonObject[])[0]!.type).toBe(2);
	}
});
test('1PUX imports every vault from the first account, limits history, and rejects malformed containers', async () => {
	const base = JSON.parse(
		document('005', [], {
			password: 'synthetic',
			passwordHistory: Array.from({ length: 8 }, (_, i) => ({ value: `old-${i}`, time: 1700000000 + i })),
		}),
	);
	base.accounts[0].vaults.push(structuredClone(base.accounts[0].vaults[0]));
	const secondAccount = structuredClone(base.accounts[0]);
	secondAccount.vaults[0].items[0].overview.title = 'Ignored second account';
	base.accounts.push(secondAccount);
	const items = (await parseOnePassword1Pux(JSON.stringify(base))).items as JsonObject[];
	expect(items).toHaveLength(2);
	expect(items.every(item => item.name === 'Synthetic fixture')).toBe(true);
	expect(items[0]!.passwordHistory).toHaveLength(5);
	for (const input of ['{secret invalid', '{}', '{"accounts":[]}', '{"accounts":[{"vaults":123}]}']) {
		await expect(parseOnePassword1Pux(input)).rejects.toThrow();
	}
	await expect(parseOnePassword1Pux(zipSync({ 'wrong.data': source }))).rejects.toThrow('export.data');
	await expect(parseOnePassword1Pux(new Uint8Array([80, 75, 1, 2]))).rejects.toThrow('archive');
});
test('1PUX upload uses fresh item keys and reports skipped records without plaintext on the wire', async () => {
	const owner = Buffer.alloc(64, 12);
	let calls = 0;
	const fetcher = withImportSync(async (_url: unknown, init: RequestInit) => {
		calls++;
		const body = JSON.parse(String(init.body));
		expect(String(init.body)).not.toContain('synthetic-password');
		expect(body.ciphers).toHaveLength(11);
		expect(body.folderRelationships).toHaveLength(11);
		const child = decrypt(body.ciphers[0].key, owner);
		try {
			expect(child.equals(owner)).toBe(false);
			expect(transformItem(body.ciphers[0], child, 'decrypt').passwordHistory).toHaveLength(2);
		} finally {
			child.fill(0);
		}
		return new Response(null, { status: 204 });
	});
	const vault = new VaultService(new VaultwardenClient('https://example.com', { fetch: fetcher }), 'access', {
		profile: { id: 'synthetic' },
	}, owner);
	try {
		expect(await vault.importVault('1password1pux', source)).toMatchObject({
			items: 11,
			folders: 2,
			errors: [{ id: 'bad-ssh', reason: 'sshKeyParseFailed' }],
		});
		expect(calls).toBe(1);
	} finally {
		vault.dispose();
	}
});
test('1PUX SSH conversion reports unsupported algorithms and malformed keys', async () => {
	for (
		const pair of [
			generateKeyPairSync('x25519'),
		]
	) {
		await expect(importSshPkcs8(pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()))
			.rejects.toMatchObject({ reason: 'unsupportedType' });
	}
	await expect(importSshPkcs8('-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----'))
		.rejects.toMatchObject({ reason: 'sshKeyParseFailed' });
});

for (const algorithm of ['ed25519', 'rsa', 'rsa1024', 'P-256', 'P-384', 'P-521'] as const) {
	test(`1PUX ${algorithm} PKCS#8 conversion is independently readable by OpenSSH`, async () => {
		const pair = algorithm === 'rsa' || algorithm === 'rsa1024'
			? generateKeyPairSync('rsa', { modulusLength: algorithm === 'rsa1024' ? 1024 : 2048 })
			: algorithm === 'ed25519'
			? generateKeyPairSync('ed25519')
			: generateKeyPairSync('ec', { namedCurve: algorithm });
		const pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
		const imported = await importSshPkcs8(pem);
		const location = await mkdtemp(join(tmpdir(), 'vw-synthetic-ssh-'));
		try {
			const path = join(location, 'key');
			await writeFile(path, String(imported.privateKey), { mode: 0o600 });
			const converted = Bun.spawnSync(['ssh-keygen', '-y', '-f', path], { stdout: 'pipe', stderr: 'pipe' });
			expect(converted.exitCode).toBe(0);
			expect(converted.stdout.toString().trim()).toBe(String(imported.publicKey));
			await writeFile(join(location, 'public'), `${imported.publicKey}\n`);
			const fingerprint = Bun.spawnSync(['ssh-keygen', '-l', '-E', 'sha256', '-f', join(location, 'public')], {
				stdout: 'pipe',
				stderr: 'pipe',
			});
			expect(fingerprint.exitCode).toBe(0);
			expect(fingerprint.stdout.toString()).toContain(String(imported.keyFingerprint));
		} finally {
			await rm(location, { recursive: true, force: true });
		}
	});
}
