import { withImportSync } from '#test/import-server';
import { expect, test } from 'bun:test';
import { Kdbx, KdbxUuid, Credentials, ProtectedValue, Consts, VarDictionary, Int64, CryptoEngine } from 'kdbxweb';
import { parseKdbx } from '#kdbx';
import { configureKdbxCrypto, kdbxTotp, mapKdbx } from '#kdbx-codec';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { decryptOwnedItem } from '#vault';

configureKdbxCrypto();
function database(password?: string, keyFile?: Uint8Array) {
	const db = Kdbx.create(
		new Credentials(password === undefined ? null : ProtectedValue.fromString(password), keyFile?.slice()),
		'Root',
	);
	const group = db.createGroup(db.getDefaultGroup(), 'Work');
	const entry = db.createEntry(group);
	entry.fields.set('Title', 'KDBX fixture');
	entry.fields.set('UserName', 'alice');
	entry.fields.set('Password', ProtectedValue.fromString('  synthetic-secret  '));
	entry.fields.set('URL', 'example.com/a,b');
	entry.fields.set('Notes', 'exact\tnotes\nsecond line');
	entry.fields.set('Hidden', ProtectedValue.fromString('x'.repeat(230) + '\nprivate'));
	entry.fields.set('Multiline', 'line1\nline2');
	entry.fields.set('TimeOtp-Secret-Base64', 'SGVsbG8=');
	entry.fields.set('TimeOtp-Period', '60');
	entry.fields.set('TimeOtp-Length', '8');
	entry.fields.set('TimeOtp-Algorithm', 'HMAC-SHA-256');
	const trash = db.getGroup(db.meta.recycleBinUuid!)!;
	db.createEntry(trash).fields.set('Title', 'Excluded recycle entry');
	return { db, entry };
}
function setKdf(db: Kdbx, kind: 'aes3' | 'aes4' | 'argon2d' | 'argon2id') {
	if (kind === 'aes3') {
		db.setVersion(3);
		db.header.keyEncryptionRounds = 1000;
		return;
	}
	db.setVersion(4);
	db.setKdf(kind === 'aes4' ? Consts.KdfId.Aes : kind === 'argon2d' ? Consts.KdfId.Argon2d : Consts.KdfId.Argon2id);
	const params = db.header.kdfParameters!;
	if (kind === 'aes4') params.set('R', VarDictionary.ValueType.UInt64, Int64.from(1000));
	else {
		params.set('M', VarDictionary.ValueType.UInt64, Int64.from(8192 * 1024));
		params.set('I', VarDictionary.ValueType.UInt64, Int64.from(1));
		params.set('P', VarDictionary.ValueType.UInt32, 1);
	}
}
for (
	const [kind, mode] of [
		['aes3', 'password'],
		['aes4', 'combined'],
		['argon2d', 'keyfile'],
		['argon2id', 'password'],
	] as const
) {
	test(`KDBX ${kind} decodes ${mode} credentials in a worker and imports protected fields`, async () => {
		const keyFile = mode === 'combined'
			? await Credentials.createRandomKeyFile(2)
			: mode === 'keyfile'
			? new Uint8Array(32).fill(9)
			: undefined;
		const password = mode === 'keyfile' ? undefined : 'synthetic-database-password';
		const { db } = database(password, keyFile);
		setKdf(db, kind);
		const bytes = new Uint8Array(await db.save()), original = bytes.slice();
		const document = await parseKdbx(bytes, { password, keyFile });
		expect(bytes).toEqual(original);
		expect(document.folders).toMatchObject([{ name: 'Work' }]);
		const items = document.items as JsonObject[];
		expect(items).toHaveLength(1);
		expect(items[0]).toMatchObject({
			name: 'KDBX fixture',
			notes: 'exact\tnotes\nsecond line',
			login: {
				password: '  synthetic-secret  ',
				totp: 'otpauth://totp/Imported?secret=JBSWY3DP&algorithm=SHA256&digits=8&period=60',
				uris: [{ uri: 'https://example.com/a,b' }],
			},
		});
		expect((items[0]!.fields as JsonObject[]).find(field => field.name === 'Hidden')).toMatchObject({
			type: 1,
			value: 'x'.repeat(230) + '\nprivate',
		});
		expect((items[0]!.fields as JsonObject[]).find(field => field.name === 'Multiline')).toMatchObject({
			type: 0,
			value: 'line1\nline2',
		});
	}, 15000);
}
test('KDBX TOTP handles each secret encoding, precedence and a leading key prefix only', () => {
	const { entry } = database();
	for (const key of [...entry.fields.keys()].filter(key => key.startsWith('TimeOtp-'))) entry.fields.delete(key);
	for (
		const [key, value] of [
			['TimeOtp-Secret', 'Hello'],
			['TimeOtp-Secret-Hex', '48656c6c6f'],
			['TimeOtp-Secret-Base64', 'SGVsbG8='],
			['TimeOtp-Secret-Base32', 'jbsw y3dp==='],
		]
	) {
		entry.fields.set(key!, value!);
		expect(kdbxTotp(entry)).toBe('JBSWY3DP');
		entry.fields.delete(key!);
	}
	entry.fields.set('TimeOtp-Secret-Base32', 'INVALID!');
	expect(kdbxTotp(entry)).toBeNull();
	entry.fields.set('otp', 'otpauth://totp/key=literal?secret=ABC');
	expect(kdbxTotp(entry)).toBe('otpauth://totp/key=literal?secret=ABC');
	entry.fields.set('otp', 'key=ABC');
	expect(kdbxTotp(entry)).toBe('ABC');
});
test('KDBX 4 also decodes ChaCha20 database payloads', async () => {
	const { db } = database('synthetic-database-password');
	setKdf(db, 'argon2id');
	db.header.dataCipherUuid = new KdbxUuid(Consts.CipherId.ChaCha20);
	const document = await parseKdbx(new Uint8Array(await db.save()), { password: 'synthetic-database-password' });
	expect((document.items as JsonObject[])[0]).toMatchObject({
		name: 'KDBX fixture',
		notes: 'exact\tnotes\nsecond line',
	});
});
test('KDBX imports the recycle group when disabled and maps groups to organization collections', () => {
	const { db } = database();
	db.meta.recycleBinEnabled = false;
	const document = mapKdbx(db, true), collections = document.collections as JsonObject[];
	expect(document.items).toHaveLength(2);
	expect(collections.map(group => group.name)).toContain('Recycle Bin');
	expect((document.items as JsonObject[]).every(item => item.folderId === null && Array.isArray(item.collectionIds)))
		.toBe(true);
});
test('wrong KDBX credentials, corrupt files, excessive input and KDF work fail before mutation', async () => {
	const { db } = database('synthetic-database-password');
	setKdf(db, 'aes3');
	const bytes = new Uint8Array(await db.save());
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: (async () => {
			calls++;
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, Buffer.alloc(64, 7));
	await expect(vault.importVault('keepasskdbx', bytes, { password: 'incorrect' })).rejects.toThrow(
		'password or key file',
	);
	await expect(vault.importVault('keepasskdbx', new Uint8Array([3, 217, 162, 154]))).rejects.toThrow(
		'corrupt or unsupported',
	);
	await expect(parseKdbx(new Uint8Array(10 * 1024 * 1024 + 1))).rejects.toThrow('10 MiB');
	await expect(CryptoEngine.argon2(new ArrayBuffer(32), new ArrayBuffer(32), 512 * 1024, 1, 32, 1, 2, 0x13)).rejects
		.toThrow('KDF parameters');
	expect(calls).toBe(0);
	vault.dispose();
});
test('KDBX bulk import encrypts decoded data with new item keys', async () => {
	const { db } = database('synthetic-database-password');
	setKdf(db, 'aes3');
	const bytes = new Uint8Array(await db.save()), owner = Buffer.alloc(64, 7);
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: withImportSync(async (_url: unknown, init?: RequestInit) => {
			calls++;
			const body = JSON.parse(String(init!.body));
			expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }]);
			expect(decryptOwnedItem(body.ciphers[0], owner)).toMatchObject({
				name: 'KDBX fixture',
				login: { password: '  synthetic-secret  ' },
			});
			expect(String(init!.body)).not.toContain('synthetic-secret');
			return new Response(null, { status: 204 });
		}),
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, owner);
	expect(await vault.importVault('keepasskdbx', bytes, { password: 'synthetic-database-password' })).toEqual({
		items: 1,
		folders: 1,
		collections: 0,
		attachments: 0,
	});
	expect(calls).toBe(1);
	vault.dispose();
});
