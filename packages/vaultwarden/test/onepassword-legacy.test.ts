import { withImportSync } from '#test/import-server';
import { test, expect } from 'bun:test';
import { readFile } from 'node:fs/promises';
import { parseOnePassword1Pif, parseOnePasswordCsv } from '#onepassword-legacy';
import { parseCsv } from '#csv';
import { VaultwardenClient, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { decrypt } from '#crypto';
import { transformItem } from '#item-codec';

const fixture = (file: string) =>
	readFile(new URL(`../../../apps/cli/test/fixtures/onepassword/${file}`, import.meta.url), 'utf8');
const pif = await fixture('legacy.1pif'), mac = await fixture('mac.csv'), windows = await fixture('windows.csv');
test('1PIF standard and OPVault records import mapped data and exclude trash', () => {
	const result = parseOnePassword1Pif(pif), items = result.items as JsonObject[];
	expect(items).toHaveLength(7);
	expect(items.map(i => i.type)).toEqual([1, 3, 4, 2, 1, 3, 4]);
	expect(items[0]).toMatchObject({
		favorite: true,
		notes: 'first\nsecond\nMultiline: first\nsecond\n',
		login: {
			username: 'alice',
			password: '  synthetic-password  ',
			totp: 'otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP',
		},
		passwordHistory: [{ password: 'previous synthetic password', lastUsedDate: '2023-11-14T22:13:20.000Z' }],
	});
	expect(items[0]!.fields).toEqual([{ name: 'Private', value: 'synthetic-hidden', type: 1 }]);
	expect((items[0]!.login as JsonObject).uris).toEqual([
		{ uri: 'http://example.com/a,b', match: null },
		{ uri: 'https://second.example.com', match: null },
	]);
	expect(items[1]!.card).toEqual({
		number: '4111111111111111',
		brand: 'Visa',
		code: '123',
		cardholderName: 'Alice Example',
		expMonth: '6',
		expYear: '2030',
	});
	expect(items[2]!.identity).toEqual({
		firstName: 'Alice',
		lastName: 'Example',
		address1: 'Test street 1',
		city: 'Test city',
		country: 'NL',
		postalCode: '1234AB',
	});
	expect(items[2]!.fields).toContainEqual({ name: 'Birthday', value: 'Sat, 01 Jan 2000 00:00:00 GMT', type: 0 });
	expect(items[3]!.notes).toBe('  synthetic notes\t \n\n');
	expect(items[4]!.login).toMatchObject({ username: 'opvault-user', password: 'opvault-synthetic' });
	expect(items[5]!.card).toMatchObject({ brand: 'Mastercard', expMonth: '1', expYear: '2031' });
	expect(items[6]!.identity).toEqual({ firstName: 'Bob', email: 'bob@example.com' });
	expect(parseOnePassword1Pif(pif, true).collections).toEqual([]);
});
test('1PIF missing fields, unknown designations and legacy category fallback remain importable', () => {
	const source = {
		title: 'Synthetic',
		typeName: 'wallet.government.Passport',
		secureContents: {
			passwordHistory: Array.from({ length: 9 }, (_, i) => ({ value: `synthetic-${i}`, time: 1700000000 + i })),
			sections: [{
				fields: [
					{ n: 'number', v: 'synthetic passport', t: 'number' },
					{ n: '__proto__', v: 'literal', t: 'prototype' },
				],
			}],
		},
	};
	const item = (parseOnePassword1Pif(JSON.stringify(source)).items as JsonObject[])[0]!;
	expect(item.type).toBe(2);
	expect(item.passwordHistory).toHaveLength(5);
	expect(item.fields).toContainEqual({ name: 'prototype', value: 'literal', type: 0 });
	expect(() => parseOnePassword1Pif('{broken secret')).toThrow('Invalid 1PIF JSON record.');
	expect(() => parseOnePassword1Pif('{"title":"bad","secureContents":{"fields":{}}}')).toThrow('list');
});
test('Mac CSV uses escaped quotes, multiple URLs, card/identity types and note continuations', () => {
	const items = parseOnePasswordCsv('1passwordmaccsv', mac).items as JsonObject[];
	expect(items).toHaveLength(4);
	expect(items.map(i => i.type)).toEqual([1, 3, 4, 2]);
	expect(items[0]!.login).toMatchObject({
		username: 'alice',
		password: '  synthetic-"quoted"  ',
		uris: [{ uri: 'http://example.com/a,b', match: null }, { uri: 'https://second.example.com', match: null }],
	});
	expect(items[0]!.notes).toBe('first\nsecond\nmore notes\n');
	expect(items[0]!.fields).toContainEqual({ name: 'API secret', value: 'synthetic-secret', type: 1 });
	expect(items[0]!.fields).toContainEqual({
		name: '1Password Created date',
		value: 'Tue, 14 Nov 2023 22:13:20 GMT',
		type: 0,
	});
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
		lastName: 'Example',
		middleName: 'Q',
		phone: '123',
		company: 'Example company',
		email: 'alice@example.com',
	});
});
for (const format of ['1passwordmaccsv', '1passwordwincsv'] as const) {
	test(`${format} distinguishes card numbers from verification codes independently of column order`, () => {
		const number = format === '1passwordwincsv' ? 'card 1: number' : 'Number';
		const verification = format === '1passwordwincsv' ? 'card 1: verification number' : 'Verification number';
		for (
			const [headers, values] of [
				[[number, verification], ['', '123']],
				[[verification, number], ['123', '4111111111111111']],
				[[number, verification], ['4111111111111111', '123']],
			] as const
		) {
			const parsed = parseOnePasswordCsv(
				format,
				['Title,Type,' + headers.join(','), 'Card,Credit Card,' + values.join(',')].join('\n'),
			);
			const card = (parsed.items as JsonObject[])[0]!.card as JsonObject;
			expect(card.code).toBe('123');
			expect(card.number ?? null).toBe(values.some(value => value === '4111111111111111') ? '4111111111111111' : null);
		}
	});
}

test('Windows CSV infers card/identity types and supports multiline addresses', () => {
	const items = parseOnePasswordCsv('1passwordwincsv', windows).items as JsonObject[];
	expect(items).toHaveLength(3);
	expect(items.map(i => i.type)).toEqual([1, 3, 4]);
	expect(items[1]!.card).toEqual({
		number: '5555555555554444',
		brand: 'Mastercard',
		code: '987',
		cardholderName: 'Bob Example',
		expMonth: '1',
		expYear: '2031',
	});
	expect(items[2]!.identity).toEqual({ firstName: 'Bob', lastName: 'Example', email: 'bob@example.com' });
	expect(items[2]!.notes).toBe('\n\naddress: Test street 1\nTest city\n');
});
test('Legacy CSV singular URLs stay intact, aliases stay case insensitive, malformed CSV fails', () => {
	const parsed = parseOnePasswordCsv('1passwordmaccsv', 'TITLE,URL,USERNAME\nExample,example.com,alice\n');
	expect((parsed.items as JsonObject[])[0]!.login).toMatchObject({
		username: 'alice',
		uris: [{ uri: 'http://example.com', match: null }],
	});
	expect(parseOnePasswordCsv('1passwordwincsv', 'Title,Username\n,skip\n').items).toEqual([]);
	expect(
		(parseOnePasswordCsv('1passwordmaccsv', 'Title,NotesPlain,Notes\nExample,  ,sample\n').items as JsonObject[])[0]!
			.notes,
	).toBe('\nsample\n');
	for (const source of ['name,password\na,b', 'Title,title\na,b', 'Title,Username\na', 'Title\n"unfinished']) {
		expect(() => parseOnePasswordCsv('1passwordmaccsv', source)).toThrow();
	}
	expect(parseCsv('"x","a\\"b"', '\\')).toEqual([['x', 'a"b']]);
	expect(parseCsv('"x","a""b"')).toEqual([['x', 'a"b']]);
});
for (
	const [format, source, count] of [
		['1password1pif', pif, 7],
		['1passwordmaccsv', mac, 4],
		['1passwordwincsv', windows, 3],
	] as const
) {
	test(`${format} uses encrypted bulk import and validates malformed input before server writes`, async () => {
		const owner = Buffer.alloc(64, 13);
		let calls = 0;
		const fetcher = withImportSync(async (_url: unknown, init: RequestInit) => {
			calls++;
			const body = JSON.parse(String(init.body));
			expect(body.ciphers).toHaveLength(count);
			expect(String(init.body)).not.toContain('synthetic-password');
			expect(String(init.body)).not.toContain('alice');
			const key = decrypt(body.ciphers[0].key, owner);
			try {
				expect(transformItem(body.ciphers[0], key, 'decrypt').type).toBe(1);
			} finally {
				key.fill(0);
			}
			return new Response(null, { status: 204 });
		});
		const vault = new VaultService(new VaultwardenClient('https://example.com', { fetch: fetcher }), 'access', {
			profile: { id: 'account' },
		}, owner);
		try {
			await expect(vault.importVault(format, format === '1password1pif' ? '{malformed' : 'Title\n"malformed')).rejects
				.toThrow();
			expect(calls).toBe(0);
			expect(await vault.importVault(format, source)).toEqual({
				items: count,
				folders: 0,
				collections: 0,
				attachments: 0,
			});
			expect(calls).toBe(1);
		} finally {
			vault.dispose();
		}
	});
}
