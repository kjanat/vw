import { withImportSync } from '#test/import-server';
import { expect, test } from 'bun:test';
import { parseExternalCsv } from '#csv-import';
import { writeCsv } from '#csv';
import { VaultwardenClient, object, type JsonObject } from '#client';
import { VaultService } from '#vault-service';
import { decryptOwnedItem } from '#vault';
import { decrypt } from '#crypto';

const items = (document: JsonObject) => (document.items as JsonObject[]);
function nordPassCsv(records: Record<string, string>[]): string {
	const headers = [...new Set(['type', ...records.flatMap(record => Object.keys(record))])];
	return writeCsv([headers, ...records.map(record => headers.map(header => record[header] ?? ''))]);
}
test('Delinea CSV maps URL logins, secure notes, hidden passwords, and folders or collections', () => {
	const source = writeCsv([
		['Secret Name', 'URL', 'Username', 'Password', 'Notes', 'Folder', 'Custom'],
		[
			'Delinea login',
			'https://delinea.example.test/login',
			'delinea-user',
			'  delinea-secret  ',
			'login note',
			'Work/Bank',
			'private',
		],
		['Delinea note', '', '', 'note-password', 'secure note', 'Work/Bank', 'reference'],
	]);
	const result = parseExternalCsv('delineacsv', source);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'Delinea login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'login note',
		login: {
			username: 'delinea-user',
			password: '  delinea-secret  ',
			uris: [{ uri: 'https://delinea.example.test/login', match: null }],
		},
		fields: [{ name: 'Custom', value: 'private', type: 0 }],
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		notes: 'secure note',
		fields: [
			{ name: 'Password', value: 'note-password', type: 1 },
			{ name: 'Custom', value: 'reference', type: 0 },
		],
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parseExternalCsv('delineacsv', source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Zoho Vault CSV maps names, URLs, TOTP, embedded fields, favorites, and folders', () => {
	const source = writeCsv([
		[
			'Password Name',
			'Secret Name',
			'Favorite',
			'Notes',
			'Password URL',
			'Secret URL',
			'TOTP',
			'login_totp',
			'SecretData',
			'CustomData',
			'Folder Name',
		],
		[
			'Zoho login',
			'Fallback name',
			'1',
			'Entry note',
			'https://zoho.example.test/login',
			'https://ignored.example.test',
			'',
			'ZOHO_TEST_SEED',
			'Username: zoho-user\nPassword: zoho-secret\nSecretType: login\nAccount: checking',
			'Password: extra-value\nLong: first\nsecond',
			'Personal/Finance',
		],
		['', 'Zoho note', '0', 'Note body', '', '', '', '', 'SecretType: note\nReference: id-1', '', 'Personal/Notes'],
	]);
	const result = parseExternalCsv('zohovaultcsv', source);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'Zoho login',
		favorite: true,
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'Entry note',
		login: {
			username: ' zoho-user',
			password: ' zoho-secret',
			totp: 'ZOHO_TEST_SEED',
			uris: [{ uri: 'https://zoho.example.test/login', match: null }],
		},
		fields: [
			{ name: 'Account', value: ' checking', type: 0 },
			{ name: 'Password', value: ' extra-value', type: 0 },
			{ name: 'Long', value: ' first', type: 0 },
		],
	});
	expect(items(result)[1]).toMatchObject({
		name: 'Zoho note',
		type: 2,
		secureNote: { type: 0 },
		notes: 'Note body',
		fields: [{ name: 'Reference', value: ' id-1', type: 0 }],
	});
	expect(items(result)[1]!.login).toBeUndefined();
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Personal/Finance' },
		{ id: expect.any(String), name: 'Personal' },
		{ id: expect.any(String), name: 'Personal/Notes' },
	]);
	const organization = parseExternalCsv('zohovaultcsv', source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('RoboForm CSV maps legacy and V2 fields, alternate credentials, TOTP, and nested folders', () => {
	const source = writeCsv([
		['Name', 'Login', 'Pwd', 'Password', 'Url', 'URL', 'Folder', 'Note', 'Rf_fields', 'RfFieldsV2'],
		[
			'RoboForm legacy',
			'legacy-user',
			'',
			'fallback-secret',
			'',
			'https://legacy.example.test',
			'/Vault/Legacy',
			'Legacy note',
			'Color:label:blue',
			'',
			'Recovery:ABC:rck:ignored',
		],
		[
			'RoboForm V2',
			'main-user',
			'main-secret',
			'',
			'https://v2.example.test',
			'',
			'Vault/Modern',
			'',
			'',
			'TOTP KEY$,Name,totp,text,ROBOFORM_TEST_SEED',
			'User ID$,Name,user,text,alternate-user',
			'User ID$,Name,user,text,main-user',
			'Password$,Name,pwd,pwd,alternate-secret',
			'Password$,Name,pwd,pwd,main-secret',
		],
		['', '', '', '', '', '', '', '', '', ''],
	]);
	const result = parseExternalCsv('roboformcsv', source);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'RoboForm legacy',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'Legacy note',
		login: {
			username: 'legacy-user',
			password: 'fallback-secret',
			uris: [{ uri: 'https://legacy.example.test', match: null }],
		},
		fields: [
			{ name: 'Color', value: 'blue', type: 0 },
			{ name: 'Recovery', value: 'ABC', type: 0 },
		],
	});
	expect(items(result)[1]).toMatchObject({
		name: 'RoboForm V2',
		login: { username: 'main-user', password: 'main-secret', totp: 'ROBOFORM_TEST_SEED' },
		fields: [
			{ name: 'Alternate User ID 1', value: 'alternate-user', type: 0 },
			{ name: 'Alternate Password 1', value: 'alternate-secret', type: 1 },
		],
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Vault/Legacy' },
		{ id: expect.any(String), name: 'Vault' },
		{ id: expect.any(String), name: 'Vault/Modern' },
	]);
	const organization = parseExternalCsv('roboformcsv', source, true);
	expect(result.folders).toBeDefined();
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Keeper CSV maps headerless logins, secure notes, TOTP, custom fields, and folders or collections', () => {
	const source = writeCsv([
		[
			'Vault/Personal',
			'Keeper login',
			'keeper-user',
			'  keeper-secret  ',
			'https://keeper.example.test',
			'Keeper note',
			'Shared ignored',
			'TFC:Keeper',
			'KEEPER_TEST_SEED',
			'Recovery code',
			'keeper-recovery',
		],
		['Vault/Personal', 'Keeper note', '', '', '', 'Reference note', 'Shared ignored', 'Reference', 'keeper-ref'],
	]);
	const result = parseExternalCsv('keepercsv', source);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'Keeper login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'Keeper note',
		login: {
			username: 'keeper-user',
			password: '  keeper-secret  ',
			totp: 'KEEPER_TEST_SEED',
			uris: [{ uri: 'https://keeper.example.test', match: null }],
		},
		fields: [{ name: 'Recovery code', value: 'keeper-recovery', type: 0 }],
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		notes: 'Reference note',
		fields: [{ name: 'Reference', value: 'keeper-ref', type: 0 }],
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Vault/Personal' },
		{ id: expect.any(String), name: 'Vault' },
	]);
	const organization = parseExternalCsv('keepercsv', source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('PasswordXP CSV maps translated headers, folder markers, descriptions, and custom fields', () => {
	const source = writeCsv([
		['Titel', 'Benutzername', 'URL', 'Passwort', 'Beschreibung', 'Account', 'Private'],
		['[Work/Bank]', '', '', '', '', '', ''],
		[
			'PasswordXP login',
			'passwordxp-user',
			'https://passwordxp.example.test',
			'  passwordxp-secret  ',
			'login note',
			'checking',
			'private',
		],
		['PasswordXP note', '', '', '', 'note body', 'reference', ''],
	]);
	const result = parseExternalCsv('passwordxpcsv', source);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'PasswordXP login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'login note',
		login: {
			username: 'passwordxp-user',
			password: '  passwordxp-secret  ',
			uris: [{ uri: 'https://passwordxp.example.test', match: null }],
		},
		fields: [{ name: 'Account', value: 'checking', type: 0 }, { name: 'Private', value: 'private', type: 0 }],
	});
	expect(items(result)[1]).toMatchObject({ type: 2, name: 'PasswordXP note', notes: 'note body' });
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Work/Bank' },
		{ id: expect.any(String), name: 'Work' },
	]);
	const organization = parseExternalCsv('passwordxpcsv', source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Netwrix Password Secure CSV handles semicolons, language aliases, multiple URLs, and wrapped rows', () => {
	const source = [
		'Organisationseinheit;Beschreibung;Benutzername;Passwort;Internetseite;Website;Informationen;One-Time Passwort;DataTags',
		'Ops/Finance;MFA portal;mfa-user;"  mfa-secret  ";https://mfa.example.test;https://backup.example.test;"login note  ";NETWRIX_TEST_SEED;blue',
		'Ops/Finance;Secure note;;;;;reference;;;',
	].join('\r\n');
	const wrapped = [
		'"Organisationseinheit;""Beschreibung"";""Benutzername"";""Passwort"";""Internetseite"";""Website"";""Informationen"";""One-Time Passwort"";""DataTags"""',
		'"Ops/Finance;""MFA portal"";""mfa-user"";""  mfa-secret  "";""https://mfa.example.test"";""https://backup.example.test"";""login note  "";""NETWRIX_TEST_SEED"";""blue"""',
	].join('\r\n');
	const result = parseExternalCsv('netwrixpasswordsecure', source);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'MFA portal',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'login note',
		login: {
			username: 'mfa-user',
			password: '  mfa-secret  ',
			totp: 'NETWRIX_TEST_SEED',
			uris: [
				{ uri: 'https://mfa.example.test', match: null },
				{ uri: 'https://backup.example.test', match: null },
			],
		},
		fields: [{ name: 'DataTags', value: 'blue', type: 0 }],
	});
	expect(items(parseExternalCsv('netwrixpasswordsecure', wrapped))[0]).toMatchObject({
		name: 'MFA portal',
		login: { password: '  mfa-secret  ', totp: 'NETWRIX_TEST_SEED' },
		fields: [{ name: 'DataTags', value: 'blue', type: 0 }],
	});
	const organization = parseExternalCsv('netwrixpasswordsecure', source, true);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Encryptr maps password, credit-card, and fallback note records like the reference importer', () => {
	const source = writeCsv([
		[
			'Label',
			'Notes',
			'Text',
			'Entry Type',
			'Username',
			'Password',
			'Site URL',
			'Name on card',
			'Card Number',
			'CVV',
			'Expiry',
		],
		['Login', 'first note', 'additional text', 'Password', ' alice ', '  secret  ', 'example.com/path', '', '', '', ''],
		[
			'Card',
			'card note',
			'extra detail',
			'Credit Card',
			'',
			'',
			'',
			'Alice Example',
			'4111111111111111',
			'123',
			'06/30/ignored',
		],
		['Secure note', 'note only', 'continued note', 'Unknown', '', '', '', '', '', '', ''],
		['Empty login', '', 'becomes a note', 'Password', '', '  ', '', '', '', '', ''],
	]);
	const parsed = items(parseExternalCsv('encryptrcsv', source));
	expect(parsed).toHaveLength(4);
	expect(parsed[0]).toMatchObject({
		name: 'Login',
		notes: 'first note\n\nadditional text',
		login: {
			username: ' alice ',
			password: '  secret  ',
			uris: [{ uri: 'http://example.com/path' }],
		},
	});
	expect(parsed[1]).toMatchObject({
		type: 3,
		name: 'Card',
		notes: 'card note\n\nextra detail',
		card: {
			cardholderName: 'Alice Example',
			brand: 'Visa',
			number: '4111111111111111',
			code: '123',
			expMonth: '6',
			expYear: '2030',
		},
	});
	expect(parsed[2]).toMatchObject({
		type: 2,
		name: 'Secure note',
		notes: 'note only\n\ncontinued note',
		secureNote: { type: 0 },
	});
	expect(parsed[3]).toMatchObject({
		type: 2,
		name: 'Empty login',
		notes: 'becomes a note',
		secureNote: { type: 0 },
	});
});
test('PassKeep maps whitespace-prefixed columns, categories, descriptions, and its second password field', () => {
	const source = writeCsv([
		[' title', ' username', 'password', ' site', 'description', 'password2', ' category'],
		['Work', 'alice', 'secret', 'example.com', 'notes', 'backup', 'Work\\Accounts'],
	]);
	const personal = parseExternalCsv('passkeepcsv', source), item = items(personal)[0]!;
	expect(personal.folders).toMatchObject([{ name: 'Work/Accounts' }]);
	expect(item).toMatchObject({
		name: 'Work',
		notes: 'notes',
		fields: [{ name: 'Password 2', value: 'backup', type: 0 }],
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'http://example.com' }] },
	});
	const organization = parseExternalCsv('passkeepcsv', source, true),
		collection = (organization.collections as JsonObject[])[0]!;
	expect(items(organization)[0]!.collectionIds).toEqual([collection.id]);
});
test('PasswordWallet positional CSV maps credentials, multiline notes, and folder grouping', () => {
	const source = writeCsv([
		['Example', 'example.com', 'alice', ' secret ', 'line one¬line two', 'Work\\Accounts'],
		['Minimal'],
	]);
	const personal = parseExternalCsv('passwordwallettxt', source), parsed = items(personal);
	expect(personal.folders).toMatchObject([{ name: 'Work/Accounts' }]);
	expect(parsed).toHaveLength(2);
	expect(parsed[0]).toMatchObject({
		name: 'Example',
		notes: 'line one\nline two',
		login: { username: 'alice', password: ' secret ', uris: [{ uri: 'http://example.com' }] },
	});
	expect(parsed[1]).toMatchObject({ name: 'Minimal', login: { username: null, password: null, uris: [] } });
	const organization = parseExternalCsv('passwordwallettxt', source, true),
		collection = (organization.collections as JsonObject[])[0]!;
	expect(items(organization)[0]!.collectionIds).toEqual([collection.id]);
});
test('Passpack maps tags, shared notes, extra fields, and organization collection membership', () => {
	const source = nordPassCsv([{
		'Tags': JSON.stringify({ tags: [JSON.stringify({ tag: 'Shared' }), JSON.stringify({ tag: 'Personal' })] }),
		'Entry Name': 'Passpack entry',
		'User ID': 'alice',
		Password: 'secret',
		URL: 'example.com',
		Notes: 'Private note',
		'Shared Notes': 'Shared note',
		'Extra Fields': JSON.stringify({
			extraFields: [
				JSON.stringify({ name: 'Answer', data: 'custom value' }),
				JSON.stringify({ name: 'Long', data: 'x'.repeat(201) }),
			],
		}),
	}]);
	const personal = parseExternalCsv('passpackcsv', source), item = items(personal)[0]!;
	expect(personal.folders).toMatchObject([{ name: 'Shared' }]);
	expect(item).toMatchObject({
		name: 'Passpack entry',
		notes: `Private note\n\nShared note\nLong: ${'x'.repeat(201)}\n`,
		fields: [{ name: 'Answer', value: 'custom value', type: 0 }],
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'http://example.com' }] },
	});
	const organization = parseExternalCsv('passpackcsv', source, true), groups = organization.collections as JsonObject[];
	expect(groups.map(value => value.name)).toEqual(['Shared', 'Personal']);
	expect(items(organization)[0]!.collectionIds).toEqual(groups.map(value => value.id));
});
test('Passpack malformed embedded JSON fails with a fixed, nonsecret diagnostic', () => {
	try {
		parseExternalCsv('passpackcsv', 'Tags\nSYNTHETIC_SECRET_INVALID_JSON');
		throw new Error('Expected invalid Passpack input to fail.');
	} catch (error) {
		expect(String(error)).toContain('Invalid Passpack Tags JSON.');
		expect(String(error)).not.toContain('SYNTHETIC_SECRET');
	}
});
test('Ascendo positional CSV identifies credentials and URIs from localized generic field names', () => {
	const source = writeCsv([[
		'Ascendo entry',
		'Website',
		'https://example.com',
		'Benutzername',
		'alice',
		'Passwort',
		'secret',
		'Recovery code',
		'backup',
		'Notes',
	]]);
	const item = items(parseExternalCsv('ascendocsv', source))[0]!;
	expect(item).toMatchObject({
		name: 'Ascendo entry',
		notes: 'Notes',
		fields: [{ name: 'Recovery code', value: 'backup', type: 0 }],
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
});
test('BlackBerry skips list rows, maps favorites, and converts note-only rows', () => {
	const source = writeCsv([
		['name', 'grouping', 'fav', 'extra', 'url', 'username', 'password'],
		['BlackBerry login', 'password', '1', 'notes', 'https://example.com', 'alice', 'secret'],
		['BlackBerry note', 'note', '0', 'note body', '', '', ''],
		['List row', 'list', '0', '', '', '', ''],
	]);
	const parsed = items(parseExternalCsv('blackberrycsv', source));
	expect(parsed).toHaveLength(2);
	expect(parsed[0]).toMatchObject({ favorite: true, name: 'BlackBerry login', login: { username: 'alice' } });
	expect(parsed[1]).toMatchObject({ type: 2, name: 'BlackBerry note', notes: 'note body', secureNote: { type: 0 } });
});
test('Blur imports alternate usernames and falls back to a domain-derived name', () => {
	const parsed = items(parseExternalCsv(
		'blurcsv',
		writeCsv([
			['label', 'domain', 'email', 'username', 'password'],
			['null', 'https://www.example.com/login', '', 'legacy user', 'secret'],
		]),
	));
	expect(parsed[0]).toMatchObject({
		name: 'example.com',
		login: { username: 'legacy user', password: 'secret', uris: [{ uri: 'https://www.example.com/login' }] },
	});
	const trailing = items(parseExternalCsv(
		'blurcsv',
		writeCsv([
			['label', 'domain', 'email', 'username', 'password'],
			['Blur trailing', 'example.com', 'alice', '', '  secret  '],
		]),
	))[0]!;
	expect(trailing.login).toMatchObject({ password: '  secret' });
});
test('Codebook maps category, OTP, favorites, fallback email, and extra fields', () => {
	const source = writeCsv([
		['Category', 'Favorite', 'Entry', 'Note', 'Username', 'Email', 'Password', 'TOTP', 'Website', 'Phone', 'PIN'],
		['Work', 'True', 'Codebook', 'notes', '', 'alice@example.com', 'secret', 'otp', 'example.com', '123', '4567'],
	]);
	const parsed = parseExternalCsv('codebookcsv', source), item = items(parsed)[0]!;
	expect(parsed.folders).toMatchObject([{ name: 'Work' }]);
	expect(item).toMatchObject({
		favorite: true,
		name: 'Codebook',
		notes: 'notes',
		fields: [{ name: 'Phone', value: '123', type: 0 }, { name: 'PIN', value: '4567', type: 0 }],
		login: {
			username: 'alice@example.com',
			password: 'secret',
			totp: 'otp',
			uris: [{ uri: 'http://example.com' }],
		},
	});
});
test('Avast CSV maps its web/login column names', () => {
	const item = items(parseExternalCsv(
		'avastcsv',
		writeCsv([
			['name', 'web', 'login', 'password'],
			['Avast entry', 'https://example.com', 'alice', 'secret'],
		]),
	))[0]!;
	expect(item).toMatchObject({
		name: 'Avast entry',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
});
test('Buttercup CSV maps group, login, notes, and nonstandard columns to custom fields', () => {
	const source = writeCsv([
		['!group_id', '!group_name', '!type', 'title', 'username', 'password', 'URL', 'note', 'id', 'Recovery Code'],
		['g1', 'Work', 'login', 'Buttercup entry', 'alice', 'secret', 'example.com', 'notes', 'i1', 'backup'],
	]);
	const personal = parseExternalCsv('buttercupcsv', source), item = items(personal)[0]!;
	expect(personal.folders).toMatchObject([{ name: 'Work' }]);
	expect(item).toMatchObject({
		name: 'Buttercup entry',
		notes: 'notes',
		fields: [{ name: 'Recovery Code', value: 'backup', type: 0 }],
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'http://example.com' }] },
	});
});
test('Padlock positional CSV maps tagged folders, credentials, generic fields, and multiple collections', () => {
	const source = writeCsv([
		['Name', 'Tags', 'username', 'website', 'password', 'Recovery'],
		['Padlock entry', 'Personal, Shared', 'alice', 'example.com', 'secret', 'backup'],
	]);
	const personal = parseExternalCsv('padlockcsv', source), item = items(personal)[0]!;
	expect(personal.folders).toMatchObject([{ name: 'Personal' }]);
	expect(item).toMatchObject({
		name: 'Padlock entry',
		fields: [{ name: 'Recovery', value: 'backup', type: 0 }],
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'http://example.com' }] },
	});
	const organization = parseExternalCsv('padlockcsv', source, true), groups = organization.collections as JsonObject[];
	expect(groups.map(value => value.name)).toEqual(['Personal', 'Shared']);
	expect(items(organization)[0]!.collectionIds).toEqual(groups.map(value => value.id));
});
test('Yoti CSV maps its spaced username header', () => {
	const item = items(parseExternalCsv(
		'yoticsv',
		writeCsv([
			['Name', 'User name', 'Password', 'URL'],
			['Yoti entry', 'alice', 'secret', 'https://example.com'],
		]),
	))[0]!;
	expect(item).toMatchObject({
		name: 'Yoti entry',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
});
test('SaferPass CSV derives the item name from its URL and maps notes', () => {
	const item = items(parseExternalCsv(
		'saferpasscsv',
		writeCsv([
			['url', 'notes', 'username', 'password'],
			['https://www.example.com/login', 'SaferPass note', 'alice', 'secret'],
		]),
	))[0]!;
	expect(item).toMatchObject({
		name: 'example.com',
		notes: 'SaferPass note',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://www.example.com/login' }] },
	});
});
test('SecureSafe finds case-insensitive URL headers and maps account fields', () => {
	const item = items(parseExternalCsv(
		'securesafecsv',
		writeCsv([
			['Title', 'Comment', 'Username', 'Password', 'Web URL'],
			['SecureSafe entry', 'notes', 'alice', 'secret', 'https://example.com'],
		]),
	))[0]!;
	expect(item).toMatchObject({
		name: 'SecureSafe entry',
		notes: 'notes',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
});
test('Meldium CSV maps display name and account headers', () => {
	const item = items(parseExternalCsv(
		'meldiumcsv',
		writeCsv([
			['DisplayName', 'Notes', 'UserName', 'Password', 'Url'],
			['Meldium entry', 'notes', 'alice', 'secret', 'https://example.com'],
		]),
	))[0]!;
	expect(item).toMatchObject({
		name: 'Meldium entry',
		notes: 'notes',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
});
test('True Key CSV maps login, credit card, and secure-note records', () => {
	const source = writeCsv([
		[
			'kind',
			'name',
			'title',
			'favorite',
			'memo',
			'note',
			'login',
			'password',
			'url',
			'cardholder',
			'number',
			'expiryDate',
			'document_content',
			'Reference',
		],
		[
			'login',
			'True Key login',
			'',
			'true',
			'login note',
			'',
			'alice',
			'  secret  ',
			'https://example.com',
			'',
			'',
			'',
			'',
			'',
		],
		['cc', '', 'True Key card', 'false', '', '', '', '', '', 'Alice', '4111111111111111', '2030-06-01', '', ''],
		['note', '', 'True Key note', 'false', '', 'Caption', '', '', '', '', '', '', 'Document body', 'note reference'],
		['note', '', 'True Key document-only', 'false', '', '', '', '', '', '', '', '', 'Body without caption', ''],
		['note', '', 'True Key caption-only', 'false', '', 'Caption without body', '', '', '', '', '', '', '', ''],
	]);
	const parsed = items(parseExternalCsv('truekeycsv', source));
	expect(parsed).toHaveLength(5);
	expect(parsed[0]).toMatchObject({
		name: 'True Key login',
		favorite: true,
		notes: 'login note',
		login: { username: 'alice', password: '  secret  ', uris: [{ uri: 'https://example.com' }] },
	});
	expect(parsed[1]).toMatchObject({
		type: 3,
		name: 'True Key card',
		card: { cardholderName: 'Alice', brand: 'Visa', expYear: '2030', expMonth: '6' },
	});
	expect(parsed[2]).toMatchObject({
		type: 2,
		name: 'True Key note',
		notes: 'Document body',
		fields: [{ name: 'Reference', value: 'note reference', type: 0 }],
		secureNote: { type: 0 },
	});
	expect(parsed[3]).toMatchObject({ type: 2, notes: 'Body without caption' });
	expect(parsed[4]).toMatchObject({ type: 2, notes: 'Caption without body' });
});
test('SplashID positional CSV maps login details, continuation notes, and category grouping', () => {
	const source = writeCsv([
		[
			'Web Logins',
			'SplashID entry',
			'alice',
			'secret',
			'https://example.com',
			'recovery: 123',
			'owner: Alice',
			'tail note',
			'Work',
		],
		['Secure Note', 'SplashID note', 'first line', 'second line', 'tail note', 'Personal'],
	]);
	const personal = parseExternalCsv('splashidcsv', source), parsed = items(personal);
	expect(personal.folders).toMatchObject([{ name: 'Work' }, { name: 'Personal' }]);
	expect(parsed[0]).toMatchObject({
		name: 'SplashID entry',
		notes: 'tail noterecovery: 123\n',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
	expect(parsed[1]).toMatchObject({
		type: 2,
		name: 'SplashID note',
		notes: 'tail notefirst line\n',
		secureNote: { type: 0 },
	});
});
test('RememBear CSV skips trash and maps logins, cards, and card custom fields', () => {
	const source = writeCsv([
		[
			'type',
			'trash',
			'name',
			'notes',
			'website',
			'username',
			'password',
			'cardholder',
			'number',
			'verification',
			'expiryMonth',
			'expiryYear',
			'pin',
			'zipCode',
		],
		[
			'LoginItem',
			'false',
			'RememBear login',
			'login notes',
			'https://example.com',
			'alice',
			'secret',
			'',
			'',
			'',
			'',
			'',
			'',
			'',
		],
		[
			'CreditCardItem',
			'false',
			'RememBear card',
			'card notes',
			'',
			'',
			'',
			'Alice',
			'4111111111111111',
			'123',
			'06',
			'2030',
			'9876',
			'12345',
		],
		['LoginItem', 'true', 'Trashed item', '', 'https://trash.example', '', '', '', '', '', '', '', '', ''],
	]);
	const parsed = items(parseExternalCsv('remembearcsv', source));
	expect(parsed).toHaveLength(2);
	expect(parsed[0]).toMatchObject({ name: 'RememBear login', notes: 'login notes', login: { username: 'alice' } });
	expect(parsed[1]).toMatchObject({
		type: 3,
		name: 'RememBear card',
		notes: 'card notes',
		card: {
			cardholderName: 'Alice',
			number: '4111111111111111',
			brand: 'Visa',
			code: '123',
			expMonth: '6',
			expYear: '2030',
		},
		fields: [{ name: 'PIN', value: '9876', type: 0 }, { name: 'Zip Code', value: '12345', type: 0 }],
	});
});
test('UPM positional CSV maps name, account fields, URI, and notes', () => {
	const item = items(
		parseExternalCsv('upmcsv', writeCsv([['UPM entry', 'alice', 'secret', 'https://example.com', 'UPM note']])),
	)[0]!;
	expect(item).toMatchObject({
		name: 'UPM entry',
		notes: 'UPM note',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
	});
});
test('LogMeOnce maps named login columns and groups to folders or collections', () => {
	const source = writeCsv([
		['name', 'username', 'password', 'url', 'group'],
		['LogMeOnce entry', 'alice', 'secret', 'https://example.com/login', 'Work'],
		['Second entry', '', 'second-secret', '', 'Work'],
	]);
	const personal = parseExternalCsv('logmeoncecsv', source), personalItems = items(personal);
	expect(personal.folders).toMatchObject([{ name: 'Work' }]);
	expect(personalItems).toHaveLength(2);
	expect(personalItems[0]).toMatchObject({
		name: 'LogMeOnce entry',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com/login' }] },
	});
	expect(personalItems[0]!.folderId).toBe((personal.folders as JsonObject[])[0]!.id);
	const organization = parseExternalCsv('logmeoncecsv', source, true), orgItems = items(organization);
	expect(orgItems[0]!.folderId).toBeNull();
	expect(orgItems[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Myki maps login, card, identity, ID, two-factor, and note records with unmapped fields', () => {
	const parse = (records: Record<string, string>[]) => {
		const headers = [...new Set(records.flatMap(record => Object.keys(record)))];
		return items(parseExternalCsv(
			'mykicsv',
			writeCsv([
				headers,
				...records.map(record => headers.map(header => record[header] ?? '')),
			]),
		));
	};
	const account = parse([{
		nickname: 'PasswordNickname',
		url: 'www.google.com',
		username: 'user.name@email.com',
		password: 'abc123',
		additionalInfo: 'This is the additional information text.',
		twofaSecret: 'someTOTPSeed',
		status: 'active',
		tags: 'someTag',
	}]);
	expect(account[0]).toMatchObject({
		name: 'PasswordNickname',
		notes: 'This is the additional information text.',
		login: {
			username: 'user.name@email.com',
			password: 'abc123',
			totp: 'someTOTPSeed',
			uris: [{ uri: 'http://www.google.com' }],
		},
		fields: [{ name: 'status', value: 'active', type: 0 }, { name: 'tags', value: 'someTag', type: 0 }],
	});
	const card = parse([{
		nickname: 'Visa test card',
		status: 'active',
		tags: 'someTag',
		cardNumber: '4111111111111111',
		cardName: 'Joe User',
		exp_month: '04',
		exp_year: '24',
		cvv: '222',
		additionalInfo: 'This is the additional information field',
	}]);
	expect(card[0]).toMatchObject({
		type: 3,
		name: 'Visa test card',
		notes: 'This is the additional information field',
		card: {
			cardholderName: 'Joe User',
			number: '4111111111111111',
			brand: 'Visa',
			expMonth: '04',
			expYear: '24',
			code: '222',
		},
		fields: [{ name: 'status', value: 'active', type: 0 }, { name: 'tags', value: 'someTag', type: 0 }],
	});
	const identity = parse([{
		nickname: "Joe User's nickname",
		status: 'active',
		tags: 'someTag',
		firstName: 'Joe',
		middleName: 'M',
		lastName: 'User',
		email: 'joe.user@email.com',
		firstAddressLine: '1 Example House',
		secondAddressLine: 'Suite 300',
		title: 'Mr',
		gender: 'Male',
		number: '2223334444',
		city: 'Portland',
		country: 'United States',
		zipCode: '04101',
		additionalInfo: 'Additional information field',
	}]);
	expect(identity[0]).toMatchObject({
		type: 4,
		name: "Joe User's nickname",
		notes: 'Additional information field',
		identity: {
			firstName: 'Joe',
			middleName: 'M',
			lastName: 'User',
			title: 'Mr',
			phone: '2223334444',
			email: 'joe.user@email.com',
			address1: '1 Example House',
			address2: 'Suite 300',
			city: 'Portland',
			country: 'United States',
			postalCode: '04101',
		},
		fields: [
			{ name: 'status', value: 'active', type: 0 },
			{ name: 'tags', value: 'someTag', type: 0 },
			{ name: 'gender', value: 'Male', type: 0 },
			{ name: 'number', value: '2223334444', type: 0 },
		],
	});
	const idCards = parse([
		{
			nickname: 'Joe User ID',
			status: 'active',
			tags: 'someTag',
			idType: "Driver's License",
			idNumber: '123456',
			idName: 'Joe M User',
			idIssuanceDate: '02/02/2022',
			idExpirationDate: '02/02/2024',
			idCountry: 'United States',
			additionalInfo: 'Additional information',
		},
		{
			nickname: 'Passport ID card',
			status: 'active',
			tags: 'someTag',
			idType: 'Passport',
			idNumber: '1234567',
			idName: 'Joe M User',
			idIssuanceDate: '03/07/2022',
			idExpirationDate: '03/07/2028',
			idCountry: 'United States',
			additionalInfo: 'Additional information field',
		},
		{
			nickname: 'Social Security ID card',
			status: 'active',
			tags: 'someTag',
			idType: 'Social Security',
			idNumber: '123455678',
			idName: 'Joe M User',
			idIssuanceDate: '03/07/2022',
			idExpirationDate: '03/07/2028',
			idCountry: 'United States',
			additionalInfo: 'Additional information field text',
		},
	]);
	expect(idCards).toHaveLength(3);
	expect(idCards[0]).toMatchObject({
		type: 4,
		name: 'Joe User ID',
		notes: 'Additional information',
		identity: {
			firstName: 'Joe',
			middleName: 'M',
			lastName: 'User',
			country: 'United States',
			licenseNumber: '123456',
		},
		fields: [
			{ name: 'status', value: 'active', type: 0 },
			{ name: 'tags', value: 'someTag', type: 0 },
			{ name: 'idType', value: "Driver's License", type: 0 },
			{ name: 'idIssuanceDate', value: '02/02/2022', type: 0 },
			{ name: 'idExpirationDate', value: '02/02/2024', type: 0 },
		],
	});
	expect(idCards[1]).toMatchObject({ identity: { passportNumber: '1234567' } });
	expect(idCards[2]).toMatchObject({ identity: { ssn: '123455678' } });
	const twoFa = parse([{
		nickname: '2FA nickname',
		status: 'active',
		tags: 'someTag',
		authToken: 'someTOTPSeed',
		additionalInfo: 'Additional information field content. ',
	}]);
	expect(twoFa[0]).toMatchObject({
		name: '2FA nickname',
		notes: 'Additional information field content.',
		login: { totp: 'someTOTPSeed' },
		fields: [{ name: 'status', value: 'active', type: 0 }, { name: 'tags', value: 'someTag', type: 0 }],
	});
	const note = parse([{
		nickname: 'The title of a secure note',
		status: 'active',
		content: 'The content of a secure note. Lorem ipsum, etc.',
	}]);
	expect(note[0]).toMatchObject({
		type: 2,
		name: 'The title of a secure note',
		notes: 'The content of a secure note. Lorem ipsum, etc.',
		secureNote: { type: 0 },
		fields: [{ name: 'status', value: 'active', type: 0 }],
	});
});
test('mSecure CSV maps encoded fields, login/card/note types, and tag folders', () => {
	const source = writeCsv([
		[
			'Bitwarden|810974637',
			'Login',
			'Work',
			'',
			'Website|2|bitwarden.com',
			'Username|7|bitwarden user',
			'Password|8|bitpassword',
		],
		[
			'myCreditCard|155089404',
			'Credit Card',
			'Cards',
			'',
			'Card Number|12|41111111111111111',
			'Expiration Date|11|05/2026',
			'Security Code|9|123',
			'Name on Card|0|John Doe',
			'PIN|9|1234',
			'Issuing Bank|0|Visa',
			'Phone Number|4|',
			'Billing Address|0|',
		],
		['Secure Note|155089405', 'Secure Note', 'Personal', '', 'first line', 'second line'],
	]);
	const personal = parseExternalCsv('msecurecsv', source), parsed = items(personal);
	expect(parsed).toHaveLength(3);
	expect(personal.folders).toMatchObject([{ name: 'Work' }, { name: 'Cards' }, { name: 'Personal' }]);
	expect(parsed[0]).toMatchObject({
		name: 'Bitwarden',
		login: { username: 'bitwarden user', password: 'bitpassword', uris: [{ uri: 'http://bitwarden.com' }] },
		folderId: (personal.folders as JsonObject[])[0]!.id,
	});
	expect(parsed[1]).toMatchObject({
		type: 3,
		name: 'myCreditCard',
		card: {
			number: '41111111111111111',
			expMonth: '05',
			expYear: '2026',
			code: '123',
			cardholderName: 'John Doe',
			brand: 'Visa',
		},
		fields: [],
		folderId: (personal.folders as JsonObject[])[1]!.id,
	});
	expect(parsed[2]).toMatchObject({
		type: 2,
		name: 'Secure Note: Secure Note',
		notes: 'first line\nsecond line\n',
		secureNote: { type: 0 },
		folderId: (personal.folders as JsonObject[])[2]!.id,
	});
	const organization = parseExternalCsv('msecurecsv', source, true), orgItems = items(organization);
	expect(orgItems[0]!.folderId).toBeNull();
	expect(orgItems[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Password Agent CSV handles legacy, current and alternate layouts with folder mapping', () => {
	const legacy = items(parseExternalCsv(
		'passwordagentcsv',
		writeCsv([[
			'Legacy login',
			'alice',
			'secret',
			'example.com',
			'Legacy notes',
		]]),
	));
	expect(legacy[0]).toMatchObject({
		name: 'Legacy login',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'http://example.com' }] },
		notes: 'Legacy notes',
	});
	const currentSource = writeCsv([
		['Current login', 'alice', 'secret', 'Current notes', 'https://example.com/current', '', '', '', 'Work > Logins'],
		[
			'0',
			'Alternate login',
			'bob',
			'alternate-secret',
			'https://example.com/alternate',
			'Alternate notes',
			'',
			'',
			'',
			'Work>Logins',
		],
		['Note only', '', '', 'Only a note', '', '', '', '', '(None)'],
	]);
	const personal = parseExternalCsv('passwordagentcsv', currentSource), parsed = items(personal);
	expect(personal.folders).toMatchObject([{ name: 'Work/Logins' }]);
	expect(parsed).toHaveLength(3);
	expect(parsed[0]).toMatchObject({
		name: 'Current login',
		login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com/current' }] },
		notes: 'Current notes',
		folderId: (personal.folders as JsonObject[])[0]!.id,
	});
	expect(parsed[1]).toMatchObject({
		name: 'Alternate login',
		login: { username: 'bob', password: 'alternate-secret', uris: [{ uri: 'https://example.com/alternate' }] },
		notes: 'Alternate notes',
		folderId: (personal.folders as JsonObject[])[0]!.id,
	});
	expect(parsed[2]).toMatchObject({ type: 2, notes: 'Only a note', secureNote: { type: 0 } });
	const organization = parseExternalCsv('passwordagentcsv', currentSource, true), orgItems = items(organization);
	expect(orgItems[0]!.folderId).toBeNull();
	expect(orgItems[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});
test('Dashlane CSV maps credentials, payment, ID, personal information, and secure-note exports', () => {
	const credentials = items(parseExternalCsv(
		'dashlanecsv',
		writeCsv([
			['username', 'username2', 'username3', 'title', 'password', 'note', 'url', 'category', 'otpSecret'],
			[
				'jdoe',
				'alternate',
				'',
				'example.com',
				'somePassword',
				'some note for example.com',
				'https://www.example.com',
				'Entertainment',
				'someTOTPSeed',
			],
		]),
	));
	expect(credentials[0]).toMatchObject({
		name: 'example.com',
		notes: 'some note for example.com',
		login: {
			username: 'jdoe',
			password: 'somePassword',
			totp: 'someTOTPSeed',
			uris: [{ uri: 'https://www.example.com' }],
		},
		fields: [{ name: 'username2', value: 'alternate', type: 0 }],
	});
	const otpUrl = items(parseExternalCsv(
		'dashlanecsv',
		writeCsv([
			['username', 'title', 'password', 'note', 'url', 'category', 'otpUrl'],
			['jdoe', 'OTP URL login', 'secret', '', 'https://example.com', '', 'anotherTOTPSeed'],
		]),
	));
	expect(otpUrl[0]!.login).toMatchObject({ totp: 'anotherTOTPSeed' });
	const payments = items(parseExternalCsv(
		'dashlanecsv',
		writeCsv([
			[
				'type',
				'account_name',
				'account_holder',
				'cc_number',
				'code',
				'expiration_month',
				'expiration_year',
				'routing_number',
				'account_number',
				'country',
				'issuing_bank',
			],
			['bank', "John's savings account", 'John Doe', '', '', '', '', 'routingNumber', 'accountNumber', 'US', 'US-ALLY'],
			['credit_card', 'John Doe', '', '41111111111111111', '123', '01', '2023', '', '', 'US', ''],
		]),
	));
	expect(payments).toHaveLength(2);
	expect(payments[0]).toMatchObject({
		type: 3,
		name: "John's savings account",
		card: { cardholderName: 'John Doe', number: 'accountNumber' },
		fields: [
			{ name: 'type', value: 'bank', type: 0 },
			{ name: 'routing_number', value: 'routingNumber', type: 0 },
			{ name: 'country', value: 'US', type: 0 },
			{ name: 'issuing_bank', value: 'US-ALLY', type: 0 },
		],
	});
	expect(payments[1]).toMatchObject({
		type: 3,
		name: 'John Doe',
		card: {
			cardholderName: 'John Doe',
			number: '41111111111111111',
			brand: 'Visa',
			code: '123',
			expMonth: '1',
			expYear: '2023',
		},
		fields: [{ name: 'type', value: 'credit_card', type: 0 }, { name: 'country', value: 'US', type: 0 }],
	});
	const ids = items(parseExternalCsv(
		'dashlanecsv',
		writeCsv([
			['type', 'number', 'name', 'issue_date', 'expiration_date', 'place_of_issue', 'state'],
			['card', '123123123', 'John Doe', '2022-1-30', '2032-1-30', '', ''],
			['passport', '123123123', 'John Doe', '2022-1-30', '2032-1-30', 'Germany', ''],
			['license', '1234556', 'John Doe', '2022-8-10', '2022-10-10', '', 'DC'],
			['social_security', '123123123', 'John Doe', '', '', '', ''],
			['tax_number', '123123123', '', '', '', '', ''],
		]),
	));
	expect(ids).toHaveLength(5);
	expect(ids[0]).toMatchObject({
		name: 'John Doe card',
		type: 4,
		identity: { firstName: 'John', lastName: 'Doe', licenseNumber: '123123123' },
	});
	expect(ids[1]).toMatchObject({ name: 'John Doe passport', identity: { passportNumber: '123123123' } });
	expect(ids[2]).toMatchObject({ name: 'John Doe license', identity: { licenseNumber: '1234556', state: 'DC' } });
	expect(ids[3]).toMatchObject({ name: 'John Doe social_security', identity: { ssn: '123123123' } });
	expect(ids[4]).toMatchObject({ name: 'tax_number', identity: { licenseNumber: '123123123' } });
	const personalInfo = items(parseExternalCsv(
		'dashlanecsv',
		writeCsv([
			[
				'type',
				'title',
				'first_name',
				'middle_name',
				'last_name',
				'login',
				'date_of_birth',
				'place_of_birth',
				'email',
				'email_type',
				'item_name',
				'phone_number',
				'address',
				'country',
				'state',
				'city',
				'zip',
				'address_recipient',
				'address_building',
				'address_apartment',
				'address_floor',
				'address_door_code',
				'job_title',
				'url',
			],
			[
				'name',
				'MR',
				'John',
				'',
				'Doe',
				'jdoe',
				'2022-01-30',
				'world',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
			],
			[
				'email',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'jdoe@example.com',
				'personal',
				'Johns email',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
			],
			[
				'number',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				"John's number",
				'+49123123123',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
			],
			[
				'address',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				'',
				"John's home address",
				'',
				'1 some street',
				'de',
				'DE-0-NW',
				'some city',
				'123123',
				'John',
				'1',
				'1',
				'1',
				'123',
				'',
				'',
			],
		]),
	));
	expect(personalInfo).toHaveLength(1);
	expect(personalInfo[0]).toMatchObject({
		type: 4,
		name: 'John Doe',
		identity: {
			title: 'MR',
			firstName: 'John',
			lastName: 'Doe',
			username: 'jdoe',
			email: 'jdoe@example.com',
			phone: '+49123123123',
			address1: '1 some street',
			country: 'de',
			state: 'DE-0-NW',
			city: 'some city',
			postalCode: '123123',
		},
		fields: [
			{ name: 'date_of_birth', value: '2022-01-30', type: 0 },
			{ name: 'place_of_birth', value: 'world', type: 0 },
			{ name: 'email_type', value: 'personal', type: 0 },
			{ name: 'address_recipient', value: 'John', type: 0 },
			{ name: 'address_building', value: '1', type: 0 },
			{ name: 'address_apartment', value: '1', type: 0 },
			{ name: 'address_floor', value: '1', type: 0 },
			{ name: 'address_door_code', value: '123', type: 0 },
		],
	});
	const multiplePersonalInfo = items(parseExternalCsv(
		'dashlanecsv',
		writeCsv([
			[
				'type',
				'title',
				'first_name',
				'middle_name',
				'last_name',
				'login',
				'email',
				'email_type',
				'item_name',
				'phone_number',
				'address',
				'country',
				'state',
				'city',
				'zip',
				'note',
			],
			['name', 'Ms', 'Alice', '', 'Example', 'alice', '', '', '', '', '', '', '', '', '', ''],
			['email', '', '', '', '', '', 'alice@example.com', 'personal', 'Alice email', '', '', '', '', '', '', ''],
			['name', 'Mr', 'Bob', '', 'Example', 'bob', '', '', '', '', '', '', '', '', '', ''],
		]),
	));
	expect(multiplePersonalInfo).toHaveLength(3);
	expect(multiplePersonalInfo.map(item => [item.type, item.name])).toEqual([
		[2, 'Ms Alice Example'],
		[2, 'Alice email'],
		[2, 'Mr Bob Example'],
	]);
	const note = items(
		parseExternalCsv('dashlanecsv', writeCsv([['title', 'note'], ['Dashlane note', 'Secret note body']])),
	);
	expect(note[0]).toMatchObject({ type: 2, name: 'Dashlane note', notes: 'Secret note body', secureNote: { type: 0 } });
});
test('NordPass maps all four item types, JSON fields/URLs, expiration, and personal/organization grouping', () => {
	const source = nordPassCsv([
		{
			type: 'password',
			name: 'Login',
			username: ' alice ',
			password: '  secret  ',
			url: 'example.com/a,b',
			additional_urls: JSON.stringify(['https://second.example', '']),
			folder: '\\Work\\Web',
			note: 'notes',
			custom_fields: JSON.stringify([
				{ label: 'Hidden', type: 'hidden', value: ' literal ' },
				{ label: 'Long', type: 'text', value: 'x'.repeat(201) },
				{ label: 'Blank', type: 'text', value: '  ' },
			]),
		},
		{
			type: 'credit_card',
			name: 'Card',
			cardholdername: 'Alice',
			cardnumber: '4111111111111111',
			cvc: '123',
			expirydate: ' 06 / 30 ',
			folder: 'Work/Web',
		},
		{
			type: 'identity',
			name: 'Identity',
			full_name: 'Alice Middle Last Name',
			country: 'nl',
			phone_number: '123',
			address1: 'Street',
			address2: 'Unit',
			city: 'City',
			state: 'State',
			zipcode: '1234',
			email: 'alice@example.com',
		},
		{ type: 'note', name: 'Note', note: 'line1\nline2' },
		{ type: 'unsupported', name: 'Ignored', folder: 'Ignored folder', custom_fields: 'invalid JSON' },
	]);
	const personal = parseExternalCsv('nordpasscsv', source), parsed = items(personal);
	expect(personal.folders).toMatchObject([{ name: 'Work/Web' }]);
	expect(parsed).toHaveLength(4);
	expect(parsed[0]).toMatchObject({
		name: 'Login',
		fields: [{ name: 'Hidden', value: ' literal ', type: 1 }],
		login: {
			username: ' alice ',
			password: '  secret  ',
			uris: [{ uri: 'http://example.com/a,b' }, { uri: 'https://second.example' }],
		},
	});
	expect(parsed[0]!.notes).toBe(`notesLong: ${'x'.repeat(201)}\n`);
	expect(parsed[1]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'Alice',
			brand: 'Visa',
			number: '4111111111111111',
			code: '123',
			expMonth: '6',
			expYear: '2030',
		},
	});
	expect(parsed[2]).toMatchObject({
		type: 4,
		identity: {
			firstName: 'Alice',
			middleName: 'Middle',
			lastName: 'Last Name',
			country: 'NL',
			phone: '123',
			postalCode: '1234',
		},
	});
	expect(parsed[3]).toMatchObject({ type: 2, secureNote: { type: 0 }, notes: 'line1\nline2' });
	const organization = parseExternalCsv('nordpasscsv', source, true);
	expect(organization.collections).toMatchObject([{ name: 'Work/Web' }]);
	const collection = (organization.collections as JsonObject[])[0]!;
	expect(items(organization).slice(0, 2).map(item => item.collectionIds)).toEqual([[collection.id], [collection.id]]);
	expect(items(organization).every(item => item.folderId === null)).toBe(true);
});
test('NordPass invalid JSON and typed array entries fail without including secrets in diagnostics', () => {
	for (
		const [column, value] of [
			['additional_urls', 'SYNTHETIC_SECRET_INVALID_JSON'],
			['additional_urls', '{}'],
			['additional_urls', '[123]'],
			['custom_fields', 'SYNTHETIC_SECRET_INVALID_JSON'],
			['custom_fields', '{}'],
			['custom_fields', '[null]'],
			['custom_fields', '[{"label":"Secret","value":123}]'],
		]
	) {
		try {
			parseExternalCsv('nordpasscsv', nordPassCsv([{ type: 'password', [column!]: value! }]));
			throw new Error('Expected invalid NordPass input to fail.');
		} catch (error) {
			expect(String(error)).toContain('Invalid NordPass');
			expect(String(error)).not.toContain('SYNTHETIC_SECRET');
		}
	}
	expect(items(parseExternalCsv('nordpasscsv', 'type,note\nnote,hello'))[0]).toMatchObject({
		name: '--',
		notes: 'hello',
	});
});
test('browser CSV reads literal URI commas and secret whitespace and normalizes Android apps', () => {
	const chrome = items(parseExternalCsv(
		'chromecsv',
		writeCsv([
			['name', 'url', 'username', 'password', 'note'],
			['Browser', 'https://example.com/path,a', 'alice', '  secret  ', 'line1\nline2'],
			['', 'android://hash@com.example.app/', '', '', ''],
		]),
	));
	expect(chrome[0]).toMatchObject({
		name: 'Browser',
		notes: 'line1\nline2',
		login: { password: '  secret  ', uris: [{ uri: 'https://example.com/path,a' }] },
	});
	expect(chrome[1]).toMatchObject({
		name: 'com.example.app',
		login: { uris: [{ uri: 'androidapp://com.example.app' }] },
	});
	const firefox = items(parseExternalCsv(
		'firefoxcsv',
		writeCsv([
			['url', 'username', 'password'],
			['https://www.example.com/login', 'bob', 'secret'],
			['chrome://FirefoxAccounts', 'internal', 'internal'],
		]),
	));
	expect(firefox).toHaveLength(1);
	expect(firefox[0]!.name).toBe('example.com');
	expect(items(parseExternalCsv('firefoxcsv', 'hostname,username,password\nexample.org,alice,secret'))[0])
		.toMatchObject({ name: 'example.org', login: { uris: [{ uri: 'http://example.org' }] } });
});
test('Chromium aliases import notes and normalize Android entries while Arc derives names from URLs', () => {
	const source = writeCsv([
		['name', 'url', 'username', 'password', 'note'],
		['Display name', 'https://www.example.com/a,b', ' alice ', '  secret  ', 'line1\nline2'],
		['', 'android://hash@com.example.app/', 'app', 'secret', 'app notes'],
	]);
	const expected = parseExternalCsv('chromecsv', source);
	for (const format of ['edgecsv', 'operacsv', 'vivaldicsv', 'bravecsv'] as const) {
		expect(parseExternalCsv(format, source)).toEqual(expected);
	}
	expect(items(parseExternalCsv('arccsv', source))[0]).toMatchObject({
		name: 'example.com',
		notes: 'line1\nline2',
		login: { username: ' alice ', password: '  secret  ', uris: [{ uri: 'https://www.example.com/a,b' }] },
	});
});
test('Avira maps website, optional hostname names, and alternate usernames without discarding either identity', () => {
	const parsed = items(parseExternalCsv(
		'aviracsv',
		writeCsv([
			['name', 'website', 'username', 'secondary_username', 'password'],
			['Named', 'example.com/a,b', ' alice ', 'alternate@example.com', '  secret  '],
			['', 'https://www.other.example/path', ' ', ' alternate ', 'secret'],
			['', '', '', '', 'secret'],
		]),
	));
	expect(parsed[0]).toMatchObject({
		name: 'Named',
		notes: 'alternate@example.com',
		login: { username: ' alice ', password: '  secret  ', uris: [{ uri: 'http://example.com/a,b' }] },
	});
	expect(parsed[1]).toMatchObject({ name: 'other.example', notes: null, login: { username: ' alternate ' } });
	expect(parsed[2]).toMatchObject({ name: '--', notes: null, login: { username: null, uris: [] } });
});
test('Passbolt uses the LastPass mapping including structured records and grouping', () => {
	const source = writeCsv([
		['url', 'name', 'username', 'password', 'extra', 'grouping', 'fav'],
		['https://example.com', 'Passbolt', 'alice', ' secret ', 'notes', 'Work\\Web', '1'],
		['http://sn', 'Note', '', '', 'multiline\nnotes', 'Work\\Web', '0'],
	]);
	const parsed = parseExternalCsv('passboltcsv', source);
	expect(parsed.folders).toMatchObject([{ name: 'Work/Web' }]);
	expect(items(parsed)[0]).toMatchObject({ favorite: true, notes: 'notes', login: { password: ' secret ' } });
	expect(items(parsed)[1]).toMatchObject({ type: 2, notes: 'multiline\nnotes' });
});
test('Safari OTP/notes and KeePassX groups are translated into native import documents', () => {
	expect(
		items(parseExternalCsv(
			'safaricsv',
			writeCsv([
				['Title', 'Url', 'Username', 'Password', 'Notes', 'OTPAuth'],
				['Safari', 'https://example.com', 'alice', 'secret', 'notes', 'otpauth://totp/x?secret=ABC'],
			]),
		))[0],
	).toMatchObject({ name: 'Safari', notes: 'notes', login: { totp: 'otpauth://totp/x?secret=ABC' } });
	const document = parseExternalCsv(
		'keepassxcsv',
		writeCsv([
			['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP'],
			['Root/Work\\Web', 'Entry', 'alice', 'secret', 'example.com/a,b', 'notes', 'ABC'],
			['Root/Ignored', '  ', 'ignored', 'ignored', 'ignored', '', ''],
		]),
		true,
	);
	expect(document.collections).toMatchObject([{ name: 'Work/Web' }]);
	expect(items(document)).toHaveLength(1);
	expect(items(document)[0]).toMatchObject({
		folderId: null,
		collectionIds: [(document.collections as JsonObject[])[0]!.id],
		login: { totp: 'ABC', uris: [{ uri: 'http://example.com/a,b' }] },
	});
});
test('LastPass site, secure note, structured card and identity import groups and unrecognized fields', () => {
	const document = parseExternalCsv(
		'lastpasscsv',
		writeCsv([
			['url', 'username', 'password', 'extra', 'name', 'grouping', 'fav', 'totp'],
			['https://example.com/a,b', 'alice', 'secret', 'notes', 'Site', 'Work\\Web', '1', 'ABC'],
			[
				'http://sn',
				'',
				'',
				'NoteType:Credit Card\nNumber:4111111111111111\nName on Card:Alice\nSecurity Code:123\nExpiration Date:June,2030\nIssuer:Example\nNotes:note\ncontinuation:marker',
				'Card',
				'Work\\Web',
				'0',
				'',
			],
			[
				'http://sn',
				'',
				'',
				'NoteType:Address\nFirst Name:Alice\nLast Name:Example\nAddress 1:Street\nUnknown:marker',
				'Identity',
				'(none)',
				'0',
				'',
			],
			[
				'http://sn',
				'',
				'',
				'NoteType:Bank Account\nAccount Number:123\nNotes:entire record',
				'Legacy note',
				'',
				'0',
				'',
			],
		]),
	);
	expect(document.folders).toMatchObject([{ name: 'Work/Web' }]);
	const parsed = items(document);
	expect(parsed[0]).toMatchObject({
		favorite: true,
		login: { totp: 'ABC', uris: [{ uri: 'https://example.com/a,b' }] },
	});
	expect(parsed[1]).toMatchObject({
		type: 3,
		card: { number: '4111111111111111', cardholderName: 'Alice', code: '123', expMonth: '6', expYear: '2030' },
		fields: [{ name: 'Issuer', value: 'Example' }],
		notes: 'note\ncontinuation:marker',
	});
	expect(parsed[2]).toMatchObject({
		type: 4,
		identity: { firstName: 'Alice', lastName: 'Example' },
		fields: [{ name: 'Unknown', value: 'marker' }],
		folderId: null,
	});
	expect(parsed[3]).toMatchObject({ type: 2, notes: 'NoteType:Bank Account\nAccount Number:123\nNotes:entire record' });
});
test('LastPass form-fill identities import an accompanying card', () => {
	const document = parseExternalCsv(
		'lastpasscsv',
		writeCsv([
			['profilename', 'profilelanguage', 'firstname', 'lastname', 'ccname', 'ccnum', 'cccsc', 'ccexp'],
			['Profile', 'en', 'Alice', 'Example', 'Alice Example', '4111111111111111', '123', '2030-06'],
		]),
	);
	expect(items(document)).toHaveLength(2);
	expect(items(document)[0]).toMatchObject({ type: 3, card: { brand: 'Visa', expMonth: '6', expYear: '2030' } });
	expect(items(document)[1]).toMatchObject({ type: 4, identity: { firstName: 'Alice', lastName: 'Example' } });
});
test('LastPass HTML exports extract CSV from preformatted text and decode entities', () => {
	const document = parseExternalCsv(
		'lastpasscsv',
		'<!doctype html><html><body><pre>url,username,password,extra,name,grouping,fav\nhttps://example.com,alice,secret,&lt;notes&gt;,Tea &amp; Coffee,Personal,1</pre></body></html>',
	);
	expect(items(document)).toMatchObject([
		{
			name: 'Tea & Coffee',
			favorite: true,
			notes: '<notes>',
			login: { username: 'alice', password: 'secret', uris: [{ uri: 'https://example.com' }] },
		},
	]);
	expect(document.folders).toMatchObject([{ name: 'Personal' }]);
});
test('LastPass HTML exports without a preformatted CSV block are rejected', () => {
	expect(() => parseExternalCsv('lastpasscsv', '<html><body>no export</body></html>'))
		.toThrow('LastPass HTML export is missing its CSV data.');
});
test('external imports reject malformed headers and rows before sending data', async () => {
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: (async () => {
			calls++;
			return Response.json({});
		}) as unknown as typeof fetch,
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, Buffer.alloc(64, 7));
	for (const source of ['name\ninvalid', 'url,username,password,password\nx,a,b,c', 'url,username,password\nx,a']) {
		await expect(vault.importVault('chromecsv', source)).rejects.toThrow();
	}
	await expect(vault.importVault(
		'nordpasscsv',
		nordPassCsv([
			{ type: 'password', name: 'Valid first row', password: 'synthetic secret' },
			{ type: 'password', name: 'Invalid later row', additional_urls: 'invalid JSON' },
		]),
	)).rejects.toThrow('Invalid NordPass');
	expect(calls).toBe(0);
	vault.dispose();
});
test('external CSV imports use fresh encrypted item keys and remap grouping relationships', async () => {
	const key = Buffer.alloc(64, 7);
	let calls = 0;
	const client = new VaultwardenClient('https://example.com', {
		fetch: withImportSync(async (_url: unknown, init?: RequestInit) => {
			calls++;
			const body = JSON.parse(String(init!.body));
			expect(body.folderRelationships).toEqual([{ key: 0, value: 0 }]);
			expect(decrypt(body.folders[0].name, key).toString()).toBe('Work');
			const cipher = object(body.ciphers[0]);
			const itemKey = decrypt(String(cipher.key), key);
			try {
				expect(itemKey.equals(key)).toBe(false);
			} finally {
				itemKey.fill(0);
			}
			expect(decryptOwnedItem(cipher, key)).toMatchObject({
				name: 'Imported',
				login: { password: 'synthetic-password', uris: [{ uri: 'https://example.com/a,b' }] },
			});
			expect(String(init!.body).includes('synthetic-password')).toBe(false);
			return new Response(null, { status: 204 });
		}),
	});
	const vault = new VaultService(client, 'access', { profile: { id: 'fixture' }, ciphers: [] }, key);
	expect(
		await vault.importVault(
			'keepassxcsv',
			'Group,Title,Username,Password,URL\nRoot/Work,Imported,alice,synthetic-password,"https://example.com/a,b"',
		),
	).toEqual({ items: 1, folders: 1, collections: 0, attachments: 0 });
	expect(calls).toBe(1);
	vault.dispose();
});
