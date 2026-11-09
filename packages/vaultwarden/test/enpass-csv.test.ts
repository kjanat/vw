import { expect, test } from 'bun:test';
import { parseExternalCsv } from '#csv-import';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];

test('Enpass CSV maps real login labels, repeated websites, TOTP, and sensitive fields', () => {
	const result = parseExternalCsv(
		'enpasscsv',
		[
			'Booking,Username,,E-mail,rwilson@example.com,*Password,  secret  ,Website,https://booking.example,Website,https://booking.example/sign-in',
			'Site,Username,alice,E-mail,alice@example.com,*Password,password,One-time code,totp-seed,*Security answer,42',
		].join('\n'),
	);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'Booking',
		login: {
			username: 'rwilson@example.com',
			password: '  secret  ',
			uris: [
				{ uri: 'https://booking.example', match: null },
				{ uri: 'https://booking.example/sign-in', match: null },
			],
		},
	});
	expect(items(result)[1]).toMatchObject({
		login: { username: 'alice', password: 'password', totp: 'totp-seed' },
		fields: [
			{ name: 'E-mail', value: 'alice@example.com', type: 0 },
			{ name: 'Security answer', value: '42', type: 1 },
		],
	});
});

test('Enpass CSV handles headers, notes, quoted values, and login classification', () => {
	const result = parseExternalCsv(
		'enpasscsv',
		[
			'Title,Username,Password',
			'"Quoted, title",Username,alice,*Password,secret,Some trailing note text',
			'Router,*Password,secret',
			'Sticky,Username,user,password,secret,Website,https://example.com',
			'MyNote,Some note text',
		].join('\n'),
	);
	expect(items(result)).toHaveLength(4);
	expect(items(result)[0]).toMatchObject({
		name: 'Quoted, title',
		login: { username: 'alice', password: 'secret' },
		notes: 'Some trailing note text',
	});
	expect(items(result)[1]).toMatchObject({ type: 1, name: 'Router', login: { password: 'secret' } });
	expect(items(result)[2]).toMatchObject({ type: 1, name: 'Sticky', login: { username: 'user', password: 'secret' } });
	expect(items(result)[3]).toMatchObject({ type: 2, name: 'MyNote', notes: 'Some note text', secureNote: { type: 0 } });
});

test('Enpass CSV maps cards and card expiration, storing invalid expiry as custom data', () => {
	const result = parseExternalCsv(
		'enpasscsv',
		[
			'Visa,Cardholder,John Doe,*Number,4111111111111111,Type,Visa,*CVC,123,Expiry date,01/2030',
			'Card,Cardholder,Jane Doe,Number,5555555555554444,Expiry date,15/2030',
		].join('\n'),
	);
	expect(items(result)[0]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'John Doe',
			number: '4111111111111111',
			brand: 'Visa',
			code: '123',
			expMonth: '1',
			expYear: '2030',
		},
	});
	expect(items(result)[1]).toMatchObject({
		type: 3,
		card: { cardholderName: 'Jane Doe', number: '5555555555554444', brand: 'Mastercard' },
		fields: [{ name: 'Expiry date', value: '15/2030', type: 0 }],
	});
	expect(result.folders).toEqual([]);
});

test('Enpass CSV exports no rows for header-only input and handles organization scope', () => {
	expect(parseExternalCsv('enpasscsv', 'Title,Username,Password').items).toEqual([]);
	expect(parseExternalCsv('enpasscsv', 'MyNote,Some note', true)).toMatchObject({
		items: [{ type: 2, name: 'MyNote' }],
		collections: [],
	});
});
