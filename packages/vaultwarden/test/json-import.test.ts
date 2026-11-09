import { expect, test } from 'bun:test';
import { bwCardBrand, parseExternalJson } from '#json-import';
import type { JsonObject } from '#client';

const items = (value: JsonObject) => value.items as JsonObject[];

test('card-brand patterns match the pinned bw CardView rules', () => {
	const cases: [string, string | null][] = [
		['4111111111111111', 'Visa'],
		['2221000000000000', 'Mastercard'],
		['2220000000000000', null],
		['378282246310005', 'Amex'],
		['6221260000000000', 'Discover'],
		['6221250000000000', null],
		['36148900647913', 'Diners Club'],
		['38123456789012', null],
		['3528000000000000', 'JCB'],
		['3500000000000000', null],
		['4026000000000000', 'Visa'],
		[' 4111111111111111', null],
		['6212345678901234', null],
	];
	for (const [number, expected] of cases) expect(bwCardBrand(number)).toBe(expected);
	expect(bwCardBrand(null)).toBeNull();
	expect(bwCardBrand('  ')).toBeNull();
});

test('Avast JSON maps logins, secure notes, and payment cards', () => {
	const result = parseExternalJson(
		'avastjson',
		JSON.stringify({
			logins: [{
				custName: 'Avast login',
				note: 'login note',
				url: 'example.com/login',
				pwd: '  secret  ',
				loginName: 'alice',
			}],
			notes: [{ label: 'Avast note', text: 'secure note body' }],
			cards: [{
				custName: 'Avast card',
				note: 'card note',
				holderName: 'Alice Example',
				cardNumber: '4111111111111111',
				cvv: '123',
				expirationDate: { month: 6, year: 2030 },
			}],
		}),
	);
	expect(items(result)).toHaveLength(3);
	expect(items(result)[0]).toMatchObject({
		name: 'Avast login',
		notes: 'login note',
		login: {
			username: 'alice',
			password: '  secret  ',
			uris: [{ uri: 'http://example.com/login', match: null }],
		},
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		name: 'Avast note',
		notes: 'secure note body',
		secureNote: { type: 0 },
	});
	expect(items(result)[2]).toMatchObject({
		type: 3,
		name: 'Avast card',
		notes: 'card note',
		card: {
			cardholderName: 'Alice Example',
			number: '4111111111111111',
			code: '123',
			brand: 'Visa',
			expMonth: '6',
			expYear: '2030',
		},
	});
	expect(result.folders).toEqual([]);
});

test('Avast JSON rejects malformed input without echoing it', () => {
	const secret = 'private-import-payload';
	expect(() => parseExternalJson('avastjson', `{not json ${secret}`)).toThrow('Invalid Avast JSON.');
	expect(() => parseExternalJson('avastjson', JSON.stringify({ logins: {} }))).toThrow(
		'Invalid Avast JSON login records.',
	);
	expect(JSON.stringify(parseExternalJson('avastjson', JSON.stringify({ logins: [{ private: secret }] })))).not
		.toContain(secret);
});

test('F-Secure FSK JSON maps logins, cards, favorites, and unknown entry types', () => {
	const document = parseExternalJson(
		'fsecurefsk',
		JSON.stringify({
			data: {
				'1c3a2e31dcaa8459edd70a9d895ce298': {
					type: 1,
					service: 'example.com',
					username: 'jdoe',
					password: 'somePassword',
					url: 'https://www.example.com',
					notes: 'some note for example.com',
					favorite: 1666440874,
				},
				'156498a46a3254f16035cbbbd09c2b8f': {
					type: 2,
					service: 'My credit card',
					username: 'John Doe',
					creditNumber: '4242424242424242',
					creditCvv: '123',
					creditExpiry: '22.10.2026',
					password: '1234',
					notes: 'some notes to my card',
					favorite: 0,
				},
				unsupported: { type: 3, service: 'Ignored entry' },
			},
		}),
	);
	expect(items(document)).toHaveLength(2);
	expect(items(document)[0]).toMatchObject({
		name: 'example.com',
		favorite: true,
		notes: 'some note for example.com',
		login: {
			username: 'jdoe',
			password: 'somePassword',
			uris: [{ uri: 'https://www.example.com', match: null }],
		},
	});
	expect(items(document)[1]).toMatchObject({
		type: 3,
		name: 'My credit card',
		notes: 'some notes to my card',
		card: {
			cardholderName: 'John Doe',
			number: '4242424242424242',
			brand: 'Visa',
			code: '123',
		},
		fields: [
			{ name: 'Expiration', value: '22.10.2026', type: 0 },
			{ name: 'PIN', value: '1234', type: 0 },
		],
	});
});

test('F-Secure FSK JSON rejects malformed exports with fixed errors', () => {
	const secret = 'private-fsecure-payload';
	expect(() => parseExternalJson('fsecurefsk', `{broken ${secret}`)).toThrow('Invalid F-Secure FSK JSON.');
	expect(() => parseExternalJson('fsecurefsk', JSON.stringify({ data: [] }))).toThrow(
		'Invalid F-Secure FSK JSON.',
	);
	expect(() => parseExternalJson('fsecurefsk', JSON.stringify({ data: { entry: null } }))).toThrow(
		'Invalid F-Secure FSK entry.',
	);
});

test('F-Secure FSK card brands match bw Discover BIN recognition', () => {
	const result = parseExternalJson(
		'fsecurefsk',
		JSON.stringify({ data: { card: { type: 2, service: 'Discover', creditNumber: '6221260000000000' } } }),
	);
	expect(items(result)[0]!.card).toMatchObject({ number: '6221260000000000', brand: 'Discover' });
});

test('Proton Pass JSON imports supported Vaultwarden item types, fields, favorites, and vault folders', () => {
	const extra = (fieldName: string, content: string, type = 'text') => ({ fieldName, type, data: { content } });
	const result = parseExternalJson(
		'protonpass',
		JSON.stringify({
			encrypted: false,
			vaults: {
				vault: {
					name: 'Personal',
					items: [
						{
							state: 1,
							pinned: true,
							data: {
								type: 'login',
								metadata: { name: 'Proton login', note: 'login note' },
								content: {
									itemUsername: 'alice',
									itemEmail: 'alice@example.test',
									password: 'secret',
									urls: ['proton.example.test'],
									totpUri: 'otpauth://totp/test',
								},
								extraFields: [extra('Recovery', 'backup-code'), extra('Private', 'hidden-value', 'hidden')],
							},
						},
						{
							state: 1,
							pinned: false,
							data: {
								type: 'note',
								metadata: { name: 'Secure note', note: 'body' },
								content: {},
								extraFields: [extra('Note field', 'value')],
							},
						},
						{
							state: 1,
							data: {
								type: 'creditCard',
								metadata: { name: 'Card' },
								content: {
									cardholderName: 'Alice',
									number: '4111111111111111',
									verificationNumber: '123',
									expirationDate: '2030-06-01',
									pin: '1234',
								},
								extraFields: [],
							},
						},
						{
							state: 1,
							data: {
								type: 'identity',
								metadata: { name: 'Identity' },
								content: {
									fullName: 'Alice Q Example',
									email: 'alice@example.test',
									birthdate: '2000-01-01',
									gender: 'Other',
									extraSections: [{ sectionFields: [extra('Section', 'section-value')] }],
								},
								extraFields: [],
							},
						},
						{
							state: 1,
							aliasEmail: 'alias@example.test',
							data: { type: 'alias', metadata: { name: 'Alias' }, content: {}, extraFields: [] },
						},
						{
							state: 1,
							data: {
								type: 'sshKey',
								metadata: { name: 'SSH' },
								content: {
									privateKey: 'private',
									publicKey: 'public',
									fingerprint: 'SHA256:abc',
									sections: [{ sectionFields: [extra('Host', 'example.test')] }],
								},
								extraFields: [],
							},
						},
						{
							state: 1,
							data: {
								type: 'wifi',
								metadata: { name: 'WiFi' },
								content: { ssid: 'office', password: 'wifi-secret', security: 3 },
								extraFields: [],
							},
						},
						{
							state: 1,
							data: {
								type: 'custom',
								metadata: { name: 'Custom' },
								content: {
									sections: [{ sectionFields: [extra('Account', '1234'), extra('PIN', '5678', 'hidden')] }],
									count: 3,
								},
								extraFields: [],
							},
						},
						{ state: 2, data: { type: 'note', metadata: { name: 'Trashed' }, content: {}, extraFields: [] } },
					],
				},
			},
		}),
	);
	expect(items(result)).toHaveLength(8);
	expect(items(result)[0]).toMatchObject({
		name: 'Proton login',
		favorite: true,
		notes: 'login note',
		login: {
			username: 'alice',
			password: 'secret',
			totp: 'otpauth://totp/test',
			uris: [{ uri: 'http://proton.example.test', match: null }],
		},
		fields: [
			{ name: 'email', value: 'alice@example.test', type: 0 },
			{ name: 'Recovery', value: 'backup-code', type: 0 },
			{ name: 'Private', value: 'hidden-value', type: 1 },
		],
		folderId: expect.any(String),
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		notes: 'body',
		fields: [{ name: 'Note field', value: 'value', type: 0 }],
	});
	expect(items(result)[2]).toMatchObject({
		type: 3,
		card: { brand: 'Visa', expMonth: '6', expYear: '2030', code: '123' },
		fields: [{ name: 'PIN', value: '1234', type: 1 }],
	});
	expect(items(result)[3]).toMatchObject({
		type: 4,
		identity: { firstName: 'Alice', middleName: 'Q', lastName: 'Example', email: 'alice@example.test' },
		fields: [
			{ name: 'birthdate', value: '2000-01-01', type: 0 },
			{ name: 'gender', value: 'Other', type: 0 },
			{ name: 'Section', value: 'section-value', type: 0 },
		],
	});
	expect(items(result)[4]).toMatchObject({ login: { username: 'alias@example.test' } });
	expect(items(result)[5]).toMatchObject({
		type: 5,
		sshKey: { privateKey: 'private', publicKey: 'public', keyFingerprint: 'SHA256:abc' },
		fields: [{ name: 'Host', value: 'example.test', type: 0 }],
	});
	expect(items(result)[6]).toMatchObject({
		type: 2,
		fields: [
			{ name: 'Password', value: 'wifi-secret', type: 1 },
			{ name: 'SSID', value: 'office', type: 0 },
			{ name: 'Security', value: 'WPA3', type: 0 },
		],
	});
	expect(items(result)[7]).toMatchObject({
		type: 2,
		fields: [
			{ name: 'Account', value: '1234', type: 0 },
			{ name: 'PIN', value: '5678', type: 1 },
			{ name: 'count', value: '3', type: 0 },
		],
	});
	expect(result.folders).toEqual([{ id: expect.any(String), name: 'Personal' }]);
	const organization = parseExternalJson(
		'protonpass',
		JSON.stringify({
			encrypted: false,
			vaults: {
				team: {
					name: 'Team',
					items: [{ state: 1, data: { type: 'note', metadata: { name: 'Shared' }, content: {}, extraFields: [] } }],
				},
			},
		}),
		true,
	);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});

test('Proton Pass JSON rejects encrypted and malformed exports without exposing data', () => {
	const secret = 'proton-pass-private-data';
	expect(() => parseExternalJson('protonpass', `{broken ${secret}`)).toThrow('Invalid Proton Pass JSON.');
	expect(() => parseExternalJson('protonpass', JSON.stringify({ encrypted: true, vaults: {} }))).toThrow(
		'Encrypted Proton Pass exports are unsupported.',
	);
	expect(() => parseExternalJson('protonpass', JSON.stringify({ vaults: { x: { items: [null] } } }))).toThrow(
		'Invalid Proton Pass item.',
	);
});

test('Keeper JSON imports logins, typed cards and identities, folders, and cross-record references', () => {
	const result = parseExternalJson(
		'keeperjson',
		JSON.stringify({
			shared_folders: [{ path: 'Shared\\Finance' }],
			records: [
				{
					$type: 'login',
					uid: 'login-1',
					title: 'Keeper login',
					login: 'alice',
					password: '  secret  ',
					login_url: 'example.test/login',
					notes: 'login notes',
					custom_fields: {
						'$oneTimeCode': ['KEEPER_TEST_SEED'],
						'$text:Recovery code': 'recovery-1',
						'$pinCode': 'pin-1234',
					},
					folders: [{ folder: 'Personal/Accounts' }],
					references: { '$securityQuestionRef': ['question-1'] },
				},
				{
					$type: 'bankCard',
					title: 'Keeper card',
					login_url: ['https://bank.test', 'https://bank.test/card'],
					custom_fields: {
						'$text:cardholderName': 'Alice Example',
						'$paymentCard': { cardNumber: '4111111111111111', cardSecurityCode: '123', cardExpirationDate: '06/2030' },
						'$pinCode': 'card-pin',
					},
				},
				{
					$type: 'ssnCard',
					title: 'Keeper identity',
					custom_fields: {
						'$accountNumber:identityNumber': '123-45-6789',
						'$name': { first: 'Alice', middle: 'Q', last: 'Example' },
					},
				},
				{
					$type: 'general',
					uid: 'question-1',
					title: 'Keeper question',
					custom_fields: { '$text:securityQuestion': 'Milo' },
				},
			],
		}),
	);
	expect(items(result)).toHaveLength(4);
	expect(items(result)[0]).toMatchObject({
		name: 'Keeper login',
		folderId: (result.folders as JsonObject[]).find(folder => folder.name === 'Personal-Accounts')!.id,
		login: {
			username: 'alice',
			password: '  secret  ',
			totp: 'KEEPER_TEST_SEED',
			uris: [{ uri: 'http://example.test/login', match: null }],
		},
		fields: [
			{ name: 'Recovery code', value: 'recovery-1', type: 0 },
			{ name: 'pinCode', value: 'pin-1234', type: 1 },
			{ name: 'securityQuestion', value: 'Milo', type: 0 },
		],
	});
	expect(items(result)[1]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'Alice Example',
			number: '4111111111111111',
			code: '123',
			brand: 'Visa',
			expMonth: '06',
			expYear: '2030',
		},
		fields: [
			{ name: 'PIN', value: 'card-pin', type: 1 },
			{ name: 'URL', value: 'https://bank.test', type: 0 },
			{ name: 'URL', value: 'https://bank.test/card', type: 0 },
		],
	});
	expect(items(result)[2]).toMatchObject({
		type: 4,
		identity: { ssn: '123-45-6789', firstName: 'Alice', middleName: 'Q', lastName: 'Example' },
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Shared/Finance' },
		{ id: expect.any(String), name: 'Shared' },
		{ id: expect.any(String), name: 'Personal-Accounts' },
	]);
	const organization = parseExternalJson(
		'keeperjson',
		JSON.stringify({
			records: [{ title: 'Org record', login: 'org-user', folders: [{ shared_folder: 'Team/Projects' }] }],
		}),
		true,
	);
	expect(organization.folders).toBeUndefined();
	expect(items(organization)[0]!.collectionIds).toEqual([(organization.collections as JsonObject[])[0]!.id]);
});

test('Keeper JSON malformed input and empty record lists fail with fixed diagnostics', () => {
	const secret = 'keeper-private-payload';
	expect(() => parseExternalJson('keeperjson', `{bad ${secret}`)).toThrow('Invalid Keeper JSON.');
	expect(() => parseExternalJson('keeperjson', JSON.stringify({ records: [] }))).toThrow(
		'Keeper JSON contains no records.',
	);
});

test('Keeper JSON resolves numbered typed fields and excludes them from custom fields', () => {
	const result = parseExternalJson(
		'keeperjson',
		JSON.stringify({
			records: [{
				$type: 'bankCard',
				title: 'Numbered Keeper card fields',
				custom_fields: {
					'$text:cardholderName:1': 'Alice Example',
					'$paymentCard:1': {
						cardNumber: '4111111111111111',
						cardSecurityCode: '123',
						cardExpirationDate: '06/2030',
					},
					'$pinCode:1': 'card-pin',
				},
			}],
		}),
	);
	expect(items(result)[0]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'Alice Example',
			number: '4111111111111111',
			code: '123',
			expMonth: '06',
			expYear: '2030',
		},
		fields: [{ name: 'PIN', value: 'card-pin', type: 1 }],
	});
});

test('Dashlane JSON maps credentials, addresses, identities, cards, and fallback notes', () => {
	const result = parseExternalJson(
		'dashlanejson',
		JSON.stringify({
			AUTHENTIFIANT: [{
				title: 'Dashlane login',
				login: 'dash-user',
				email: 'dash@example.test',
				password: '  secret  ',
				domain: 'https://dash.example.test',
				note: 'login note',
			}],
			ADDRESS: [{
				addressName: 'Home',
				addressFull: '12 Example Road',
				city: 'Amsterdam',
				state: 'NH',
				zipcode: '1000 AA',
				country: 'nl',
			}],
			IDENTITY: [{ fullName: 'Alice Q Example', pseudo: 'alice' }],
			PAYMENTMEANS_CREDITCARD: [{ bank: 'Example Bank', owner: 'Alice Example', cardNumber: '4111111111111111' }],
			BANKSTATEMENT: [{ BankAccountName: 'Checking', account: '1234', note: 'line one\nline two' }],
			UNKNOWN: [{ code: 'generic-value' }],
		}),
	);
	expect(items(result)).toHaveLength(6);
	expect(items(result)[0]).toMatchObject({
		type: 4,
		name: 'Home',
		identity: { address1: '12 Example Road', country: 'NL' },
	});
	expect(items(result)[1]).toMatchObject({
		name: 'Dashlane login',
		notes: 'Email: dash@example.test\nlogin note',
		login: {
			username: 'dash-user',
			password: '  secret  ',
			uris: [{ uri: 'https://dash.example.test', match: null }],
		},
	});
	expect(items(result)[2]).toMatchObject({
		type: 2,
		name: 'Checking',
		notes: 'note: line one\nline two\n',
		fields: [{ name: 'account', value: '1234', type: 0 }],
	});
	expect(items(result)[3]).toMatchObject({
		type: 3,
		name: 'Example Bank - Visa',
		card: { cardholderName: 'Alice Example', number: '4111111111111111', brand: 'Visa' },
	});
	expect(items(result)[4]).toMatchObject({
		type: 4,
		identity: { firstName: 'Alice', middleName: 'Q', lastName: 'Example', username: 'alice' },
	});
	expect(items(result)[5]).toMatchObject({
		type: 2,
		name: 'Generic Note',
		fields: [{ name: 'code', value: 'generic-value', type: 0 }],
	});
});

test('Dashlane JSON rejects malformed records without echoing source data', () => {
	const secret = 'private-dashlane-payload';
	expect(() => parseExternalJson('dashlanejson', `{broken ${secret}`)).toThrow('Invalid Dashlane JSON.');
	expect(() => parseExternalJson('dashlanejson', JSON.stringify({ AUTHENTIFIANT: 'bad' }))).toThrow(
		'Invalid Dashlane JSON AUTHENTIFIANT records.',
	);
});

test('Password Boss JSON maps current and legacy exports, cards, folders, and custom values', () => {
	const flat = parseExternalJson(
		'passwordbossjson',
		JSON.stringify([
			{
				id: 'flat-1',
				itemType: 'Login',
				itemTypeName: 'Login',
				name: 'Password Boss login',
				folder: 'Work/Accounts',
				username: '',
				email: 'boss@example.test',
				password: '  boss-secret  ',
				url: 'https://boss.example.test',
				totp: 'BOSS_TEST_SEED',
				notes: 'login note',
				tags: ['work', 'important'],
				customFields: [{ name: 'Recovery code', value: 'boss-recovery' }],
				extra: 'extra-value',
			},
			{
				itemTypeName: 'CreditCard',
				name: 'Bank card',
				cardNumber: '4111111111111111',
				nameOnCard: 'Alice Example',
				securityCode: '123',
				expirationDate: '2030-06-01T00:00:00Z',
				issuingBank: 'Example Bank',
				pin: '1234',
			},
			{ itemTypeName: 'SecureNote', name: 'Reference note', notes: 'note body', customFields: [] },
		]),
	);
	expect(items(flat)).toHaveLength(3);
	expect(items(flat)[0]).toMatchObject({
		name: 'Password Boss login',
		folderId: (flat.folders as JsonObject[])[0]!.id,
		login: {
			username: 'boss@example.test',
			password: '  boss-secret  ',
			totp: 'BOSS_TEST_SEED',
			uris: [{ uri: 'https://boss.example.test', match: null }],
		},
		fields: [
			{ name: 'Recovery code', value: 'boss-recovery', type: 0 },
			{ name: 'Tags', value: 'work, important', type: 0 },
			{ name: 'extra', value: 'extra-value', type: 0 },
		],
	});
	expect(items(flat)[1]).toMatchObject({
		type: 3,
		card: {
			brand: 'Visa',
			number: '4111111111111111',
			cardholderName: 'Alice Example',
			code: '123',
			expMonth: '6',
			expYear: '2030',
		},
		fields: [
			{ name: 'Issuing Bank', value: 'Example Bank', type: 0 },
			{ name: 'PIN', value: '1234', type: 1 },
		],
	});
	expect(items(flat)[2]).toMatchObject({ type: 2, secureNote: { type: 0 }, notes: 'note body' });
	const legacy = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [{ id: 'legacy-folder', name: 'Archive' }],
			items: [{
				name: 'Legacy Boss login',
				type: 'Login',
				folder: 'legacy-folder',
				login_url: 'https://legacy.example.test',
				identifiers: {
					email: 'legacy@example.test',
					password: 'legacy-secret',
					notes: 'first\\nsecond',
					custom_fields: [{ name: 'Recovery', value: 'legacy-recovery' }],
				},
			}],
		}),
	);
	expect(items(legacy)[0]).toMatchObject({
		name: 'Legacy Boss login',
		folderId: 'legacy-folder',
		notes: 'first\nsecond',
		login: {
			username: 'legacy@example.test',
			password: 'legacy-secret',
			uris: [{ uri: 'https://legacy.example.test', match: null }],
		},
		fields: [{ name: 'Recovery', value: 'legacy-recovery', type: 0 }],
	});
});

test('Password Boss JSON rejects malformed input without echoing it', () => {
	const secret = 'private-password-boss-payload';
	expect(() => parseExternalJson('passwordbossjson', `{broken ${secret}`)).toThrow('Invalid Password Boss JSON.');
	expect(() => parseExternalJson('passwordbossjson', JSON.stringify({ entries: [] }))).toThrow(
		'Invalid Password Boss JSON items.',
	);
});

test('Password Boss card brands match bw Discover BIN recognition', () => {
	const flat = parseExternalJson(
		'passwordbossjson',
		JSON.stringify([{ itemTypeName: 'CreditCard', cardNumber: '6221260000000000' }]),
	);
	expect(items(flat)[0]!.card).toMatchObject({ number: '6221260000000000', brand: 'Discover' });

	const legacy = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({ folders: [], items: [{ type: 'CreditCard', identifiers: { cardNumber: '6229250000000000' } }] }),
	);
	expect(items(legacy)[0]!.card).toMatchObject({ number: '6229250000000000', brand: 'Discover' });
});

test('legacy Password Boss card expiry uses local calendar fields like bw', () => {
	const previousTimezone = process.env.TZ;
	process.env.TZ = 'Europe/Amsterdam';
	try {
		const result = parseExternalJson(
			'passwordbossjson',
			JSON.stringify({
				folders: [],
				items: [{
					name: 'Legacy card',
					type: 'CreditCard',
					identifiers: { cardNumber: '4111111111111111', expires: '2030-06-01T00:30:00+02:00' },
				}],
			}),
		);
		expect(items(result)[0]!.card).toMatchObject({ expMonth: '6', expYear: '2030' });
	} finally {
		if (previousTimezone === undefined) delete process.env.TZ;
		else process.env.TZ = previousTimezone;
	}
});

test('legacy Password Boss matches bw malformed expiry behavior', () => {
	const result = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [],
			items: [{ type: 'CreditCard', identifiers: { expires: 'not-a-date' } }],
		}),
	);
	expect(items(result)[0]!.card).toMatchObject({ expMonth: 'NaN', expYear: 'NaN' });
});

test('legacy Password Boss imports a folder whose source ID matches its name', () => {
	const result = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [{ id: 'Archive', name: 'Archive' }],
			items: [{
				name: 'Legacy folder item',
				folder: 'Archive',
				identifiers: { username: 'legacy-user' },
			}],
		}),
	);
	const folder = (result.folders as JsonObject[])[0]!;
	expect(folder).toMatchObject({ id: 'Archive', name: 'Archive' });
	expect(items(result)[0]!.folderId).toBe(folder.id);
});

test('legacy Password Boss imports duplicate folder names and source ID relationships', () => {
	const result = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [
				{ id: 'folder-one', name: 'Archive' },
				{ id: 'folder-two', name: 'Archive' },
				{ id: 'folder-path', name: 'Parent/Child' },
			],
			items: [
				{ name: 'First', folder: 'folder-one', identifiers: { username: 'first' } },
				{ name: 'Second', folder: 'folder-two', identifiers: { username: 'second' } },
				{ name: 'Path', folder: 'folder-path', identifiers: { username: 'path' } },
			],
		}),
	);
	expect(result.folders).toEqual([
		{ id: 'folder-one', name: 'Archive' },
		{ id: 'folder-two', name: 'Archive' },
		{ id: 'folder-path', name: 'Parent/Child' },
	]);
	expect(items(result).map(value => value.folderId)).toEqual(['folder-one', 'folder-two', 'folder-path']);
});

test('legacy Password Boss resolves username and email in source property order', () => {
	const result = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [],
			items: [{
				name: 'Legacy ordered fields',
				identifiers: { email: 'first@example.test', username: 'later-user', password: 'secret' },
			}],
		}),
	);
	expect(items(result)[0]).toMatchObject({
		login: { username: 'first@example.test', password: 'secret' },
		fields: [{ name: 'username', value: 'later-user', type: 0 }],
	});
});

test('legacy Password Boss matches case-sensitive URI field names from bw', () => {
	const result = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [],
			items: [{ name: 'Legacy uppercase URI', identifiers: { URL: 'https://example.test' } }],
		}),
	);
	expect(items(result)[0]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		fields: [{ name: 'URL', value: 'https://example.test', type: 0 }],
	});
});

test('legacy Password Boss follows custom field order from the source identifiers object', () => {
	const result = parseExternalJson(
		'passwordbossjson',
		JSON.stringify({
			folders: [],
			items: [{
				name: 'Legacy ordered custom fields',
				identifiers: {
					first: 'one',
					custom_fields: [{ name: 'Recovery', value: 'two' }],
					last: 'three',
				},
			}],
		}),
	);
	expect(items(result)[0]!.fields).toEqual([
		{ name: 'first', value: 'one', type: 0 },
		{ name: 'Recovery', value: 'two', type: 0 },
		{ name: 'last', value: 'three', type: 0 },
	]);
});

test('Enpass JSON maps nested folders, login data, secure notes, and cards', () => {
	const result = parseExternalJson(
		'enpassjson',
		JSON.stringify({
			folders: [
				{ uuid: 'parent', title: 'Personal', parent_uuid: '' },
				{ uuid: 'child', title: 'Social', parent_uuid: 'parent' },
			],
			items: [
				{
					title: 'Enpass login',
					template_type: 'login.default',
					favorite: 1,
					folders: ['child'],
					note: 'login note  \n',
					fields: [
						{ type: 'email', label: 'Email', value: 'alice@example.com' },
						{ type: 'password', label: 'Password', value: '  secret  ' },
						{ type: 'totp', label: 'TOTP', value: 'seed' },
						{ type: 'url', label: 'Website', value: 'example.com' },
						{ type: '.Android#', label: 'App 0', value: 'com.example.0' },
						{
							type: '.Android#',
							label: 'App 1',
							value:
								'android://pMUhLBalOhcc3yK-84sMiGc2U856FVVUhm8PZveoRfNFT3ocT1KWZlciAkF2ED--B5i_fMuNlC6JfPxcHk1AQg==@com.example.1',
						},
						{ type: '.Android#', label: 'App 2', value: 'android://com.example.2' },
						{ type: '.Android#', label: 'App 3', value: 'androidapp://com.example.3' },
						{ type: 'text', label: 'Recovery code', value: '  recovery  ', sensitive: 1 },
					],
				},
				{
					title: 'Enpass note',
					template_type: 'note.default',
					favorite: 0,
					fields: [{ type: 'text', label: 'Reference', value: '  sample  ' }],
				},
				{
					title: 'Enpass card',
					template_type: 'creditcard.default',
					favorite: 1,
					fields: [
						{ type: 'ccName', label: 'Name', value: 'Alice Example' },
						{ type: 'ccNumber', label: 'Number', value: '3782 822463 10005' },
						{ type: 'ccCvc', label: 'CVC', value: '123', sensitive: 1 },
						{ type: 'ccExpiry', label: 'Expiry', value: '03/23' },
					],
				},
			],
		}),
	);
	expect(items(result)).toHaveLength(3);
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Personal' },
		{ id: expect.any(String), name: 'Personal/Social' },
	]);
	expect(items(result)[0]).toMatchObject({
		name: 'Enpass login',
		favorite: true,
		folderId: (result.folders as JsonObject[])[1]!.id,
		notes: 'login note',
		login: {
			username: 'alice@example.com',
			password: '  secret  ',
			totp: 'seed',
			uris: [
				{ uri: 'http://example.com', match: null },
				{ uri: 'androidapp://com.example.0', match: null },
				{ uri: 'androidapp://com.example.1', match: null },
				{ uri: 'androidapp://com.example.2', match: null },
				{ uri: 'androidapp://com.example.3', match: null },
			],
		},
		fields: [{ name: 'Recovery code', value: '  recovery  ', type: 1 }],
	});
	expect(items(result)[1]).toMatchObject({
		type: 2,
		secureNote: { type: 0 },
		fields: [{ value: '  sample  ', type: 0 }],
	});
	expect(items(result)[2]).toMatchObject({
		type: 3,
		card: {
			cardholderName: 'Alice Example',
			number: '3782 822463 10005',
			brand: 'Amex',
			code: '123',
			expMonth: '3',
			expYear: '2023',
		},
	});
});

test('Enpass JSON combines source notes with long and multiline custom fields', () => {
	const recovery = `first-line\n${'x'.repeat(220)}\nlast-line`;
	const result = parseExternalJson(
		'enpassjson',
		JSON.stringify({
			items: [{
				title: 'Recovery note',
				template_type: 'note.default',
				note: 'Existing note',
				fields: [{ type: 'text', label: 'Recovery codes', value: recovery }],
			}],
		}),
	);
	expect(items(result)[0]?.notes).toBe(`Existing note\nRecovery codes: ${recovery}\n`);
});

test('Enpass JSON rejects malformed documents and ignores cyclic folder paths', () => {
	expect(() => parseExternalJson('enpassjson', '{bad secret payload')).toThrow('Invalid Enpass JSON.');
	expect(() => parseExternalJson('enpassjson', JSON.stringify({ items: {} }))).toThrow(
		'Invalid Enpass JSON item records.',
	);
	const result = parseExternalJson(
		'enpassjson',
		JSON.stringify({
			folders: [
				{ uuid: 'cycle-a', title: 'A', parent_uuid: 'cycle-b' },
				{ uuid: 'cycle-b', title: 'B', parent_uuid: 'cycle-a' },
			],
			items: [{ title: 'No folder', folders: ['cycle-a'] }],
		}),
	);
	expect(result.folders).toEqual([]);
	expect(items(result)[0]!.folderId).toBeUndefined();
});

test('Enpass Android app URI normalization stays linear on repeated prefixes', () => {
	const adversarial = 'androidapp://'.repeat(76);
	const result = parseExternalJson(
		'enpassjson',
		JSON.stringify({
			items: [{
				title: 'Android URL',
				template_type: 'login.default',
				fields: [{ type: '.Android#', label: 'App', value: adversarial }],
			}],
		}),
	);
	expect((items(result)[0]!.login as JsonObject).uris).toEqual([{ uri: adversarial, match: null }]);
});

test('GNOME Passwords JSON maps URL credentials, keyring folders, and custom attributes', () => {
	const result = parseExternalJson(
		'gnomejson',
		JSON.stringify({
			'Personal/Browser': [
				{
					display_name: 'https://accounts.example.test/login',
					secret: '  gnome-secret  ',
					attributes: {
						username_value: 'alice@example.test',
						'xdg:schema': 'org.gnome.Password',
						account: 'primary',
						comment: 'Line one\nLine two',
					},
				},
				{ display_name: 'SSH connection', secret: 'ignored' },
			],
			Empty: [],
		}),
	);
	expect(items(result)).toHaveLength(1);
	expect(items(result)[0]).toMatchObject({
		name: 'accounts.example.test/login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		login: {
			username: 'alice@example.test',
			password: '  gnome-secret  ',
			uris: [{ uri: 'https://accounts.example.test/login', match: null }],
		},
		fields: [{ name: 'account', value: 'primary', type: 0 }],
		notes: 'comment: Line one\nLine two\n',
	});
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Personal/Browser' },
		{ id: expect.any(String), name: 'Personal' },
	]);
});

test('GNOME Passwords JSON supports organization collections and rejects malformed exports', () => {
	const result = parseExternalJson(
		'gnomejson',
		JSON.stringify({
			'Finance/Bank': [{ display_name: 'http://bank.example', secret: 'secret' }],
		}),
		true,
	);
	expect(result.folders).toBeUndefined();
	expect(result.collections).toEqual([
		{ id: expect.any(String), name: 'Finance/Bank' },
		{ id: expect.any(String), name: 'Finance' },
	]);
	expect(items(result)[0]!.collectionIds).toEqual([(result.collections as JsonObject[])[0]!.id]);
	expect(() => parseExternalJson('gnomejson', '{bad private data')).toThrow('Invalid GNOME Passwords JSON.');
	expect(() => parseExternalJson('gnomejson', JSON.stringify({ Personal: {} }))).toThrow(
		'Invalid GNOME Passwords keyring records.',
	);
});

test('Passman JSON maps logins, fallback email, notes, TOTP, custom fields, and folders', () => {
	const result = parseExternalJson(
		'passmanjson',
		JSON.stringify([
			{
				label: 'Passman login',
				username: 'alice',
				email: 'alice@example.test',
				password: '  passman-secret  ',
				url: 'passman.example.test/login',
				description: 'Description',
				otp: { secret: 'PASSMAN_TEST_SEED' },
				tags: [{ text: 'Personal/Accounts' }, { text: 'Ignored' }],
				custom_fields: [
					{ field_type: 'text', label: 'Recovery', value: 'backup-code' },
					{ field_type: 'password', label: 'Extra secret', value: 'field-secret' },
					{ field_type: 'boolean', label: 'Ignored', value: 'true' },
					{ field_type: 'text', label: 'Details', value: 'first\nsecond' },
				],
			},
			{ label: 'Email fallback', email: 'bob@example.test' },
			{ label: 'Passman secure note', description: 'note text' },
		]),
	);
	expect(items(result)).toHaveLength(3);
	expect(items(result)[0]).toMatchObject({
		name: 'Passman login',
		folderId: (result.folders as JsonObject[])[0]!.id,
		notes: 'Email: alice@example.test\nDescriptionDetails: first\nsecond\n',
		login: {
			username: 'alice',
			password: '  passman-secret  ',
			totp: 'PASSMAN_TEST_SEED',
			uris: [{ uri: 'http://passman.example.test/login', match: null }],
		},
		fields: [
			{ name: 'Recovery', value: 'backup-code', type: 0 },
			{ name: 'Extra secret', value: 'field-secret', type: 0 },
		],
	});
	expect(items(result)[1]).toMatchObject({ login: { username: 'bob@example.test' } });
	expect(items(result)[2]).toMatchObject({ type: 2, secureNote: { type: 0 }, notes: 'note text' });
	expect(result.folders).toEqual([
		{ id: expect.any(String), name: 'Personal/Accounts' },
		{ id: expect.any(String), name: 'Personal' },
	]);
});

test('Passman JSON converts organization folders to collections and rejects malformed exports', () => {
	const result = parseExternalJson(
		'passmanjson',
		JSON.stringify([{
			label: 'Organization login',
			username: 'org-user',
			tags: [{ text: 'Finance/Bank' }],
		}]),
		true,
	);
	expect(result.folders).toBeUndefined();
	expect(result.collections).toEqual([
		{ id: expect.any(String), name: 'Finance/Bank' },
		{ id: expect.any(String), name: 'Finance' },
	]);
	expect(items(result)[0]!.collectionIds).toEqual([(result.collections as JsonObject[])[0]!.id]);
	expect(() => parseExternalJson('passmanjson', '{private malformed payload')).toThrow('Invalid Passman JSON.');
	expect(() => parseExternalJson('passmanjson', '[]')).toThrow('Passman JSON contains no items.');
});

test('TOTP-only records remain logins across external JSON importers', () => {
	const sources: [string, unknown][] = [
		['enpassjson', {
			items: [{
				title: 'Enpass OTP',
				template_type: 'login.default',
				fields: [{ type: 'totp', value: 'ENPASS_TEST_SEED' }],
			}],
		}],
		['passmanjson', [{ label: 'Passman OTP', otp: { secret: 'PASSMAN_TEST_SEED' } }]],
		['keeperjson', {
			records: [{ $type: 'login', title: 'Keeper OTP', custom_fields: { $oneTimeCode: ['KEEPER_TEST_SEED'] } }],
		}],
		['passwordbossjson', [{ itemTypeName: 'Login', name: 'Password Boss OTP', totp: 'BOSS_TEST_SEED' }]],
	];
	for (const [format, source] of sources) {
		const imported =
			items(parseExternalJson(format as Parameters<typeof parseExternalJson>[0], JSON.stringify(source)))[0];
		expect(imported).toMatchObject({ type: 1, login: { totp: expect.any(String) } });
	}
});

test('Passky JSON maps password records and rejects encrypted or invalid exports', () => {
	const result = parseExternalJson(
		'passkyjson',
		JSON.stringify({
			encrypted: false,
			passwords: [
				{
					website: 'https://passky.example.test/login',
					username: 'passky-user',
					password: '  passky-secret  ',
					message: 'Passky note',
				},
				{ website: '', username: '', password: '', message: 'Secure note only' },
			],
		}),
	);
	expect(items(result)).toHaveLength(2);
	expect(items(result)[0]).toMatchObject({
		name: 'https://passky.example.test/login',
		notes: 'Passky note',
		login: {
			username: 'passky-user',
			password: '  passky-secret  ',
			uris: [{ uri: 'https://passky.example.test/login', match: null }],
		},
	});
	expect(items(result)[1]).toMatchObject({ type: 2, name: '--', secureNote: { type: 0 }, notes: 'Secure note only' });
	expect(() => parseExternalJson('passkyjson', '{private malformed payload')).toThrow('Invalid Passky JSON.');
	expect(() => parseExternalJson('passkyjson', JSON.stringify({ encrypted: true, passwords: [{ website: 'x' }] })))
		.toThrow('Unable to import an encrypted Passky backup.');
	expect(() => parseExternalJson('passkyjson', JSON.stringify({ passwords: [] }))).toThrow(
		'Passky JSON contains no passwords.',
	);
});
