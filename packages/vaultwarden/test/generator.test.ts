import { test, expect } from 'bun:test';
import {
	generatePassword,
	generatePassphrase,
	generateSecret,
	generateVaultSecret,
	enforceGeneratorPolicies,
	parseGeneratorNumber,
} from '#generator';
import { passphraseWords } from '#wordlist';

test('vault generation combines both synced policy fields and applies membership exemptions', () => {
	const organization = { id: 'org', type: 2, status: 2, enabled: true, usePolicies: true };
	const snapshot = {
		profile: { id: 'user', organizations: [organization] },
		policies: [{ organizationId: 'org', type: 2, enabled: true, data: { minLength: 24 } }],
		policiesNew: [{ organizationId: 'org', type: 2, enabled: true, data: { minLength: 32 } }],
	};
	expect(generateVaultSecret({ length: 5 }, snapshot)).toHaveLength(32);
	for (
		const overrides of [
			{ type: 0 },
			{ type: 1 },
			{ status: 0 },
			{ enabled: false },
			{ usePolicies: false },
			{ isProviderUser: true },
		]
	) {
		expect(
			generateVaultSecret(
				{ length: 5 },
				{ ...snapshot, profile: { organizations: [{ ...organization, ...overrides }] } },
			),
		).toHaveLength(5);
	}
	expect(generateVaultSecret({ length: 5 })).toHaveLength(5);
});

test('generation honors character sets, minima, and ambiguous-character exclusion', () => {
	for (let i = 0; i < 30; i++) {
		const secret = generatePassword({
			length: 24,
			uppercase: true,
			lowercase: true,
			number: true,
			special: true,
			minNumber: 4,
			minSpecial: 3,
			avoidAmbiguous: true,
		});
		expect(secret.length).toBe(24);
		expect(secret).toMatch(/[A-Z]/);
		expect(secret).toMatch(/[a-z]/);
		expect(secret.match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4);
		expect(secret.match(/[!@#$%^&*]/g)!.length).toBeGreaterThanOrEqual(3);
		expect(secret).not.toMatch(/[IOl01]/);
	}
	expect(generatePassword().length).toBe(14);
	expect(generatePassword({ length: 1 }).length).toBe(5);
	const extended = generatePassword({ length: 5, number: true, minNumber: 6 });
	expect(extended).toHaveLength(6);
	expect(extended).toMatch(/^\d{6}$/);
	const combined = generatePassword({ length: 5, number: true, minNumber: 4, special: true, minSpecial: 4 });
	expect(combined).toHaveLength(8);
	expect(combined.match(/\d/g)!).toHaveLength(4);
	expect(combined.match(/[!@#$%^&*]/g)!).toHaveLength(4);
	expect(() => generatePassword({ length: Infinity })).toThrow('length');
});
test('special characters are not required unless a minimum is supplied', () => {
	const samples = Array.from(
		{ length: 128 },
		() => generatePassword({ length: 5, uppercase: true, lowercase: true, special: true }),
	);
	expect(samples.some(secret => !/[!@#$%^&*]/.test(secret))).toBe(true);
	for (const secret of samples) {
		expect(secret).toHaveLength(5);
	}
	for (let i = 0; i < 16; i++) {
		expect(generatePassword({ length: 5, uppercase: true, lowercase: true, special: true, minSpecial: 1 }))
			.toMatch(/[!@#$%^&*]/);
	}
});
test('generation clamps small values, accepts large values, and enforces resource bounds', () => {
	expect(generatePassword({ length: -1 })).toHaveLength(5);
	expect(generatePassword({ length: 4097 })).toHaveLength(4097);
	expect(generatePassphrase({ words: -1 }).split('-')).toHaveLength(3);
	expect(generatePassphrase({ words: 129, separator: '/' }).split('/')).toHaveLength(129);
	expect(generatePassword({ length: 65_536 })).toHaveLength(65_536);
	expect(() => generatePassword({ length: 65_537 })).toThrow('password length');
	expect(generatePassphrase({ words: 8_192, separator: '/' }).split('/')).toHaveLength(8_192);
	expect(() => generatePassphrase({ words: 8_193 })).toThrow('word count');
	expect(() => generatePassword({ length: Number.MAX_SAFE_INTEGER })).toThrow('password length');
	expect(() => generatePassword({ number: true, minNumber: Number.MAX_SAFE_INTEGER })).toThrow('minimum number count');
	expect(() => generatePassphrase({ words: Number.MAX_SAFE_INTEGER })).toThrow('word count');
});
test('generation numeric options use bw parseInt and fallback behavior', () => {
	expect(parseGeneratorNumber('5.9', 14)).toBe(5);
	expect(parseGeneratorNumber('5tail', 14)).toBe(5);
	expect(parseGeneratorNumber('nonsense', 14)).toBe(14);
	expect(parseGeneratorNumber(undefined, 6)).toBe(6);
});
test('passphrases use all 7776 EFF words and honor separator, casing, number, and minimum word count', () => {
	expect(passphraseWords.length).toBe(7776);
	expect(new Set(passphraseWords).size).toBe(7776);
	const phrase = generatePassphrase({ words: 6, separator: 'space', capitalize: true, includeNumber: true });
	const words = phrase.split(' ');
	expect(words.length).toBe(6);
	for (const word of words) {
		expect(word).toMatch(/^[A-Z]/);
		expect(passphraseWords).toContain(word.replace(/[0-9]/g, '').toLowerCase());
	}
	expect(phrase).toMatch(/[0-9]/);
	expect(generatePassphrase({ words: 1 }).split('-').length).toBe(3);
});
test('cached generator policies add requirements without dropping default character classes', () => {
	const policies = [
		{
			type: 2,
			enabled: true,
			data: {
				minLength: 25,
				useUpper: true,
				useLower: true,
				useNumbers: true,
				useSpecial: true,
				minNumbers: 3,
				minSpecial: 3,
			},
		},
		{ type: 2, enabled: true, data: { minLength: 30, minNumbers: 4 } },
	];
	const secret = generateSecret({ uppercase: false, lowercase: false, number: false, special: true }, policies);
	expect(secret.length).toBe(30);
	expect(secret).toMatch(/[A-Z]/);
	expect(secret).toMatch(/[a-z]/);
	expect(secret.match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4);
	expect(secret.match(/[!@#$%^&*]/g)!.length).toBeGreaterThanOrEqual(3);
	const passphrase = generateSecret({ passphrase: true, words: 4, separator: '/' }, [{
		type: 2,
		enabled: true,
		data: { capitalize: true, includeNumber: true, minNumberWords: 8 },
	}]);
	const words = passphrase.split('/');
	expect(words).toHaveLength(8);
	expect(words.every(word => word[0] === word[0]!.toUpperCase())).toBe(true);
	expect(passphrase).toMatch(/\d/);
	expect(enforceGeneratorPolicies({ length: 20 }, [{ ...policies[0]!, enabled: false }]).length).toBe(20);
	expect(
		enforceGeneratorPolicies({ number: true, minNumber: 1 }, [{
			type: 2,
			enabled: true,
			data: { minNumbers: 0, minSpecial: 0 },
		}]).minNumber,
	).toBe(1);
});
