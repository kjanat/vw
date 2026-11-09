import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { constants, createPublicKey, generateKeyPairSync, publicEncrypt } from 'node:crypto';
import { sealSession, withStore } from '#store';
import { collectionOrganizationId } from '#vault-commands';
import { runCapturedProcess } from '#test/process';
import {
	decrypt,
	deriveMasterKey,
	deriveSendKey,
	encrypt,
	encryptAttachment,
	encryptItem,
	stretchKey,
} from '@kjanat/vaultwarden';

const executable = fileURLToPath(import.meta.resolve('#main'));
async function run(
	dir: string,
	args: string[],
	environment: Record<string, string> = {},
	stdinData?: string,
) {
	return runCapturedProcess(['node', executable, ...args], {
		env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, ...environment },
	}, stdinData);
}
test('org collection create/edit treat whitespace organization options as absent', () => {
	const organizationId = '11111111-1111-1111-1111-111111111111';
	expect(collectionOrganizationId('   ', { organizationId })).toBe(organizationId);
	expect(collectionOrganizationId(organizationId.toUpperCase(), { organizationId })).toBe(organizationId);
	expect(() => collectionOrganizationId('   ', {})).toThrow('An organization id is required');
});
test('built Node CLI exposes DreamCLI help and common flags', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-cli-'));
	try {
		const noArgs = await run(dir, []);
		expect(noArgs.code).toBe(0);
		expect(noArgs.stdout).toContain('A Vaultwarden-first client');
		const help = await run(dir, ['--help']);
		expect(help.code).toBe(0);
		expect(help.stdout).toContain('Vaultwarden-first');
		const commandHelp = await run(dir, ['help', 'config']);
		expect(commandHelp.code).toBe(0);
		expect(commandHelp.stdout).toContain('Usage: vw config');
		const loginHelp = await run(dir, ['login', '--help']);
		expect(loginHelp.code).toBe(0);
		expect(loginHelp.stdout).toContain('Two-factor provider: 0=TOTP, 1=email, 2=Duo,');
		expect(loginHelp.stdout).toContain('3=YubiKey, 7=WebAuthn');
		expect(loginHelp.stdout).toContain('[password]  [env: VW_PASSWORD]');
		expect(loginHelp.stdout).toContain('Without this option, login reads');
		expect(loginHelp.stdout).toContain('VW_PASSWORD.');
		expect(loginHelp.stdout).toContain('VW_CLIENTSECRET.');
		const encodeHelp = await run(dir, ['encode', '--help']);
		expect(encodeHelp.stdout).toContain('[input]');
		expect(encodeHelp.stdout).not.toContain('<input>');
		const globalRaw = await run(dir, ['--raw', 'generate', '--length', '5']);
		expect(globalRaw.code).toBe(0);
		expect(globalRaw.stdout.trim()).toHaveLength(5);
		const noInteraction = await run(dir, ['generate', '--nointeraction', '--length', '5']);
		expect(noInteraction.code).toBe(0);
		expect(noInteraction.stdout.trim()).toHaveLength(5);
		const directCommandNoInteraction = await run(dir, ['sdk-version', '--nointeraction']);
		expect(directCommandNoInteraction.code).toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('built Node CLI validates noninteractive input and authenticated object names', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-cli-input-'));
	try {
		const protectedImport = join(dir, 'protected.json');
		await writeFile(protectedImport, JSON.stringify({ passwordProtected: true }));
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		for (
			const [args, environment] of [
				[['import', 'bitwardenjson', protectedImport, '--nointeraction'], {}],
				[['import', 'bitwardenjson', protectedImport], { VW_NOINTERACTION: 'true' }],
			] as const
		) {
			const result = await run(dir, [...args], environment);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain('Vault is locked.');
		}
		const keepassWithoutPassword = await run(dir, [
			'import',
			'keepasskdbx',
			protectedImport,
			'--nointeraction',
		]);
		expect(keepassWithoutPassword.code).toBe(1);
		expect(keepassWithoutPassword.stderr).toContain('Vault is locked.');
		const unknownGet = await run(dir, ['get', 'unsupported-object', 'synthetic-id']);
		expect(unknownGet.code).toBe(1);
		expect(unknownGet.stderr).toContain('Unknown object.');
		const unknownList = await run(dir, ['list', 'unsupported-object']);
		expect(unknownList.code).toBe(1);
		expect(unknownList.stderr).toContain('Unknown object.');
		const lockedOrganizationList = await run(dir, [
			'list',
			'org-collections',
			'--organizationid',
			'not-a-guid',
			'--nointeraction',
		]);
		expect(lockedOrganizationList.code).toBe(1);
		expect(lockedOrganizationList.stderr).toContain('Vault is locked.');
		const lockedOrganizationCollectionGet = await run(dir, [
			'get',
			'org-collection',
			'not-a-guid',
			'--organizationid',
			'also-not-a-guid',
		]);
		expect(lockedOrganizationCollectionGet.code).toBe(1);
		expect(lockedOrganizationCollectionGet.stderr).toContain('Vault is locked.');
		const lockedAttachmentGet = await run(dir, ['get', 'attachment', 'some-id']);
		expect(lockedAttachmentGet.code).toBe(1);
		expect(lockedAttachmentGet.stderr).toContain('Vault is locked.');
		for (
			const args of [
				['create', 'folder'],
				['create', 'attachment', '--file', join(dir, 'missing.bin')],
				['edit', 'folder', 'some-id'],
				['delete', 'attachment', 'some-id'],
				['delete', 'org-collection', 'not-a-guid'],
				['move', 'some-id', 'not-a-guid', Buffer.from('{').toString('base64')],
				['import'],
				['import', 'unknown-format', join(dir, 'missing.import')],
			]
		) {
			const result = await run(dir, args);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain('Vault is locked.');
		}
		const unknownEdit = await run(dir, [
			'edit',
			'unsupported-object',
			'synthetic-id',
			Buffer.from('{}').toString('base64'),
		]);
		expect(unknownEdit.code).toBe(1);
		expect(unknownEdit.stderr).toContain('Unknown object.');
		const flagsBeforeEditObject = await run(dir, [
			'edit',
			'--session',
			'Synthetic-SESSION',
			'UNSUPPORTED-OBJECT',
			'Synthetic-ID',
			Buffer.from('{}').toString('base64'),
		]);
		expect(flagsBeforeEditObject.code).toBe(1);
		expect(flagsBeforeEditObject.stderr).toContain('Unknown object.');
		const flagsBeforeCreateObject = await run(dir, ['create', '--session', 'Synthetic-SESSION', 'ITEM']);
		expect(flagsBeforeCreateObject.code).toBe(1);
		expect(flagsBeforeCreateObject.stderr).toContain('Vault is locked.');
		const unknownRestore = await run(dir, ['restore', 'unsupported-object', 'synthetic-id']);
		expect(unknownRestore.code).toBe(1);
		expect(unknownRestore.stderr).toContain('Unknown object.');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('built Node CLI gates logged-out vault commands before validating their inputs', { timeout: 30000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-cli-gating-'));
	try {
		const uppercaseObject = await run(dir, ['--raw', 'get', 'TEMPLATE', 'ITEM']);
		expect(uppercaseObject.code).toBe(1);
		expect(uppercaseObject.stderr).toContain('You are not logged in.');
		const moveHelp = await run(dir, ['move', '--help']);
		expect(moveHelp.code).toBe(0);
		expect(moveHelp.stdout).toContain('[encodedJson]');
		const exportHelp = await run(dir, ['export', '--help']);
		expect(exportHelp.code).toBe(0);
		expect(exportHelp.stdout).toContain('[password]');
		expect(exportHelp.stdout).toContain('Without this option, export');
		expect(exportHelp.stdout).toContain('VW_EXPORT_PASSWORD.');
		const editHelp = await run(dir, ['edit', '--help']);
		expect(editHelp.code).toBe(0);
		expect(editHelp.stdout).toContain('[encodedJson]');
		const editWithoutJson = await run(dir, ['edit', 'item', 'item-id']);
		expect(editWithoutJson.code).toBe(1);
		expect(editWithoutJson.stderr).toContain('You are not logged in.');
		const createWithoutJson = await run(dir, ['create', 'folder']);
		expect(createWithoutJson.code).toBe(1);
		expect(createWithoutJson.stderr).toContain('You are not logged in.');
		const positionalExportPassword = await run(dir, ['export', 'synthetic-export-secret', '--format', 'json']);
		expect(positionalExportPassword.code).toBe(1);
		expect(positionalExportPassword.stderr).toContain('You are not logged in.');
		expect(positionalExportPassword.stderr).not.toContain('synthetic-export-secret');
		const createAttachmentWithoutItem = await run(dir, ['create', 'attachment']);
		expect(createAttachmentWithoutItem.code).toBe(1);
		expect(createAttachmentWithoutItem.stderr).toContain('You are not logged in.');
		const createAttachmentWithoutFile = await run(dir, ['create', 'attachment', '--itemid', 'item-id']);
		expect(createAttachmentWithoutFile.code).toBe(1);
		expect(createAttachmentWithoutFile.stderr).toContain('You are not logged in.');
		const createAttachmentMissingFile = await run(dir, [
			'create',
			'attachment',
			'--itemid',
			'item-id',
			'--file',
			join(dir, 'missing-attachment-file'),
		]);
		expect(createAttachmentMissingFile.code).toBe(1);
		expect(createAttachmentMissingFile.stderr).toContain('You are not logged in.');
		const invalidEditJson = await run(dir, ['edit', 'item', 'item-id', 'not-base64']);
		expect(invalidEditJson.code).toBe(1);
		expect(invalidEditJson.stderr).toContain('You are not logged in.');
		for (const args of [['send', 'create'], ['send', 'edit']]) {
			const result = await run(dir, args);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain('You are not logged in.');
		}
		const invalidSendJson = await run(dir, ['send', 'create', 'not-base64']);
		expect(invalidSendJson.code).toBe(1);
		expect(invalidSendJson.stderr).toContain('You are not logged in.');
		const emptyShare = await run(dir, ['share', 'item-id', 'organization-id']);
		expect(emptyShare.code).toBe(1);
		expect(emptyShare.stderr).toContain('You are not logged in.');
		const organizationId = '11111111-1111-1111-1111-111111111111';
		const organizationCollection = Buffer.from(JSON.stringify({ organizationId, name: 'Synthetic collection' }))
			.toString('base64');
		const createWithBodyOrganization = await run(dir, ['create', 'org-collection', organizationCollection]);
		expect(createWithBodyOrganization.code).toBe(1);
		expect(createWithBodyOrganization.stderr).toContain('You are not logged in.');
		expect(createWithBodyOrganization.stderr).not.toContain('organization id is required');
		const createWithoutOrganization = await run(
			dir,
			['create', 'org-collection', Buffer.from(JSON.stringify({ name: 'No organization' })).toString('base64')],
		);
		expect(createWithoutOrganization.code).toBe(1);
		expect(createWithoutOrganization.stderr).toContain('You are not logged in.');
		const editWithBodyOrganization = await run(dir, [
			'edit',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
			organizationCollection,
		]);
		expect(editWithBodyOrganization.code).toBe(1);
		expect(editWithBodyOrganization.stderr).toContain('You are not logged in.');
		const invalidDeleteId = await run(dir, [
			'delete',
			'org-collection',
			'not-a-guid',
			'--organizationid',
			organizationId,
		]);
		expect(invalidDeleteId.code).toBe(1);
		expect(invalidDeleteId.stderr).toContain('You are not logged in.');
		const missingAttachmentItem = await run(dir, ['delete', 'attachment', 'attachment-id']);
		expect(missingAttachmentItem.code).toBe(1);
		expect(missingAttachmentItem.stderr).toContain('You are not logged in.');
		const missingDeleteOrganization = await run(dir, [
			'delete',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
		]);
		expect(missingDeleteOrganization.code).toBe(1);
		expect(missingDeleteOrganization.stderr).toContain('You are not logged in.');
		const invalidDeleteOrganization = await run(dir, [
			'delete',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
			'--organizationid',
			'not-a-guid',
		]);
		expect(invalidDeleteOrganization.code).toBe(1);
		expect(invalidDeleteOrganization.stderr).toContain('You are not logged in.');
		const missingListOrganization = await run(dir, ['list', 'org-members']);
		expect(missingListOrganization.code).toBe(1);
		expect(missingListOrganization.stderr).toContain('You are not logged in.');
		const invalidListOrganization = await run(dir, ['list', 'org-collections', '--organizationid', 'not-a-guid']);
		expect(invalidListOrganization.code).toBe(1);
		expect(invalidListOrganization.stderr).toContain('You are not logged in.');
		const missingGetOrganization = await run(dir, [
			'get',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
		]);
		expect(missingGetOrganization.code).toBe(1);
		expect(missingGetOrganization.stderr).toContain('You are not logged in.');
		const conflictingOrganization = await run(dir, [
			'edit',
			'org-collection',
			'22222222-2222-2222-2222-222222222222',
			organizationCollection,
			'--organizationid',
			'33333333-3333-3333-3333-333333333333',
		]);
		expect(conflictingOrganization.code).toBe(1);
		expect(conflictingOrganization.stderr).toContain('You are not logged in.');
		const reportHelp = await run(dir, ['report', '--help']);
		expect(reportHelp.code).toBe(0);
		expect(reportHelp.stdout).toContain('--no-check-exposed');
		expect(reportHelp.stdout).not.toContain('[no-]check-exposed');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('built Node CLI persists server configuration and applies clean-exit flags', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-cli-config-'));
	try {
		const config = await run(dir, [
			'config',
			'server',
			'https://example.com/vault/',
		]);
		expect(config.code).toBe(0);
		expect(config.stdout.trim()).toBe('Saved setting `config`.');
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://example.com/vault');
		const shorthand = await run(dir, ['config', 'server', 'bitwarden.com']);
		expect(shorthand.code).toBe(0);
		expect(shorthand.stdout.trim()).toBe('Saved setting `config`.');
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://bitwarden.com');
		const status = await run(dir, ['status']);
		expect(JSON.parse(status.stdout).status).toBe('unauthenticated');
		expect((await run(dir, ['list', 'items'])).code).toBe(1);
		expect((await run(dir, ['list', 'items', '--cleanexit'])).code).toBe(0);
		expect((await run(dir, ['--cleanexit', 'list', 'items'])).code).toBe(0);
		expect((await run(dir, ['list', 'items', '--cleanexit=false'])).code).toBe(1);
		expect((await run(dir, ['list', 'items'], { VW_CLEANEXIT: 'false' })).code).toBe(1);
		expect((await run(dir, ['list', 'items', '--cleanexit'], { VW_CLEANEXIT: 'false' })).code).toBe(0);
		expect(
			(await run(dir, ['config', 'server', 'http://example.com'])).code,
		).toBe(1);
		expect((await run(dir, ['unknown'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('get templates require login but do not require an unlocked vault', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-template-login-'));
	try {
		const loggedOut = await run(dir, ['get', 'template', 'item']);
		expect(loggedOut.code).toBe(1);
		expect(loggedOut.stderr).toContain('You are not logged in.');
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const item = await run(dir, ['--raw', 'get', 'TEMPLATE', 'ITEM']);
		expect(item.code).toBe(0);
		expect(JSON.parse(item.stdout)).toEqual({
			type: 1,
			name: 'Item name',
			notes: 'Some notes about this item.',
			favorite: false,
			fields: [],
			reprompt: 0,
			passwordHistory: [],
		});
		expect(JSON.parse((await run(dir, ['get', 'template', 'item.login'])).stdout)).toEqual({
			uris: [],
			username: 'jdoe',
			password: 'myp@ssword123',
			totp: 'JBSWY3DPEHPK3PXP',
			fido2Credentials: [],
		});
		expect(JSON.parse((await run(dir, ['get', 'template', 'item.login.uri'])).stdout)).toEqual({
			uri: 'https://google.com',
		});
		expect(JSON.parse((await run(dir, ['get', 'template', 'item.field'])).stdout)).toEqual({
			name: 'Field name',
			value: 'Some value',
			type: 0,
		});
		expect(JSON.parse((await run(dir, ['get', 'template', 'item.card'])).stdout)).toEqual({
			cardholderName: 'John Doe',
			brand: 'visa',
			number: '4242424242424242',
			expMonth: '04',
			expYear: '2023',
			code: '123',
		});
		expect(JSON.parse((await run(dir, ['get', 'template', 'item.identity'])).stdout)).toEqual({
			title: 'Mr',
			firstName: 'John',
			middleName: 'William',
			lastName: 'Doe',
			address1: '123 Any St',
			address2: 'Apt #123',
			city: 'New York',
			state: 'NY',
			postalCode: '10001',
			country: 'US',
			company: 'Acme Inc.',
			email: 'john@company.com',
			phone: '5555551234',
			ssn: '000-123-4567',
			username: 'jdoe',
			passportNumber: 'US-123456789',
			licenseNumber: 'D123-12-123-12333',
		});
		const collection = await run(dir, ['get', 'template', 'collection']);
		expect(JSON.parse(collection.stdout)).toEqual({
			organizationId: '00000000-0000-0000-0000-000000000000',
			name: 'Collection name',
			externalId: null,
		});
		const secureNote = await run(dir, ['get', 'template', 'item.secureNote']);
		expect(JSON.parse(secureNote.stdout)).toEqual({ type: 0 });
		const collections = await run(dir, ['get', 'template', 'item-collections']);
		expect(JSON.parse(collections.stdout)).toEqual(['collection-id1', 'collection-id2']);
		const orgCollection = JSON.parse((await run(dir, ['get', 'template', 'org-collection'])).stdout);
		expect(orgCollection.groups).toHaveLength(2);
		expect(orgCollection.users).toHaveLength(2);
		expect(orgCollection.groups[0]).toEqual({
			id: '00000000-0000-0000-0000-000000000000',
			readOnly: false,
			hidePasswords: false,
			manage: false,
		});
		for (const object of ['send.text', 'send.file']) {
			const invalid = await run(dir, ['get', 'template', object]);
			expect(invalid.code).toBe(1);
			expect(invalid.stderr).toContain(`Invalid template object. Use \`bw send template ${object}\` instead.`);
		}
		const unknown = await run(dir, ['get', 'template', 'item.unknown']);
		expect(unknown.code).toBe(1);
		expect(unknown.stderr).toContain('Unknown template object.');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('new cipher templates follow the connected Vaultwarden version while locked', async () => {
	const server = createServer((request, response) => {
		if (request.url === '/api/config') {
			response.writeHead(200, { 'Content-Type': 'application/json' });
			response.end(JSON.stringify({ server: { name: 'Vaultwarden' } }));
		} else if (request.url === '/api/version') {
			response.writeHead(200, { 'Content-Type': 'application/json' });
			response.end(JSON.stringify(serverVersion));
		} else {
			response.writeHead(404).end();
		}
	});
	let serverVersion = '1.36.0';
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Expected a TCP test server address.');
	const dir = await mkdtemp(join(tmpdir(), 'vw-template-capability-'));
	try {
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		for (const name of ['item.bankaccount', 'item.driverslicense', 'item.passport']) {
			const unavailable = await run(dir, ['get', 'template', name]);
			expect(unavailable.code).toBe(1);
			expect(unavailable.stderr).toContain('item type is not available.');
		}
		serverVersion = '1.37.4';
		const expectedTemplates: Record<string, object> = {
			'item.bankaccount': {
				bankName: 'Acme Bank',
				nameOnAccount: 'John Doe',
				accountType: 'checking',
				accountNumber: '000123456789',
				routingNumber: '000000000',
				branchNumber: '000',
				pin: '1234',
				swiftCode: 'ACMEUS33',
				iban: 'GB00ACME12345600000001',
				bankContactPhone: '1-800-123-4567',
			},
			'item.driverslicense': {
				firstName: 'Jane',
				middleName: 'A.',
				lastName: 'Smith',
				dateOfBirth: '1990-01-15',
				licenseNumber: 'D12345678',
				issuingCountry: 'US',
				issuingState: 'CA',
				issueDate: '2020-06-01',
				expirationDate: '2028-06-01',
				issuingAuthority: 'California DMV',
				licenseClass: 'C',
			},
			'item.passport': {
				surname: 'Smith',
				givenName: 'Jane',
				dateOfBirth: '1990-01-15',
				sex: 'F',
				birthPlace: 'Los Angeles, CA',
				nationality: 'USA',
				issuingCountry: 'US',
				passportNumber: 'A12345678',
				passportType: 'P',
				nationalIdentificationNumber: '123-45-6789',
				issuingAuthority: 'U.S. Department of State',
				issueDate: '2020-06-01',
				expirationDate: '2030-06-01',
			},
		};
		for (const name of Object.keys(expectedTemplates)) {
			const available = await run(dir, ['get', 'template', name]);
			expect(available.code).toBe(0);
			expect(JSON.parse(available.stdout)).toEqual(expectedTemplates[name]);
		}
	} finally {
		await rm(dir, { recursive: true, force: true });
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
	}
});

test('Send templates match the pinned bw JSON shape for text and file Sends', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-template-'));
	try {
		for (
			const [kind, type, content] of [
				['text', 0, { text: 'Text contained in the send.', hidden: false }],
				['file', 1, { fileName: 'file attachment location' }],
			] as const
		) {
			const result = await run(dir, ['send', 'template', kind]);
			expect(result.code).toBe(0);
			const value = JSON.parse(result.stdout);
			const { deletionDate, ...template } = value;
			expect(template).toEqual({
				object: 'send',
				type,
				name: 'Send name',
				notes: 'Some notes about this send.',
				text: type === 0 ? content : null,
				file: type === 1 ? content : null,
				maxAccessCount: null,
				expirationDate: null,
				password: null,
				emails: null,
				disabled: false,
				hideEmail: false,
			});
			const parsedDeletionDate = Date.parse(deletionDate);
			expect(Number.isFinite(parsedDeletionDate)).toBe(true);
			expect(parsedDeletionDate).toBeGreaterThan(Date.now());
			expect(parsedDeletionDate).toBeLessThanOrEqual(Date.now() + 7 * 86400000 + 1000);
		}
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('global nointeraction prevents the password prompt for a protected Send', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-nointeraction-'));
	let requests = 0;
	const server = createServer((_request, response) => {
		requests++;
		response.writeHead(400, { 'Content-Type': 'application/json' });
		response.end(JSON.stringify({ send_access_error_type: 'password_hash_b64_required' }));
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	try {
		const url = `http://127.0.0.1:${address.port}/#/send/${Buffer.alloc(16, 9).toString('base64url')}/${
			Buffer.alloc(16, 1).toString('base64url')
		}`;
		const result = await run(dir, ['--nointeraction', 'receive', url]);
		expect(result.code).toBe(1);
		expect(result.stderr).toContain('Password required');
		expect(result.stderr).not.toContain('Send password:');
		expect(requests).toBe(1);
	} finally {
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('quiet suppresses JSON, text, and command errors while allowing operations, help, and exit codes', {
	timeout: 15000,
}, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-quiet-'));
	try {
		for (
			const args of [['--quiet', 'status'], ['generate', '--quiet'], ['send', 'template', 'text', '--quiet']]
		) {
			expect(await run(dir, args)).toEqual({ code: 0, stdout: '', stderr: '' });
		}
		expect(await run(dir, ['get', 'template', 'item', '--quiet'])).toEqual({
			code: 1,
			stdout: '',
			stderr: '',
		});
		expect(await run(dir, ['config', 'server', 'https://example.com/vault', '--quiet'])).toEqual({
			code: 0,
			stdout: '',
			stderr: '',
		});
		expect((await run(dir, ['config', 'server'])).stdout.trim()).toBe('https://example.com/vault');
		expect(await run(dir, ['list', 'items', '--quiet'])).toEqual({ code: 1, stdout: '', stderr: '' });
		expect((await run(dir, ['list', 'items', '--quiet=false'])).stderr).toContain('You are not logged in.');
		const parseError = await run(dir, ['generate', '--unknown-fixture-flag', '--quiet']);
		expect(parseError.code).not.toBe(0);
		expect(parseError.stderr).toContain('unknown-fixture-flag');
		expect(await run(dir, ['status'], { VW_QUIET: 'true' })).toEqual({ code: 0, stdout: '', stderr: '' });
		expect((await run(dir, ['status', '--quiet=false'], { VW_QUIET: 'true' })).stdout).toContain('unauthenticated');
		expect((await run(dir, ['--quiet', '--help'])).stdout).toContain('Vaultwarden-first');
		expect((await run(dir, ['--quiet', '--version'])).stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
		expect((await run(dir, ['encode', '--', '--quiet'])).stdout.trim()).toBe(Buffer.from('--quiet').toString('base64'));
		expect((await run(dir, ['encode'])).stdout.trim()).toBe('');
		const encoded = await run(dir, ['encode'], {}, '  piped text\n');
		expect(encoded.stdout.trim()).toBe(Buffer.from('  piped text\n').toString('base64'));
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test(
	'get misses use bw not-found text; quiet suppresses secrets without changing the cache',
	{ timeout: 15000 },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), 'vw-quiet-secrets-'));
		const key = Buffer.alloc(64, 17), id = 'abcdef01-0000-0000-0000-000000000001';
		try {
			let session = '';
			await withStore(dir, async (state, save) => {
				state.server = 'https://example.com';
				state.account = {
					email: 'synthetic@example.com',
					kdf: { type: 0, iterations: 10000 },
					encryptedUserKey: 'synthetic-wrapped-key',
					accessToken: 'synthetic-token',
					refreshToken: 'synthetic-refresh',
					expiresAt: Date.now() + 3600000,
				};
				state.vault = {
					profile: { id: 'abcdef02-0000-0000-0000-000000000002' },
					folders: [],
					collections: [],
					ciphers: [{
						...encryptItem({ type: 1, name: 'Private', login: { password: '  {"private":true}  ' } }, key),
						id,
					}],
				};
				session = sealSession(state, key);
				await save();
			});
			const before = await withStore(dir, async state => JSON.stringify(state));
			expect((await run(dir, ['get', 'password', id, '--session', session])).stdout).toBe('  {"private":true}  ');
			const uppercaseGet = await run(dir, ['get', '--session', session, 'ITEM', id.toUpperCase()]);
			expect(uppercaseGet.code).toBe(0);
			expect(JSON.parse(uppercaseGet.stdout)).toMatchObject({ id, name: 'Private' });
			const uppercaseList = await run(dir, ['list', '--session', session, '--search', 'Private', 'ITEMS']);
			expect(uppercaseList.code).toBe(0);
			expect(JSON.parse(uppercaseList.stdout).map((item: { id: string }) => item.id)).toEqual([id]);
			const missing = await run(dir, [
				'get',
				'item',
				'abcdef01-ffff-ffff-ffff-ffffffffffff',
				'--session',
				session,
			]);
			expect(missing.code).toBe(1);
			expect(missing.stderr).toContain('Not found.');
			const emptyId = await run(dir, ['get', 'item', '', '--session', session]);
			expect(emptyId.code).toBe(1);
			expect(emptyId.stderr).toContain('Not found.');
			const attachmentWithoutItem = await run(dir, ['get', 'attachment', 'file.bin', '--session', session]);
			expect(attachmentWithoutItem.code).toBe(1);
			expect(attachmentWithoutItem.stderr).toContain('--itemid <itemid> required.');
			const fingerprintWithoutKey = await run(dir, ['get', 'fingerprint', 'me', '--session', session]);
			expect(fingerprintWithoutKey.code).toBe(1);
			expect(fingerprintWithoutKey.stderr).toContain('No public key available for the active user.');
			expect((await run(dir, ['--pretty', 'get', 'password', id, '--session', session])).stdout).toBe(
				'  {"private":true}  ',
			);
			expect((await run(dir, ['export', '--format', 'json', '--raw', '--session', session, '--pretty'])).stdout).toBe(
				(await run(dir, ['export', '--format', 'json', '--raw', '--session', session])).stdout,
			);
			for (const args of [['get', 'password', id], ['export', '--format', 'json', '--raw']]) {
				expect(await run(dir, [...args, '--session', session, '--quiet'])).toEqual({ code: 0, stdout: '', stderr: '' });
			}
			expect(await withStore(dir, async state => JSON.stringify(state))).toBe(before);
		} finally {
			key.fill(0);
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test('CLI responses redact secrets when Vaultwarden denies password visibility', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-hidden-passwords-'));
	const key = Buffer.alloc(64, 23), id = 'abcdef02-0000-0000-0000-000000000002';
	const paths: string[] = [];
	const server = createServer((request, response) => {
		paths.push(request.url ?? '');
		response.setHeader('Content-Type', 'application/json');
		response.end(JSON.stringify({ server: { name: 'Bitwarden' } }));
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	const secrets = [
		'hidden-password-sentinel',
		'hidden-totp-sentinel',
		'hidden-field-sentinel',
		'hidden-history-sentinel',
		'hidden-passkey-private-key-sentinel',
	];
	try {
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.com',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user', premium: false, premiumPersonally: false, premiumFromOrganization: false },
				policies: [{ organizationId: 'synthetic-org', type: 15, enabled: true, data: [3] }],
				folders: [],
				collections: [],
				ciphers: [{
					...encryptItem({
						type: 1,
						name: 'Restricted item',
						login: {
							password: secrets[0],
							totp: secrets[1],
							fido2Credentials: [{ credentialId: 'synthetic-credential', keyValue: secrets[4] }],
						},
						fields: [{ name: 'hidden', value: secrets[2], type: 1 }],
						passwordHistory: [{ password: secrets[3], lastUsedDate: '2026-01-01T00:00:00Z' }],
					}, key),
					id,
					viewPassword: false,
				}, {
					...encryptItem({ type: 3, name: 'Restricted card', card: { number: 'restricted-card-sentinel' } }, key),
					id: 'restricted-card',
				}, {
					...encryptItem({
						type: 1,
						name: 'Visible item',
						login: { username: 'visible-user', password: 'visible-password' },
					}, key),
					id: 'visible-item',
				}, {
					...encryptItem({
						type: 1,
						name: 'TOTP item',
						login: { totp: 'JBSWY3DPEHPK3PXP' },
					}, key),
					id: 'totp-item',
				}],
			};
			session = sealSession(state, key);
			await save();
		});
		for (
			const args of [
				['list', 'items'],
				['get', 'item', id],
				['export', '--format', 'json', '--raw'],
			]
		) {
			const result = await run(dir, [...args, '--session', session]);
			expect(result.code).toBe(0);
			for (const secret of secrets) expect(result.stdout).not.toContain(secret);
			expect(result.stdout).not.toContain('"key"');
		}
		for (const object of ['password', 'totp', 'exposed']) {
			const result = await run(dir, ['get', object, id, '--session', session]);
			expect(result.code).toBe(1);
			for (const secret of secrets) expect(`${result.stdout}${result.stderr}`).not.toContain(secret);
		}
		const listed = await run(dir, ['list', 'items', '--session', session]);
		expect(listed.code).toBe(0);
		expect(listed.stdout).not.toContain('restricted-card-sentinel');
		const restricted = await run(dir, ['get', 'item', 'restricted-card', '--session', session]);
		expect(restricted.code).toBe(1);
		expect(restricted.stderr).toContain('Access to this item type is restricted by organizational policy.');
		const noPremiumTotp = await run(dir, ['get', 'totp', 'totp-item', '--session', session]);
		expect(noPremiumTotp.code).toBe(1);
		expect(noPremiumTotp.stderr).toContain('Premium status is required to use this feature.');
		const noPremiumFileSend = await run(dir, [
			'send',
			'create',
			Buffer.from(JSON.stringify({ type: 1, file: { fileName: join(dir, 'missing-send-file') } })).toString('base64'),
			'--session',
			session,
		]);
		expect(noPremiumFileSend.code).toBe(1);
		expect(noPremiumFileSend.stderr).toContain('Premium status is required to use this feature.');
		expect(noPremiumFileSend.stderr).not.toContain('ENOENT');
		expect(paths).toEqual(['/api/config']);
		const secretResponse = await run(dir, [
			'--response',
			'--pretty',
			'get',
			'password',
			'visible-item',
			'--session',
			session,
		]);
		expect(secretResponse.code).toBe(0);
		expect(JSON.parse(secretResponse.stdout)).toEqual({
			success: true,
			data: { object: 'string', data: 'visible-password' },
		});
	} finally {
		await new Promise<void>(resolve => server.close(() => resolve()));
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('list applies organization and search filters only where bw supports them', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-list-filters-'));
	const key = Buffer.alloc(64, 41);
	const organizationId = 'abcdef11-1111-1111-1111-111111111111';
	const organizationKey = Buffer.alloc(64, 42);
	const rsa = generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: { type: 'spki', format: 'der' },
		privateKeyEncoding: { type: 'pkcs8', format: 'der' },
	});
	const wrappedOrganizationKey = `3.${
		publicEncrypt({
			key: createPublicKey({ key: rsa.publicKey, format: 'der', type: 'spki' }),
			oaepHash: 'sha256',
			padding: constants.RSA_PKCS1_OAEP_PADDING,
		}, organizationKey).toString('base64')
	}`;
	const paths: string[] = [];
	const server = createServer((request, response) => {
		paths.push(request.url!);
		response.setHeader('Content-Type', 'application/json');
		response.end(JSON.stringify({
			data: [{
				object: 'unexpected-upstream-tag',
				id: 'member-id',
				email: 'member@example.test',
				name: 'Synthetic member',
				status: 2,
				type: 0,
				twoFactorEnabled: true,
				internalField: 'must not escape response projection',
			}],
		}));
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	try {
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: {
					id: 'synthetic-user',
					privateKey: encrypt(rsa.privateKey, key),
					organizations: [
						{
							id: organizationId,
							name: 'First organization',
							email: 'billing@example.test',
							key: wrappedOrganizationKey,
							status: 2,
							type: 0,
							enabled: true,
						},
						{
							id: '22222222-2222-2222-2222-222222222222',
							name: 'Second organization',
							key: wrappedOrganizationKey,
							status: 2,
							type: 0,
							enabled: true,
						},
					],
				},
				folders: [{
					id: 'folder-id',
					name: encrypt(Buffer.from('Private folder'), key),
					revisionDate: '2026-01-01T00:00:00.000Z',
					internalField: 'must not escape response projection',
				}],
				collections: [{
					id: 'collection-id',
					name: encrypt(Buffer.from('Private collection'), key),
					organizationId: null,
					externalId: null,
					manage: true,
					internalField: 'must not escape response projection',
				}, {
					id: 'organization-collection',
					name: encrypt(Buffer.from('Organization collection'), organizationKey),
					organizationId,
					externalId: null,
					manage: true,
				}],
				ciphers: [{
					...encryptItem({ type: 1, name: 'Compatibility Search Login', login: { username: 'search-user' } }, key),
					id: 'search-item-id',
				}, {
					...encryptItem({ type: 1, name: 'Ordinary Login', login: { username: 'ordinary-user' } }, key),
					id: 'ordinary-item-id',
				}, {
					...encryptItem({ type: 1, name: 'Unassigned null folder', login: { username: 'null-folder-user' } }, key),
					id: 'null-folder-item-id',
					folderId: null,
				}],
			};
			session = sealSession(state, key);
			await save();
		});
		const folders = await run(dir, ['list', 'folders', '--organizationid', 'missing', '--session', session]);
		expect(folders.code).toBe(0);
		expect(JSON.parse(folders.stdout)).toEqual([{ object: 'folder', id: 'folder-id', name: 'Private folder' }]);
		const allItems = await run(dir, ['list', 'items', '--session', session]);
		expect(allItems.code, allItems.stderr).toBe(0);
		expect(JSON.parse(allItems.stdout).map((item: { id: string }) => item.id)).toEqual([
			'search-item-id',
			'ordinary-item-id',
			'null-folder-item-id',
		]);
		const itemsWithoutFolder = await run(dir, ['list', 'items', '--folderid', 'null', '--session', session]);
		expect(itemsWithoutFolder.code, itemsWithoutFolder.stderr).toBe(0);
		expect(JSON.parse(itemsWithoutFolder.stdout).map((item: { id: string }) => item.id)).toEqual([
			'search-item-id',
			'ordinary-item-id',
			'null-folder-item-id',
		]);
		const itemsWithoutOrganization = await run(dir, [
			'list',
			'items',
			'--organizationid',
			'null',
			'--session',
			session,
		]);
		expect(itemsWithoutOrganization.code, itemsWithoutOrganization.stderr).toBe(0);
		expect(JSON.parse(itemsWithoutOrganization.stdout).map((item: { id: string }) => item.id)).toEqual([
			'search-item-id',
			'ordinary-item-id',
			'null-folder-item-id',
		]);
		const advancedItemSearch = await run(dir, [
			'list',
			'items',
			'--search',
			'>name:compatibility',
			'--session',
			session,
		]);
		expect(advancedItemSearch.code, advancedItemSearch.stderr).toBe(0);
		expect(JSON.parse(advancedItemSearch.stdout)).toEqual([]);
		const shortItemSearch = await run(dir, ['list', 'items', '--search', 'p', '--session', session]);
		expect(shortItemSearch.code).toBe(0);
		expect(JSON.parse(shortItemSearch.stdout).map((item: { id: string }) => item.id)).toEqual(['search-item-id']);
		const whitespaceSearchFolders = await run(dir, ['list', 'folders', '--search', '   ', '--session', session]);
		expect(whitespaceSearchFolders.code).toBe(0);
		expect(JSON.parse(whitespaceSearchFolders.stdout).map((folder: { name: string }) => folder.name)).toEqual([
			'Private folder',
		]);
		const collections = await run(dir, ['list', 'collections', '--session', session]);
		expect(JSON.parse(collections.stdout)).toEqual([{
			object: 'collection',
			id: 'collection-id',
			organizationId: null,
			name: 'Private collection',
			externalId: null,
		}, {
			object: 'collection',
			id: 'organization-collection',
			organizationId,
			name: 'Organization collection',
			externalId: null,
		}]);
		const folderResponse = await run(dir, ['--response', 'list', 'folders', '--session', session]);
		expect(JSON.parse(folderResponse.stdout)).toEqual({
			success: true,
			data: { object: 'list', data: [{ object: 'folder', id: 'folder-id', name: 'Private folder' }] },
		});
		const collectionResponse = await run(dir, ['--response', 'list', 'collections', '--session', session]);
		expect(JSON.parse(collectionResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'list',
				data: [{
					object: 'collection',
					id: 'collection-id',
					organizationId: null,
					name: 'Private collection',
					externalId: null,
				}, {
					object: 'collection',
					id: 'organization-collection',
					organizationId,
					name: 'Organization collection',
					externalId: null,
				}],
			},
		});
		const organizationCollections = await run(dir, [
			'list',
			'collections',
			'--organizationid',
			organizationId,
			'--session',
			session,
		]);
		expect(organizationCollections.code).toBe(0);
		expect(JSON.parse(organizationCollections.stdout).map((collection: { id: string }) => collection.id)).toEqual([
			'organization-collection',
		]);
		const uppercaseOrganizationFilter = await run(dir, [
			'list',
			'collections',
			'--organizationid',
			organizationId.toUpperCase(),
			'--session',
			session,
		]);
		expect(uppercaseOrganizationFilter.code).toBe(0);
		expect(JSON.parse(uppercaseOrganizationFilter.stdout)).toEqual([]);
		for (
			const [object, id, expected] of [
				['folder', 'Private folder', { object: 'folder', id: 'folder-id', name: 'Private folder' }],
				[
					'collection',
					'Private collection',
					{
						object: 'collection',
						id: 'collection-id',
						organizationId: null,
						name: 'Private collection',
						externalId: null,
					},
				],
				[
					'organization',
					'first organization',
					{
						object: 'organization',
						id: organizationId,
						name: 'First organization',
						status: 2,
						type: 0,
						enabled: true,
					},
				],
			] as const
		) {
			const normal = await run(dir, ['get', object, id, '--session', session]);
			expect(normal.code).toBe(0);
			expect(JSON.parse(normal.stdout)).toEqual(expected);
			const result = await run(dir, ['--response', 'get', object, id, '--session', session]);
			expect(result.code).toBe(0);
			expect(JSON.parse(result.stdout)).toEqual({ success: true, data: expected });
		}
		const organizations = await run(dir, [
			'list',
			'organizations',
			'--organizationid',
			organizationId,
			'--session',
			session,
		]);
		expect(organizations.code).toBe(0);
		expect(JSON.parse(organizations.stdout)).toEqual([
			{
				object: 'organization',
				id: organizationId,
				name: 'First organization',
				status: 2,
				type: 0,
				enabled: true,
			},
			{
				object: 'organization',
				id: '22222222-2222-2222-2222-222222222222',
				name: 'Second organization',
				status: 2,
				type: 0,
				enabled: true,
			},
		]);
		const organizationResponse = await run(dir, [
			'--response',
			'list',
			'organizations',
			'--session',
			session,
		]);
		expect(JSON.parse(organizationResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'list',
				data: [
					{
						object: 'organization',
						id: organizationId,
						name: 'First organization',
						status: 2,
						type: 0,
						enabled: true,
					},
					{
						object: 'organization',
						id: '22222222-2222-2222-2222-222222222222',
						name: 'Second organization',
						status: 2,
						type: 0,
						enabled: true,
					},
				],
			},
		});
		const organizationEmailSearch = await run(dir, [
			'list',
			'organizations',
			'--search',
			'billing@example.test',
			'--session',
			session,
		]);
		expect(JSON.parse(organizationEmailSearch.stdout)).toEqual([]);
		const organizationNameSearch = await run(dir, [
			'list',
			'organizations',
			'--search',
			'first organization',
			'--session',
			session,
		]);
		expect(JSON.parse(organizationNameSearch.stdout)).toHaveLength(1);
		const members = await run(dir, [
			'list',
			'org-members',
			'--organizationid',
			organizationId,
			'--search',
			'no-match',
			'--session',
			session,
		]);
		expect(members.code).toBe(0);
		expect(JSON.parse(members.stdout)).toEqual([{
			object: 'org-member',
			id: 'member-id',
			email: 'member@example.test',
			name: 'Synthetic member',
			status: 2,
			type: 0,
			twoFactorEnabled: true,
		}]);
		const memberResponse = await run(dir, [
			'--response',
			'list',
			'org-members',
			'--organizationid',
			organizationId,
			'--session',
			session,
		]);
		expect(memberResponse.code).toBe(0);
		expect(JSON.parse(memberResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'list',
				data: [{
					object: 'org-member',
					id: 'member-id',
					email: 'member@example.test',
					name: 'Synthetic member',
					status: 2,
					type: 0,
					twoFactorEnabled: true,
				}],
			},
		});
		expect(paths).toEqual([
			`/api/organizations/${organizationId}/users`,
			`/api/organizations/${organizationId}/users`,
		]);
		for (const [id, org] of [['not-a-guid', organizationId], ['00000000-0000-0000-0000-000000000001', 'not-a-guid']]) {
			const invalidCollection = await run(dir, [
				'get',
				'org-collection',
				id!,
				'--organizationid',
				org!,
				'--session',
				session,
			]);
			expect(invalidCollection.code).toBe(1);
			expect(invalidCollection.stderr).toContain('is not a GUID.');
		}
		for (const [id, org] of [['not-a-guid', organizationId], ['00000000-0000-0000-0000-000000000001', 'not-a-guid']]) {
			const invalidConfirmation = await run(dir, [
				'confirm',
				'org-member',
				id!,
				'--organizationid',
				org!,
				'--session',
				session,
			]);
			expect(invalidConfirmation.code).toBe(1);
			expect(invalidConfirmation.stderr).toContain('is not a GUID.');
		}
		expect(paths).toEqual([
			`/api/organizations/${organizationId}/users`,
			`/api/organizations/${organizationId}/users`,
		]);
	} finally {
		key.fill(0);
		organizationKey.fill(0);
		rsa.privateKey.fill(0);
		server.closeAllConnections();
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('built CLI edit carries omitted cipher data and sends an explicit folder clear', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-built-edit-'));
	const key = Buffer.alloc(64, 36);
	const cipherId = '11111111-2222-4333-8444-555555555555';
	const original = {
		...encryptItem({
			type: 1,
			name: 'Before edit',
			notes: 'unchanged note',
			favorite: true,
			login: { username: 'unchanged-user', password: 'unchanged-secret' },
			fields: [{ name: 'unchanged field', value: 'unchanged value', type: 0 }],
		}, key),
		id: cipherId,
		key: null,
		edit: true,
		permissions: { delete: true, restore: true },
		folderId: 'folder-id',
		revisionDate: '2026-01-01T00:00:00.000Z',
	};
	let submitted: Record<string, unknown> | undefined;
	const server = createServer(async (request, response) => {
		if (request.method === 'GET' && request.url === '/api/accounts/revision-date') {
			response.writeHead(200, { 'Content-Type': 'application/json' }).end('1');
			return;
		}
		if (request.method === 'GET' && request.url === '/api/sync?excludeDomains=false') {
			response.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({
				profile: { id: 'synthetic-user' },
				ciphers: [submitted ? { ...submitted, id: cipherId, revisionDate: '2026-02-01T00:00:00.000Z' } : original],
				folders: [],
			}));
			return;
		}
		if (request.method !== 'PUT' || request.url !== `/api/ciphers/${cipherId}`) {
			response.writeHead(404).end('{}');
			return;
		}
		let body = '';
		for await (const chunk of request) body += chunk;
		submitted = JSON.parse(body);
		response.writeHead(200, { 'Content-Type': 'application/json' });
		response.end(JSON.stringify({ ...submitted, id: cipherId, revisionDate: '2026-02-01T00:00:00.000Z' }));
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing built-edit fixture address.');
	try {
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user' },
				ciphers: [original],
				folders: [],
			};
			session = sealSession(state, key);
			await save();
		});
		const encoded = Buffer.from(JSON.stringify({ type: 1, name: 'After edit', folderId: null })).toString('base64');
		const result = await run(dir, ['edit', 'item', cipherId, encoded, '--session', session]);
		if (result.code !== 0) throw new Error(`Built edit failed: ${result.stderr}`);
		expect(result.code).toBe(0);
		expect(JSON.parse(result.stdout)).toMatchObject({ name: 'After edit', notes: 'unchanged note' });
		expect(submitted).toMatchObject({ favorite: true, folderId: null });
		expect(decrypt(String(submitted!.name), key).toString()).toBe('After edit');
		expect(decrypt(String(submitted!.notes), key).toString()).toBe('unchanged note');
		const login = submitted!.login as Record<string, string>;
		expect(decrypt(String(login.username), key).toString()).toBe('unchanged-user');
		expect(decrypt(String(login.password), key).toString()).toBe('unchanged-secret');
		const [field] = submitted!.fields as Record<string, unknown>[];
		expect(decrypt(String(field!.name), key).toString()).toBe('unchanged field');
		expect(decrypt(String(field!.value), key).toString()).toBe('unchanged value');
	} finally {
		key.fill(0);
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('ambiguous item lookup reports the matching IDs like bw', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-ambiguous-get-'));
	const key = Buffer.alloc(64, 52);
	let session = '';
	const ids = ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222'];
	try {
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user', organizations: [] },
				folders: ids.map((id, index) => ({ id, name: encrypt(Buffer.from(`Shared folder ${index}`), key) })),
				ciphers: ids.map((id, index) => ({
					...encryptItem({ type: 1, name: `Shared login ${index}`, login: { username: `user-${index}` } }, key),
					id,
					...(index === 0
						? {
							attachments: [
								{ id: 'attachment-one', fileName: encrypt(Buffer.from('Shared attachment one.bin'), key) },
								{ id: 'attachment-two', fileName: encrypt(Buffer.from('Shared attachment two.bin'), key) },
							],
						}
						: {}),
				})),
			};
			session = sealSession(state, key);
			await save();
		});
		const plain = await run(dir, ['get', 'item', 'Shared', '--session', session]);
		expect(plain.code).toBe(1);
		expect(plain.stderr).toContain('More than one result was found. Try getting a specific object by `id` instead.');
		for (const id of ids) expect(plain.stderr).toContain(id);
		const response = await run(dir, ['--response', 'get', 'item', 'Shared', '--session', session]);
		expect(response.code).toBe(1);
		expect(JSON.parse(response.stdout)).toEqual({
			success: false,
			message:
				`More than one result was found. Try getting a specific object by \`id\` instead. The following objects were found:\n${
					ids.join('\n')
				}`,
			data: ids,
		});
		const folders = await run(dir, ['--response', 'get', 'folder', 'Shared', '--session', session]);
		expect(folders.code).toBe(1);
		expect(JSON.parse(folders.stdout)).toEqual({
			success: false,
			message:
				`More than one result was found. Try getting a specific object by \`id\` instead. The following objects were found:\n${
					ids.join('\n')
				}`,
			data: ids,
		});
		const attachments = await run(dir, [
			'--response',
			'get',
			'attachment',
			'Shared attachment',
			'--itemid',
			ids[0]!,
			'--session',
			session,
		]);
		expect(attachments.code).toBe(1);
		expect(JSON.parse(attachments.stdout)).toEqual({
			success: false,
			message: 'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nattachment-one\nattachment-two',
			data: ['attachment-one', 'attachment-two'],
		});
	} finally {
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('built CLI attachment ID lookup ignores a different attachment filename that equals that ID', {
	timeout: 15000,
}, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-attachment-id-collision-'));
	const key = Buffer.alloc(64, 61);
	const itemId = 'item-attachment-collision';
	const requestedBytes = Buffer.from('expected attachment A');
	const substitutedBytes = Buffer.from('substituted attachment B');
	const routes: string[] = [];
	const server = createServer((request, response) => {
		const path = request.url ?? '';
		routes.push(path);
		if (path === '/api/ciphers/item-attachment-collision/attachment/first') {
			response.setHeader('Content-Type', 'application/json');
			response.end(
				JSON.stringify({ url: `http://127.0.0.1:${(server.address() as { port: number }).port}/files/first` }),
			);
		} else if (path === '/files/first') {
			response.end(encryptAttachment(requestedBytes, key));
		} else if (path === '/files/second') {
			response.end(encryptAttachment(substitutedBytes, key));
		} else {
			response.statusCode = 404;
			response.end();
		}
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing attachment fixture address.');
	let session = '';
	try {
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user', premium: true, premiumPersonally: true },
				ciphers: [{
					...encryptItem({
						type: 1,
						name: 'Attachment collision fixture',
						attachments: [
							{ id: 'first', fileName: 'original-a.bin' },
							{ id: 'second', fileName: 'first' },
						],
					}, key),
					id: itemId,
				}],
			};
			session = sealSession(state, key);
			await save();
		});
		const output = join(dir, 'download.bin');
		const result = await run(dir, [
			'get',
			'attachment',
			'first',
			'--itemid',
			itemId,
			'--output',
			output,
			'--session',
			session,
		]);
		expect(result.code).toBe(0);
		expect(await readFile(output)).toEqual(requestedBytes);
		expect(routes).toEqual([
			'/api/ciphers/item-attachment-collision/attachment/first',
			'/files/first',
		]);
	} finally {
		key.fill(0);
		await new Promise<void>(resolve => server.close(() => resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test(
	'pretty formats structured JSON across global and nested commands without changing raw values',
	{ timeout: 15000 },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), 'vw-pretty-'));
		try {
			await withStore(dir, async (state, save) => {
				state.account = {
					email: 'synthetic@example.test',
					kdf: { type: 0, iterations: 10000 },
					encryptedUserKey: 'synthetic-wrapped-key',
					accessToken: 'synthetic-token',
					refreshToken: 'synthetic-refresh',
					expiresAt: Date.now() + 3600000,
				};
				await save();
			});
			const compact = await run(dir, ['get', 'template', 'item']);
			expect(compact.code).toBe(0);
			const value = JSON.parse(compact.stdout), expected = JSON.stringify(value, null, 2) + '\n';
			expect(compact.stdout).toBe(JSON.stringify(value) + '\n');
			for (const args of [['--pretty', 'get', 'template', 'item'], ['get', 'template', 'item', '--pretty']]) {
				expect(await run(dir, args)).toEqual({ code: 0, stdout: expected, stderr: '' });
			}
			expect((await run(dir, ['get', 'template', 'item'], { VW_PRETTY: 'true' })).stdout).toBe(expected);
			expect((await run(dir, ['get', 'template', 'item', '--pretty=false'], { VW_PRETTY: 'true' })).stdout).toBe(
				compact.stdout,
			);
			const nested = await run(dir, ['--pretty', 'send', 'template', 'text']);
			expect(nested.code).toBe(0);
			expect(nested.stdout).toBe(JSON.stringify(JSON.parse(nested.stdout), null, 2) + '\n');
			expect((await run(dir, ['get', 'template', 'item', '--json', '--pretty'])).stdout).toBe(expected);
			expect(await run(dir, ['--pretty', 'status', '--quiet'])).toEqual({ code: 0, stdout: '', stderr: '' });
			expect((await run(dir, ['encode', '--', '--pretty'])).stdout.trim()).toBe(
				Buffer.from('--pretty').toString('base64'),
			);
			expect((await run(dir, ['get', '--help'])).stdout).toContain('--pretty');
			expect((await run(dir, [])).stdout).toContain('Vaultwarden-first');
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test('the CLI-name-prefixed session environment unlocks status', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-session-env-'));
	const key = Buffer.alloc(64, 29);
	try {
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.com';
			state.account = {
				email: 'synthetic@example.com',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			session = sealSession(state, key);
			await save();
		});
		expect(JSON.parse((await run(dir, ['status'], { VW_SESSION: session })).stdout).status).toBe('unlocked');
		expect(JSON.parse((await run(dir, ['--session', session, 'status'])).stdout).status).toBe('unlocked');
		expect(JSON.parse((await run(dir, [`--session=${session}`, 'status'])).stdout).status).toBe('unlocked');
		expect((await run(dir, ['generate', '--length', '5', '--session', session])).stdout.trim()).toHaveLength(5);
		expect(JSON.parse((await run(dir, ['status'], { VW_SESSION: 'invalid' })).stdout).status).toBe('locked');
		expect(JSON.parse((await run(dir, ['--response', 'login', '--check'])).stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'You are logged in!', message: null, noColor: false },
		});
		expect(JSON.parse((await run(dir, ['--response', 'unlock', '--check'], { VW_SESSION: session })).stdout))
			.toEqual({
				success: true,
				data: { object: 'message', title: 'Vault is unlocked!', message: null, noColor: false },
			});
	} finally {
		key.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test(
	'response mode matches bw envelopes for status, generated strings, and command errors',
	{ timeout: 15000 },
	async () => {
		const dir = await mkdtemp(join(tmpdir(), 'vw-response-'));
		try {
			const status = await run(dir, ['--response', 'status']);
			expect(status.code).toBe(0);
			expect(JSON.parse(status.stdout)).toEqual({
				success: true,
				data: {
					object: 'template',
					template: { serverUrl: null, lastSync: null, status: 'unauthenticated' },
				},
			});
			const generated = await run(dir, ['generate', '--response', '--length', '8']);
			expect(generated.code).toBe(0);
			expect(JSON.parse(generated.stdout)).toMatchObject({ success: true, data: { object: 'string' } });
			expect(JSON.parse(generated.stdout).data.data).toMatch(/^.{8}$/);
			const encoded = await run(dir, ['encode', 'response fixture', '--response']);
			expect(JSON.parse(encoded.stdout)).toEqual({
				success: true,
				data: { object: 'string', data: Buffer.from('response fixture').toString('base64') },
			});
			const configured = await run(dir, ['config', 'server', 'https://vault.example.test', '--response']);
			expect(JSON.parse(configured.stdout)).toEqual({
				success: true,
				data: { object: 'message', title: 'Saved setting `config`.', message: null, noColor: false },
			});
			const configRead = await run(dir, ['--response', 'config', 'server', '']);
			expect(JSON.parse(configRead.stdout)).toEqual({
				success: true,
				data: { object: 'string', data: 'https://vault.example.test' },
			});
			const whitespaceConfigRead = await run(dir, ['--response', 'config', 'server', '   ']);
			expect(JSON.parse(whitespaceConfigRead.stdout)).toEqual(JSON.parse(configRead.stdout));
			await withStore(dir, async (state, save) => {
				state.account = {
					email: 'synthetic@example.test',
					kdf: { type: 0, iterations: 10000 },
					encryptedUserKey: 'synthetic-wrapped-key',
					accessToken: 'synthetic-token',
					refreshToken: 'synthetic-refresh',
					expiresAt: Date.now() + 3600000,
				};
				await save();
			});
			const itemTemplate = await run(dir, ['--response', 'get', 'template', 'item']);
			expect(JSON.parse(itemTemplate.stdout)).toMatchObject({ success: true, data: { object: 'template' } });
			await withStore(dir, async (state, save) => {
				delete state.account;
				await save();
			});
			const sendTemplate = await run(dir, ['send', 'template', 'text', '--response']);
			expect(JSON.parse(sendTemplate.stdout)).toMatchObject({
				success: true,
				data: { object: 'template', template: { object: 'send' } },
			});
			const sdkVersion = await run(dir, ['sdk-version']);
			expect((await run(dir, ['--response', 'sdk-version'])).stdout).toBe(sdkVersion.stdout);
			expect((await run(dir, ['--response'])).stdout).toContain('Vaultwarden-first');
			const failure = await run(dir, ['--response', 'list', 'items']);
			expect(failure.code).toBe(1);
			expect(JSON.parse(failure.stdout)).toEqual({ success: false, message: 'You are not logged in.' });
			expect(failure.stderr).toBe('');
			const fromEnvironment = await run(dir, ['status'], { VW_RESPONSE: 'true' });
			expect(JSON.parse(fromEnvironment.stdout)).toMatchObject({ success: true, data: { object: 'template' } });
			expect(JSON.parse((await run(dir, ['status'], { VW_RESPONSE: 'false' })).stdout))
				.toMatchObject({ serverUrl: 'https://vault.example.test', status: 'unauthenticated' });
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	},
);

test('lock and logout success messages match pinned bw responses', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-auth-messages-'));
	try {
		await withStore(dir, async (state, save) => {
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		expect(JSON.parse((await run(dir, ['--response', 'lock'])).stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'Your vault is locked.', message: null, noColor: false },
		});
		expect(JSON.parse((await run(dir, ['--response', 'logout'])).stdout)).toEqual({
			success: true,
			data: { object: 'message', title: 'You have logged out.', message: null, noColor: false },
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('status reports the authenticated user ID from the token without requiring a synced vault', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-status-user-'));
	const userId = '11111111-2222-4333-8444-555555555555';
	try {
		await withStore(dir, async (state, save) => {
			state.server = 'https://vault.example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: `header.${Buffer.from(JSON.stringify({ sub: userId })).toString('base64url')}.signature`,
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const normal = await run(dir, ['status']);
		expect(normal.code).toBe(0);
		expect(JSON.parse(normal.stdout)).toMatchObject({ userId, userEmail: 'synthetic@example.test' });
		const response = await run(dir, ['--response', 'status']);
		expect(JSON.parse(response.stdout)).toMatchObject({
			success: true,
			data: { object: 'template', template: { userId, userEmail: 'synthetic@example.test' } },
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('unlock prints session guidance by default and exposes the token only through raw output', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-session-output-'));
	const email = 'synthetic@example.test', password = 'synthetic-session-password';
	const kdf = { type: 0 as const, iterations: 10000 }, userKey = Buffer.alloc(64, 31);
	const master = await deriveMasterKey(password, email, kdf), stretched = stretchKey(master);
	try {
		const encryptedUserKey = encrypt(userKey, stretched);
		await withStore(dir, async (state, save) => {
			state.account = {
				email,
				kdf,
				encryptedUserKey,
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		const normal = await run(dir, ['unlock', password]);
		expect(normal.code).toBe(0);
		expect(normal.stdout).toContain('Your vault is now unlocked!');
		expect(normal.stdout).toContain('VW_SESSION');
		expect(normal.stdout).toContain('$ vw list items --session ');
		const raw = await run(dir, ['unlock', password, '--raw']);
		expect(raw.code).toBe(0);
		expect(raw.stdout.trim()).toMatch(/^[A-Za-z0-9+/]+=*$/);
		const rawFromEnvironment = await run(dir, ['unlock', password], { VW_RAW: 'true' });
		expect(rawFromEnvironment.code).toBe(0);
		expect(rawFromEnvironment.stdout.trim()).toMatch(/^[A-Za-z0-9+/]+=*$/);
		const response = await run(dir, ['--response', 'unlock', password]);
		expect(JSON.parse(response.stdout)).toMatchObject({
			success: true,
			data: {
				object: 'message',
				title: 'Your vault is now unlocked!',
				message: expect.stringContaining('VW_SESSION'),
				raw: expect.any(String),
			},
		});
	} finally {
		master.fill(0);
		stretched.fill(0);
		userKey.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('sync reads its last date offline, checks revisions, and forces full downloads without an unlock token', {
	timeout: 15000,
}, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-sync-'));
	const paths: string[] = [];
	let revision = 0, unauthorized = false, downloads = 0, downloadStarted = 0;
	const server = createServer((request, response) => {
		paths.push(request.url!);
		response.setHeader('Content-Type', 'application/json');
		if (request.url === '/identity/connect/token') {
			response.end(
				JSON.stringify({ access_token: 'renewed-synthetic-token', refresh_token: 'renewed', expires_in: 3600 }),
			);
		} else if (unauthorized) {
			unauthorized = false;
			response.writeHead(401).end('{}');
		} else if (request.url === '/api/accounts/revision-date') response.end(JSON.stringify(revision));
		else if (request.url === '/api/sync?excludeDomains=false') {
			downloads++;
			downloadStarted = Date.now();
			setTimeout(() => response.end(JSON.stringify({ profile: { id: 'synthetic-user' }, ciphers: [] })), 20);
		} else response.writeHead(404).end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	try {
		expect((await run(dir, ['sync', '--last'])).code).toBe(1);
		await withStore(dir, async (state, save) => {
			state.server = `http://127.0.0.1:${address.port}`;
			state.account = {
				email: 'synthetic@example.com',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-token',
				refreshToken: 'synthetic-refresh',
				expiresAt: Date.now() + 3600000,
			};
			await save();
		});
		expect((await run(dir, ['sync', '--last'])).stdout).toBe('');
		expect(JSON.parse((await run(dir, ['--response', 'sync', '--last'])).stdout)).toEqual({
			success: true,
			data: { object: 'string', data: null },
		});
		expect(paths).toEqual([]);
		expect((await run(dir, ['sync'])).stdout.trim()).toBe('Syncing complete.');
		expect(downloads).toBe(1);
		const firstDate = (await run(dir, ['sync', '--last'])).stdout.trim();
		expect(Number.isFinite(Date.parse(firstDate))).toBe(true);
		expect(Date.parse(firstDate)).toBeLessThanOrEqual(downloadStarted);
		expect(JSON.parse((await run(dir, ['--response', 'sync', '--last'])).stdout)).toEqual({
			success: true,
			data: { object: 'string', data: firstDate },
		});
		paths.length = 0;
		expect((await run(dir, ['sync'])).code).toBe(0);
		expect(paths).toEqual(['/api/accounts/revision-date']);
		expect(downloads).toBe(1);
		paths.length = 0;
		expect((await run(dir, ['sync', '-f'])).code).toBe(0);
		expect(paths).toEqual(['/api/sync?excludeDomains=false']);
		expect(downloads).toBe(2);
		paths.length = 0;
		const saved = await withStore(dir, async state => JSON.stringify(state));
		expect((await run(dir, ['sync', '--last', '--force'])).code).toBe(0);
		expect(paths).toEqual([]);
		expect(await withStore(dir, async state => JSON.stringify(state))).toBe(saved);
		revision = Date.now() + 60000;
		unauthorized = true;
		expect((await run(dir, ['sync'])).code).toBe(0);
		expect(paths).toEqual([
			'/api/accounts/revision-date',
			'/identity/connect/token',
			'/api/accounts/revision-date',
			'/api/sync?excludeDomains=false',
		]);
		expect(downloads).toBe(3);
		const beforeFailure = (await run(dir, ['sync', '--last'])).stdout;
		revision = NaN; // JSON null is an invalid revision, not permission to skip the download.
		const invalidRevision = await run(dir, ['sync']);
		expect(invalidRevision.code).toBe(1);
		expect(invalidRevision.stderr).toContain('Syncing failed:');
		expect((await run(dir, ['sync', '--last'])).stdout).toBe(beforeFailure);
		expect(downloads).toBe(3);
		revision = -1;
		const failedRequest = await run(dir, ['sync']);
		expect(failedRequest.code).toBe(1);
		expect(failedRequest.stderr).toContain('Syncing failed: Account was deleted. Log in again.');
		expect((await run(dir, ['status'])).stdout).toContain('unauthenticated');
	} finally {
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('API-key login syncs before returning the unlock guidance', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-api-login-'));
	const calls: string[] = [];
	const submittedCredentials: [string | null, string | null][] = [];
	const userId = '11111111-1111-1111-1111-111111111111';
	let authenticatedUserId = userId;
	const server = createServer(async (request, response) => {
		calls.push(request.url!);
		response.setHeader('Content-Type', 'application/json');
		if (request.url === '/identity/connect/token') {
			const body = await new Promise<string>(resolve => {
				let value = '';
				request.setEncoding('utf8').on('data', chunk => value += chunk).on('end', () => resolve(value));
			});
			const form = new URLSearchParams(body);
			expect(form.get('grant_type')).toBe('client_credentials');
			submittedCredentials.push([form.get('client_id'), form.get('client_secret')]);
			authenticatedUserId = form.get('client_id')?.slice('user.'.length) ?? userId;
			response.end(JSON.stringify({
				access_token: 'synthetic-api-access-token',
				expires_in: 3600,
				key: 'synthetic-wrapped-user-key',
				kdf: 0,
				kdfIterations: 10000,
			}));
		} else if (request.url === '/api/accounts/profile') {
			response.end(JSON.stringify({ id: authenticatedUserId, email: 'synthetic@example.com' }));
		} else if (request.url === '/api/sync?excludeDomains=false') {
			response.end(JSON.stringify({ profile: { id: authenticatedUserId }, ciphers: [] }));
		} else response.writeHead(404).end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing API-login fixture address.');
	const environment = {
		VW_CLIENTID: `user.${userId}`,
		VW_CLIENTSECRET: 'synthetic-api-client-secret',
	};
	try {
		expect((await run(dir, ['config', 'server', `http://127.0.0.1:${address.port}`])).code).toBe(0);
		const login = await run(dir, ['login', '--apikey', '--nointeraction'], environment);
		expect(login.code).toBe(0);
		expect(login.stdout).toContain('You are logged in!');
		expect(login.stdout).toContain('$ vw unlock');
		expect(calls).toEqual([
			'/identity/connect/token',
			'/api/accounts/profile',
			'/api/sync?excludeDomains=false',
		]);
		expect(submittedCredentials.at(-1)).toEqual([`user.${userId}`, 'synthetic-api-client-secret']);
		await withStore(dir, async state => {
			expect(state.account?.auth).toBe('api-key');
			expect(state.vault).toEqual({ profile: { id: userId }, ciphers: [] });
			expect(state.lastSync).toBeDefined();
		});
		const logout = await run(dir, ['logout']);
		expect(logout.code).toBe(0);
		calls.length = 0;
		const namedCredentials = await run(dir, [
			'login',
			'--apikey',
			'--clientidenv',
			'VW_TEST_NAMED_CLIENT_ID',
			'--clientsecretenv',
			'VW_TEST_NAMED_CLIENT_SECRET',
			'--nointeraction',
		], {
			...environment,
			VW_TEST_NAMED_CLIENT_ID: 'user.22222222-2222-2222-2222-222222222222',
			VW_TEST_NAMED_CLIENT_SECRET: 'named-client-secret',
		});
		expect(namedCredentials.code, namedCredentials.stderr).toBe(0);
		expect(submittedCredentials.at(-1)).toEqual([
			'user.22222222-2222-2222-2222-222222222222',
			'named-client-secret',
		]);
		expect(calls).toEqual([
			'/identity/connect/token',
			'/api/accounts/profile',
			'/api/sync?excludeDomains=false',
		]);
		expect((await run(dir, ['logout'])).code).toBe(0);
		calls.length = 0;
		const explicitCredentials = await run(dir, [
			'login',
			'--apikey',
			'--clientid',
			'user.33333333-3333-3333-3333-333333333333',
			'--clientsecret',
			'explicit-client-secret',
			'--clientidenv',
			'VW_TEST_NAMED_CLIENT_ID',
			'--clientsecretenv',
			'VW_TEST_NAMED_CLIENT_SECRET',
			'--nointeraction',
		], {
			...environment,
			VW_TEST_NAMED_CLIENT_ID: 'user.22222222-2222-2222-2222-222222222222',
			VW_TEST_NAMED_CLIENT_SECRET: 'named-client-secret',
		});
		expect(explicitCredentials.code, explicitCredentials.stderr).toBe(0);
		expect(submittedCredentials.at(-1)).toEqual([
			'user.33333333-3333-3333-3333-333333333333',
			'explicit-client-secret',
		]);
		expect((await run(dir, ['logout'])).code).toBe(0);
		calls.length = 0;
		const responseLogin = await run(dir, ['--response', 'login', '--apikey', '--nointeraction'], environment);
		expect(responseLogin.code).toBe(0);
		expect(JSON.parse(responseLogin.stdout)).toEqual({
			success: true,
			data: {
				object: 'message',
				title: 'You are logged in!',
				message: '\nTo unlock your vault, use the `unlock` command. ex:\n$ vw unlock',
				noColor: false,
			},
		});
		expect(calls).toEqual([
			'/identity/connect/token',
			'/api/accounts/profile',
			'/api/sync?excludeDomains=false',
		]);
	} finally {
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('organization device approval exposes the reference subcommands and requires an authenticated session', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-device-approval-'));
	try {
		const help = await run(dir, ['device-approval', '--help']);
		expect(help.code).toBe(0);
		for (const name of ['list', 'approve', 'approve-all', 'deny', 'deny-all']) {
			expect(help.stdout).toContain(name);
		}
		const approvalHelp = await run(dir, ['device-approval', 'help']);
		expect(approvalHelp.code).toBe(0);
		expect(approvalHelp.stdout).toContain('help');
		const listHelp = await run(dir, ['device-approval', 'help', 'list']);
		expect(listHelp.code).toBe(0);
		expect(listHelp.stdout).toContain('Usage: vw device-approval list');
		expect(listHelp.stdout).toContain('--organizationid');
		const unknownHelp = await run(dir, ['device-approval', 'help', 'unknown']);
		expect(unknownHelp.code).toBe(0);
		expect(unknownHelp.stdout).toContain('device-approval <command>');
		for (const name of ['list', 'approve', 'deny', 'approve-all', 'deny-all']) {
			const args = [
				'device-approval',
				name,
				...(['approve', 'deny'].includes(name) ? ['11111111-1111-1111-1111-111111111111'] : []),
				'--organizationid',
				'22222222-2222-2222-2222-222222222222',
				'--session',
				'synthetic-session',
			];
			const result = await run(dir, args);
			expect(result.code).toBe(1);
			expect(result.stderr).toContain('You are not logged in.');
			expect(result.stderr).not.toContain('synthetic-session');
		}
		expect((await run(dir, ['device-approval', 'list'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test('configured service overrides route CLI authentication and are cleared by a new base URL', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-config-'));
	const paths: string[] = [];
	const server = createServer((request, response) => {
		paths.push(request.url!);
		response.writeHead(401, { 'Content-Type': 'application/json' });
		response.end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing fixture address.');
	const base = `http://127.0.0.1:${address.port}`;
	try {
		const config = await run(dir, [
			'config',
			'server',
			base,
			'--api',
			`${base}/custom-api`,
			'--identity',
			`${base}/custom-auth`,
			'--web-vault',
			`${base}/web`,
			'--icons',
			`${base}/icons`,
			'--notifications',
			`${base}/notifications`,
			'--events',
			`${base}/events`,
			'--key-connector',
			`${base}/key-connector`,
		]);
		expect(config.code).toBe(0);
		expect(config.stdout.trim()).toBe('Saved setting `config`.');
		await withStore(dir, async state => {
			expect(state.server).toBe(base);
			expect(state.services).toEqual({
				webVault: `${base}/web`,
				api: `${base}/custom-api`,
				identity: `${base}/custom-auth`,
				icons: `${base}/icons`,
				notifications: `${base}/notifications`,
				events: `${base}/events`,
				keyConnector: `${base}/key-connector`,
			});
		});
		const login = () => run(dir, ['login', 'fixture@example.com', 'synthetic-password', '--nointeraction']);
		expect((await login()).code).toBe(1);
		expect(paths).toEqual(['/custom-auth/accounts/prelogin']);
		const reset = await run(dir, ['config', 'server', base]);
		expect(reset.code).toBe(0);
		expect(reset.stdout.trim()).toBe('Saved setting `config`.');
		await withStore(dir, async state => expect(state.services).toEqual({}));
		expect((await login()).code).toBe(1);
		expect(paths.at(-1)).toBe('/identity/accounts/prelogin');
		expect((await run(dir, ['config', 'server', base, '--identity', 'https://user:secret@example.com'])).code).toBe(1);
	} finally {
		server.closeAllConnections();
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('generation and import format discovery follow bw login and output semantics in the built Node CLI', {
	timeout: 30000,
}, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-tools-'));
	const userKey = Buffer.alloc(64, 17);
	let session = '';
	try {
		const generated = await run(dir, ['generate', '--length', '32', '-u', '-l', '-n', '-s', '--minNumber', '4']);
		expect(generated.code).toBe(0);
		expect(generated.stdout.trim()).toHaveLength(32);
		expect(generated.stdout.trim().match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4);
		const clamped = await run(dir, ['generate', '--length', '-1']);
		expect(clamped.code).toBe(0);
		expect(clamped.stdout.trim()).toHaveLength(5);
		const fractional = await run(dir, ['generate', '--length', '5.9', '-n', '--minNumber', '2.9']);
		expect(fractional.code).toBe(0);
		expect(fractional.stdout.trim()).toHaveLength(5);
		expect(fractional.stdout.trim().match(/\d/g)!.length).toBeGreaterThanOrEqual(2);
		const malformed = await run(dir, ['generate', '--length', 'invalid']);
		expect(malformed.code).toBe(0);
		expect(malformed.stdout.trim()).toHaveLength(14);
		const long = await run(dir, ['generate', '--length', '4097']);
		expect(long.code).toBe(0);
		expect(long.stdout.trim()).toHaveLength(4097);
		const manyNumbers = await run(dir, ['generate', '--minNumber', '4097']);
		expect(manyNumbers.code).toBe(0);
		expect(manyNumbers.stdout.trim().match(/[0-9]/g)!.length).toBeGreaterThanOrEqual(4097);
		const manySpecials = await run(dir, ['generate', '-s', '--minSpecial', '4097']);
		expect(manySpecials.code).toBe(0);
		expect(manySpecials.stdout.trim().match(/[!@#$%^&*]/g)!).toHaveLength(4097);
		const phrase = await run(dir, ['generate', '-p', '--words', '5', '--separator', '/']);
		expect(phrase.code).toBe(0);
		expect(phrase.stdout.trim().split('/')).toHaveLength(5);
		const manyWords = await run(dir, ['generate', '-p', '--words', '129', '--separator', '/']);
		expect(manyWords.code).toBe(0);
		expect(manyWords.stdout.trim().split('/')).toHaveLength(129);
		const unauthenticatedFormats = await run(dir, ['import', '--formats']);
		expect(unauthenticatedFormats.code).toBe(1);
		expect(unauthenticatedFormats.stderr).toContain('You are not logged in.');
		await withStore(dir, async (state, save) => {
			state.server = 'https://vault.example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = { profile: { id: 'synthetic-user' }, ciphers: [], folders: [], collections: [] };
			session = sealSession(state, userKey);
			await save();
		});
		const formats = await run(dir, ['import', '--formats']);
		expect(formats.code).toBe(0);
		expect(formats.stdout).toStartWith('Supported input formats:\n');
		const supportedFormats = formats.stdout.slice('Supported input formats:\n'.length).trimEnd();
		const formatsResponse = await run(dir, ['--response', 'import', '--formats']);
		expect(JSON.parse(formatsResponse.stdout)).toEqual({
			success: true,
			data: {
				object: 'message',
				title: 'Supported input formats:',
				message: supportedFormats,
				raw: supportedFormats,
				noColor: false,
			},
		});
		const rawFormats = await run(dir, ['--raw', 'import', '--formats']);
		expect(rawFormats.stdout).toBe(`${supportedFormats}\n`);
		const unsupportedKeeperFile = join(dir, 'keeper-export.txt');
		await writeFile(unsupportedKeeperFile, '{"records":[]}');
		const unsupportedKeeper = await run(dir, ['import', 'keeper', unsupportedKeeperFile, '--session', session]);
		expect(unsupportedKeeper.code).toBe(1);
		expect(unsupportedKeeper.stderr).toContain(
			'Cannot determine Keeper file type. Use a .csv or .json file.',
		);
		expect(formats.stdout.split(/\r?\n/)).toContain('bitwardenjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('bitwardenzip');
		expect(formats.stdout.split(/\r?\n/)).toContain('nordpasscsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('passkeepcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordwallettxt');
		expect(formats.stdout.split(/\r?\n/)).toContain('passpackcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('ascendocsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('blackberrycsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('blurcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('codebookcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('avastcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('buttercupcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('padlockcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('yoticsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('saferpasscsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('securesafecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('meldiumcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('splashidcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('truekeycsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('remembearcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('upmcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('logmeoncecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('mykicsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('msecurecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordagentcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('dashlanecsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('delineacsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('kasperskytxt');
		expect(formats.stdout.split(/\r?\n/)).toContain('zohovaultcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('roboformcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('keepercsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('keeperjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('dashlanejson');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordxpcsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('delineaxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('netwrixpasswordsecure');
		expect(formats.stdout.split(/\r?\n/)).toContain('passwordbossjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('psonojson');
		expect(formats.stdout.split(/\r?\n/)).toContain('pwsafexml');
		expect(formats.stdout.split(/\r?\n/)).toContain('stickypasswordxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('clipperzhtml');
		expect(formats.stdout.split(/\r?\n/)).toContain('fsecurefsk');
		expect(formats.stdout.split(/\r?\n/)).toContain('keeper');
		expect(formats.stdout.split(/\r?\n/)).toContain('protonpass');
		expect(formats.stdout.split(/\r?\n/)).toContain('passworddepot17xml');
		expect(formats.stdout.split(/\r?\n/)).toContain('passworddragonxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('safeincloudxml');
		expect(formats.stdout.split(/\r?\n/)).toContain('avastjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('enpassjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('enpasscsv');
		expect(formats.stdout.split(/\r?\n/)).toContain('gnomejson');
		expect(formats.stdout.split(/\r?\n/)).toContain('passmanjson');
		expect(formats.stdout.split(/\r?\n/)).toContain('passkyjson');
	} finally {
		userKey.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('Send templates are available before login, and malformed recipient links do not request an account session', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-cli-'));
	try {
		const root = await run(dir, []);
		expect(root.code).toBe(0);
		expect(root.stdout).toContain('Vaultwarden-first');
		const unauthenticatedResponse = await run(dir, ['--response', 'list', 'items']);
		expect(unauthenticatedResponse.code).toBe(1);
		expect(JSON.parse(unauthenticatedResponse.stdout)).toEqual({
			success: false,
			message: 'You are not logged in.',
		});
		const text = await run(dir, ['send', 'template', 'text']);
		expect(text.code).toBe(0);
		expect(JSON.parse(text.stdout).type).toBe(0);
		const file = await run(dir, ['send', 'template', 'file']);
		expect(file.code).toBe(0);
		expect(JSON.parse(file.stdout).type).toBe(1);
		const editWithoutId = await run(dir, [
			'send',
			'edit',
			Buffer.from(JSON.stringify({ type: 0, name: 'Missing ID', text: { text: 'value' } })).toString('base64'),
		]);
		expect(editWithoutId.code).toBe(1);
		expect(editWithoutId.stderr).toContain('You are not logged in.');
		const invalid = await run(dir, ['receive', 'https://vault.example/#/send/bad/key']);
		expect(invalid.code).toBe(1);
		expect(invalid.stderr).toContain('fragment');
		expect(invalid.stderr).not.toContain('session');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('owned Send CLI results use bw response discriminators', { timeout: 15000 }, async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-send-response-'));
	const userKey = Buffer.alloc(64, 47), seed = Buffer.alloc(16, 48), sendKey = deriveSendKey(seed);
	const id = 'synthetic-send-id';
	try {
		const rawSend = {
			id,
			accessId: Buffer.alloc(16, 49).toString('base64url'),
			type: 0,
			key: encrypt(seed, userKey),
			name: encrypt(Buffer.from('Cached synthetic Send'), sendKey),
			notes: null,
			text: { text: encrypt(Buffer.from('Synthetic payload'), sendKey), hidden: false },
			deletionDate: new Date(Date.now() + 86400000).toISOString(),
			expirationDate: null,
			maxAccessCount: null,
			disabled: false,
			hideEmail: false,
		};
		const rawFileSend = {
			...rawSend,
			id: 'synthetic-file-send-id',
			accessId: Buffer.alloc(16, 51).toString('base64url'),
			type: 1,
			name: encrypt(Buffer.from('Unique synthetic file Send'), sendKey),
			file: { id: 'synthetic-file-id', fileName: encrypt(Buffer.from('synthetic.txt'), sendKey), size: 10 },
		};
		delete (rawFileSend as { text?: unknown }).text;
		let session = '';
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.test';
			state.account = {
				email: 'synthetic@example.test',
				kdf: { type: 0, iterations: 10000 },
				encryptedUserKey: 'synthetic-wrapped-key',
				accessToken: 'synthetic-access-token',
				refreshToken: 'synthetic-refresh-token',
				expiresAt: Date.now() + 3600000,
			};
			state.vault = {
				profile: { id: 'synthetic-user', organizations: [] },
				ciphers: [],
				sends: [rawSend, rawFileSend],
			};
			session = sealSession(state, userKey);
			await save();
		});
		const normal = await run(dir, ['send', 'get', id, '--session', session]);
		expect(normal.code).toBe(0);
		expect(JSON.parse(normal.stdout)).toMatchObject({
			object: 'send',
			id,
			name: 'Cached synthetic Send',
			text: { text: 'Synthetic payload', hidden: false },
		});
		const response = JSON.parse(
			(await run(dir, ['--response', 'send', 'get', id, '--session', session])).stdout,
		);
		expect(response).toMatchObject({
			success: true,
			data: { object: 'send', id, name: 'Cached synthetic Send' },
		});
		const responseText = await run(dir, [
			'--response',
			'send',
			'get',
			id,
			'--text',
			'--session',
			session,
		]);
		expect(JSON.parse(responseText.stdout)).toEqual({
			success: true,
			data: { object: 'string', data: 'Synthetic payload' },
		});
		const textFromFile = await run(dir, ['send', 'get', 'synthetic-file-send-id', '--text', '--session', session]);
		expect(textFromFile.code).toBe(1);
		expect(textFromFile.stderr).toContain('Not found.');
		const listed = JSON.parse((await run(dir, ['--response', 'send', 'list', '--session', session])).stdout);
		expect(listed).toMatchObject({
			success: true,
			data: {
				object: 'list',
				data: [
					{ object: 'send', id, name: 'Cached synthetic Send' },
					{ object: 'send', id: 'synthetic-file-send-id', name: 'Unique synthetic file Send' },
				],
			},
		});
		const duplicateSend = {
			...rawSend,
			id: 'synthetic-send-id-2',
			accessId: Buffer.alloc(16, 50).toString('base64url'),
		};
		await withStore(dir, async (state, save) => {
			state.vault!.sends = [rawSend, rawFileSend, duplicateSend];
			await save();
		});
		const ambiguous = await run(dir, ['--response', 'send', 'get', 'Cached', '--session', session]);
		expect(ambiguous.code).toBe(1);
		expect(JSON.parse(ambiguous.stdout)).toEqual({
			success: false,
			message: 'More than one result was found. Try getting a specific object by `id` instead. '
				+ 'The following objects were found:\nsynthetic-send-id\nsynthetic-send-id-2',
			data: ['synthetic-send-id', 'synthetic-send-id-2'],
		});
	} finally {
		userKey.fill(0);
		seed.fill(0);
		sendKey.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
});

test('anonymous text Send receive uses the response envelope for text output', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-receive-response-'));
	const seed = Buffer.alloc(16, 61);
	const accessId = Buffer.alloc(16, 62).toString('base64url');
	const key = deriveSendKey(seed);
	const server = createServer((request, response) => {
		response.setHeader('Content-Type', 'application/json');
		if (request.url === '/identity/connect/token') {
			response.end(JSON.stringify({ access_token: 'synthetic-send-token' }));
		} else if (request.url === '/api/sends/access') {
			response.end(JSON.stringify({
				id: 'synthetic-received-send',
				accessId,
				type: 0,
				name: encrypt(Buffer.from('Synthetic received Send'), key),
				text: { text: encrypt(Buffer.from('Anonymous payload'), key), hidden: false },
				emails: null,
				deletionDate: new Date(Date.now() + 86400000).toISOString(),
				disabled: false,
				hideEmail: false,
			}));
		} else response.writeHead(404).end('{}');
	});
	await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
	const address = server.address();
	if (!address || typeof address === 'string') throw new Error('Missing Send fixture address.');
	try {
		const url = `http://127.0.0.1:${address.port}/#/send/${accessId}/${seed.toString('base64url')}`;
		const result = await run(dir, ['--response', 'receive', url]);
		expect(result.code, result.stderr).toBe(0);
		expect(JSON.parse(result.stdout)).toEqual({
			success: true,
			data: { object: 'string', data: 'Anonymous payload' },
		});
	} finally {
		seed.fill(0);
		key.fill(0);
		await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
		await rm(dir, { recursive: true, force: true });
	}
});

test('authentication checks ignore unused password files and do not prompt', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-auth-check-'));
	try {
		const login = await run(dir, [
			'login',
			'--check',
			'--nointeraction',
			'--passwordfile',
			join(dir, 'missing-secret.txt'),
		]);
		expect(login.code).toBe(1);
		expect(login.stderr).toContain('You are not logged in.');
		const unlock = await run(dir, [
			'unlock',
			'--check',
			'--nointeraction',
			'--passwordfile',
			join(dir, 'missing-secret.txt'),
		]);
		expect(unlock.code).toBe(1);
		expect(unlock.stderr).toContain('You are not logged in.');
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

for (const shell of ['zsh', 'bash', 'fish', 'powershell']) {
	// A cold PowerShell/.NET start can exceed Bun's default five-second test budget on CI.
	const shellTest = shell === 'fish' && !Bun.which(shell) ? test.skip : test;
	shellTest(
		`schema-derived ${shell} completion parses`,
		{ timeout: shell === 'powershell' ? 30000 : 5000 },
		async () => {
			const dir = await mkdtemp(join(tmpdir(), `vw-completion-${shell}-`));
			try {
				const generated = await run(dir, ['completions', shell]);
				expect(generated.code).toBe(0);
				expect(generated.stdout).toContain('login');
				expect(generated.stdout).toContain('send');
				expect(generated.stdout).toContain('passwordfile');
				const path = join(dir, shell === 'powershell' ? 'completion.ps1' : `completion.${shell}`);
				await writeFile(path, generated.stdout);
				let args = [shell, '-n', path];
				if (shell === 'powershell') {
					const parser = join(dir, 'check.ps1');
					await writeFile(
						parser,
						'param([string]$Path)\n$tokens=$null; $errors=$null\n[System.Management.Automation.Language.Parser]::ParseFile($Path,[ref]$tokens,[ref]$errors) | Out-Null\nif ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }',
					);
					args = ['pwsh', '-NoProfile', '-NonInteractive', '-File', parser, '-Path', path];
				}
				const child = Bun.spawn(args, {
					stdout: 'ignore',
					stderr: 'pipe',
					timeout: shell === 'powershell' ? 20000 : undefined,
					killSignal: 'SIGKILL',
				});
				const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
				if (child.signalCode) throw new Error(`${shell} completion parser terminated with ${child.signalCode}.`);
				if (code) throw new Error(`${shell} completion syntax failed: ${stderr}`);
				if (shell === 'fish') {
					const complete = Bun.spawn(['fish', '--no-config', '-c', 'source $argv[1]; complete -C "vw lo"', path], {
						stdout: 'pipe',
						stderr: 'pipe',
					});
					const [code, output, stderr] = await Promise.all([
						complete.exited,
						new Response(complete.stdout).text(),
						new Response(complete.stderr).text(),
					]);
					if (code) throw new Error(`fish completion failed: ${stderr}`);
					expect(output).toContain('login');
					expect(output).toContain('logout');
				}
			} finally {
				await rm(dir, { recursive: true, force: true });
			}
		},
	);
}

test('completions rejects missing and unsupported shells', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-completion-invalid-'));
	try {
		expect((await run(dir, ['completions'])).code).not.toBe(0);
		expect((await run(dir, ['completions', 'unknown'])).code).not.toBe(0);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
