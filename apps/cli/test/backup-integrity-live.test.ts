import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
	createAccountKeyMaterial,
	encrypt,
	encryptSharedKey,
	VaultService,
	VaultwardenClient,
	type JsonObject,
} from '@kjanat/vaultwarden';
import { sealSession, withStore } from '#store';

const server = process.env.VW_TEST_SERVER;
const live = server ? test : test.skip;

live('real Vaultwarden: backup integrity through CLI export and import', async () => {
	const url = new URL(server!);
	if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
		throw new Error('A disposable loopback server is required.');
	}
	const email = `backup-${randomUUID()}@example.test`, password = 'Synthetic-Backup-Password-2026!';
	const kdf = { type: 0, iterations: 600000 } as const;
	const material = await createAccountKeyMaterial(password, email, kdf);
	const directory = await mkdtemp(join(tmpdir(), 'vw-backup-integrity-'));
	let vault: VaultService | undefined;
	const organizationKey = randomBytes(64);
	try {
		const verification = await fetch(`${server}/identity/accounts/register/send-verification-email`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email, name: 'Backup fixture' }),
		});
		let verificationToken: unknown;
		if (verification.ok) {
			const body = await verification.text();
			try {
				verificationToken = JSON.parse(body);
			} catch {
				verificationToken = body;
			}
		}
		const registered = await fetch(`${server}/identity/accounts/register${verification.ok ? '/finish' : ''}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				email,
				name: 'Backup fixture',
				masterPasswordHash: material.masterPasswordHash,
				key: material.encryptedUserKey,
				kdf: 0,
				kdfIterations: kdf.iterations,
				emailVerificationToken: verificationToken,
				keys: { publicKey: material.publicKey, encryptedPrivateKey: material.encryptedPrivateKey },
			}),
		});
		expect(registered.status).toBe(200);
		const client = new VaultwardenClient(server!);
		const auth = await client.login(email, material.masterPasswordHash);
		const organization = await client.api(auth.accessToken, 'POST', '/organizations', {
			name: 'Backup organization',
			billingEmail: email,
			planType: 0,
			collectionName: encrypt(Buffer.from('Collection'), organizationKey),
			key: await encryptSharedKey(organizationKey, material.publicKey),
		});
		const refresh = async () => {
			vault?.dispose();
			vault = new VaultService(client, auth.accessToken, await client.sync(auth.accessToken), material.userKey);
			return vault;
		};
		await refresh();
		const initial = await vault!.importVault(
			'bitwardenjson',
			JSON.stringify({
				collections: [],
				items: [
					{ type: 1, name: 'Organization one', login: { password: 'synthetic-one' } },
					{ type: 1, name: 'Organization two', login: { password: 'synthetic-two' } },
				],
			}),
			{ organizationId: String(organization.id) },
		);
		expect(initial.items).toBe(2);
		await refresh();
		expect(await vault!.listItems({ organizationId: String(organization.id) })).toHaveLength(2);
		const item = await vault!.createItem({
			type: 1,
			name: 'Attachment collision backup',
			login: { password: 'synthetic' },
		});
		await refresh();
		await vault!.createAttachment(String(item.id), 'file.txt', Buffer.from('FIRST-BODY'));
		await refresh();
		const original = await vault!.getItem(String(item.id));
		const firstAttachment = (original.attachments as JsonObject[])[0]!;
		for (
			const [name, contents] of [
				[String(firstAttachment.id), 'SECOND-BODY'],
				['file.txt', 'THIRD-BODY'],
				['file_1.txt', 'FOURTH-BODY'],
			]
		) {
			await vault!.createAttachment(String(item.id), name!, Buffer.from(contents!));
			await refresh();
		}
		let session = '';
		await withStore(directory, async (state, save) => {
			state.server = server;
			state.account = { ...auth, email, kdf };
			state.vault = vault!.snapshot;
			session = sealSession(state, material.userKey);
			await save();
		});
		const run = async (args: string[]) => {
			const child = Bun.spawn(['node', fileURLToPath(import.meta.resolve('#main')), ...args], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: directory, VW_SESSION: session },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 10000,
				killSignal: 'SIGKILL',
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			return { code, stdout, stderr };
		};
		const malformed = join(directory, 'malformed.json');
		await writeFile(
			malformed,
			JSON.stringify({
				collections: [],
				items: [
					{ type: 1, name: 'Must not be partially imported', login: {} },
					{ type: 1, name: 'Missing login section' },
				],
			}),
			{ mode: 0o600 },
		);
		const rejected = await run(['import', 'bitwardenjson', malformed, '--organizationid', String(organization.id)]);
		expect(rejected.code).toBe(1);
		expect(rejected.stderr).toContain('missing its login data');
		await refresh();
		expect(await vault!.listItems({ organizationId: String(organization.id) })).toHaveLength(2);
		const archive = join(directory, 'backup.zip');
		const exported = await run(['export', '--format', 'zip', '--output', archive]);
		expect(exported.code).toBe(0);
		expect(exported.stderr).toBe('');
		const imported = await run(['import', 'bitwardenzip', archive]);
		expect(imported.code).toBe(0);
		expect(imported.stderr).toBe('');
		expect(JSON.parse(imported.stdout)).toMatchObject({ items: 1, attachments: 4 });
		await refresh();
		const restored = (await vault!.listItems()).filter(value => value.id !== item.id && !value.organizationId);
		expect(restored).toHaveLength(1);
		const files = restored[0]!.attachments as JsonObject[];
		expect(files).toHaveLength(4);
		const contents: string[] = [];
		for (const file of files) {
			const downloaded = await vault!.getAttachment(String(restored[0]!.id), String(file.id));
			try {
				contents.push(downloaded.contents.toString());
			} finally {
				downloaded.contents.fill(0);
			}
		}
		expect(contents.sort()).toEqual(['FIRST-BODY', 'FOURTH-BODY', 'SECOND-BODY', 'THIRD-BODY']);

		// Fault injection after client validation reproduces Vaultwarden's HTTP-200
		// partial import and checks the CLI's uncertain-mutation handling.
		let fault = 'missing-item';
		const proxy = Bun.serve({
			hostname: '127.0.0.1',
			port: 0,
			async fetch(request) {
				const target = new URL(request.url);
				if (fault === 'attachment' && target.pathname.startsWith('/attachments/')) {
					return new Response('Synthetic download failure', { status: 503 });
				}
				let body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.text();
				if (target.pathname === '/api/ciphers/import-organization' && request.method === 'POST') {
					const data = JSON.parse(body!);
					if (fault === 'missing-item') {
						data.ciphers[1].login = null;
						data.collectionRelationships = [];
					}
					if (fault === 'missing-password') delete data.ciphers[1].login.password;
					if (fault === 'assignment') data.collectionRelationships = [];
					body = JSON.stringify(data);
				}
				const response = await fetch(`${server}${target.pathname}${target.search}`, {
					method: request.method,
					headers: request.headers,
					body,
				});
				if (
					fault === 'attachment' && request.method === 'GET' && /\/attachment\/[^/]+$/.test(target.pathname)
					&& response.ok
				) {
					const metadata = await response.json() as JsonObject;
					const download = new URL(String(metadata.url));
					metadata.url = `${target.origin}${download.pathname}${download.search}`;
					return Response.json(metadata);
				}
				return response;
			},
		});
		try {
			const seed = () =>
				withStore(directory, async (state, save) => {
					state.server = `http://127.0.0.1:${proxy.port}`;
					state.vault = vault!.snapshot;
					state.lastSync = new Date().toISOString();
					await save();
				});
			const valid = join(directory, 'partial.json');
			const collection = (vault!.snapshot.collections as JsonObject[]).find(value =>
				value.organizationId === organization.id
			)!;
			await writeFile(
				valid,
				JSON.stringify({
					collections: [{ id: collection.id, name: 'Collection' }],
					items: [
						{ type: 1, name: 'Accepted partial record', collectionIds: [collection.id], login: { password: 'one' } },
						{ type: 1, name: 'Dropped partial record', collectionIds: [collection.id], login: { password: 'two' } },
					],
				}),
				{ mode: 0o600 },
			);
			let count = 2;
			for (const mode of ['missing-item', 'missing-password', 'assignment']) {
				fault = mode;
				await seed();
				const partial = await run(['import', 'bitwardenjson', valid, '--organizationid', String(organization.id)]);
				expect(partial.code).toBe(1);
				expect(partial.stderr).toContain('Import verification failed');
				await withStore(directory, async state => {
					expect(state.vault).toBeUndefined();
					expect(state.lastSync).toBeUndefined();
				});
				await refresh();
				count += mode === 'missing-item' ? 1 : 2;
				expect(await vault!.listItems({ organizationId: String(organization.id) })).toHaveLength(count);
			}
			fault = 'attachment';
			await seed();
			const missingBackup = join(directory, 'must-not-exist.zip');
			const incomplete = await run(['export', '--format', 'zip', '--output', missingBackup]);
			expect(incomplete.code).toBe(1);
			expect(incomplete.stderr).toContain('ZIP export is incomplete');
			expect(await stat(missingBackup).catch(() => undefined)).toBeUndefined();
			const partialBackup = join(directory, 'explicitly-partial.zip');
			const allowed = await run(['export', '--format', 'zip', '--allow-partial', '--output', partialBackup]);
			expect(allowed.code).toBe(0);
			expect(allowed.stderr).toContain('Skipped attachment');
			expect((await stat(partialBackup)).size).toBeGreaterThan(0);
		} finally {
			proxy.stop(true);
		}
		await withStore(directory, async (state, save) => {
			state.server = server;
			state.vault = vault!.snapshot;
			await save();
		});
		const csv = join(directory, 'card.csv');
		await writeFile(csv, 'Title,Type,Verification Number,Number\nBlank PAN,Credit Card,123,\n', { mode: 0o600 });
		expect((await run(['import', '1passwordmaccsv', csv])).code).toBe(0);
		await refresh();
		const card = (await vault!.listItems()).find(value => value.name === 'Blank PAN')!;
		expect(card.type).toBe(3);
		expect((card.card as JsonObject).code).toBe('123');
		expect((card.card as JsonObject).number).toBeUndefined();
		const unusual = await vault!.createAttachment(String(item.id), '.', Buffer.from('EXPLICIT-NAME-BODY'));
		const unusualFile = (unusual.attachments as JsonObject[]).find(value => value.fileName === '.')!;
		expect((await run(['sync'])).code).toBe(0);
		const safeOutput = join(directory, 'safe-name.bin');
		const saved = await run([
			'get',
			'attachment',
			String(unusualFile.id),
			'--itemid',
			String(item.id),
			'--output',
			safeOutput,
		]);
		expect(saved).toMatchObject({ code: 0, stderr: '' });
		expect(await readFile(safeOutput, 'utf8')).toBe('EXPLICIT-NAME-BODY');
	} finally {
		vault?.dispose();
		material.userKey.fill(0);
		organizationKey.fill(0);
		await rm(directory, { recursive: true, force: true });
	}
}, 30000);
