import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import {
	generateKeyPairSync,
	createHash,
	randomBytes,
	randomUUID,
	createPublicKey,
	publicEncrypt,
	constants,
} from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unzipSync } from 'fflate';
import { withStore } from '#store';
import {
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	encryptAttachment,
	encryptItem,
	decryptSharedKey,
	type Kdf,
} from '@kjanat/vaultwarden';
import { writeTestCertificate } from '#test/fixtures/tls';
import { registrationVerificationToken } from '#test/fixtures/registration';

// Explicit opt-in. Only disposable loopback instances may be mutated by this test.
const server = process.env.VW_TEST_SERVER;
// A focused importer comparison runs its own end-to-end login and server flow;
// do not repeat the unrelated expensive KDF fixtures in that mode.
const live = server && !process.env.VW_TEST_IMPORT_FORMAT ? test : test.skip;
for (
	const kdf of [
		{ type: 0, iterations: 600000 },
		{ type: 1, iterations: 3, memory: 64, parallelism: 2 },
	] as Kdf[]
) {
	live(
		`real Vaultwarden: ${kdf.type === 0 ? 'PBKDF2' : 'Argon2id'} protocol and CLI compatibility`,
		async () => {
			const url = new URL(server!);
			if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1') {
				throw new Error(
					'Live tests require a disposable HTTP loopback server.',
				);
			}
			const serverVersionResponse = await fetch(`${server}/api/version`);
			expect(serverVersionResponse.status).toBe(200);
			const serverVersion = await serverVersionResponse.json() as string;
			expect(serverVersion).toMatch(/^\d+\.\d+\.\d+$/);
			if (process.env.VW_TEST_VERSION) expect(serverVersion).toBe(process.env.VW_TEST_VERSION);
			const email = `fixture-${randomUUID()}@example.com`;
			const password = 'Synthetic-fixture-password-123!';
			const userKey = randomBytes(64);
			const itemKey = randomBytes(64);
			const master = await deriveMasterKey(password, email, kdf);
			const stretched = stretchKey(master);
			const hash = await masterPasswordHash(master, password);
			const wrapped = encrypt(userKey, stretched);
			const rsa = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			master.fill(0);
			stretched.fill(0);
			async function post(path: string, data: unknown, token?: string) {
				return fetch(`${server}${path}`, {
					method: 'POST',
					headers: {
						'Content-Type': 'application/json',
						Accept: 'application/json',
						...(token ? { Authorization: `Bearer ${token}` } : {}),
					},
					body: JSON.stringify(data),
				});
			}
			const verify = await post(
				'/identity/accounts/register/send-verification-email',
				{
					email,
					name: 'Compatibility fixture',
				},
			);
			const verificationToken = verify.ok ? await registrationVerificationToken(verify) : undefined;
			const registration = {
				keys: {
					publicKey: rsa.publicKey.toString('base64'),
					encryptedPrivateKey: encrypt(rsa.privateKey, userKey),
				},
				email,
				name: 'Compatibility fixture',
				masterPasswordHash: hash,
				key: wrapped,
				kdf: kdf.type,
				kdfIterations: kdf.iterations,
				kdfMemory: kdf.type === 1 ? kdf.memory : null,
				kdfParallelism: kdf.type === 1 ? kdf.parallelism : null,
				emailVerificationToken: verificationToken,
			};
			const registered = await post(
				verify.ok
					? '/identity/accounts/register/finish'
					: '/identity/accounts/register',
				registration,
			);
			expect(registered.status).toBe(200);
			const tokenResponse = await fetch(`${server}/identity/connect/token`, {
				method: 'POST',
				body: new URLSearchParams({
					grant_type: 'password',
					client_id: 'cli',
					scope: 'api offline_access',
					username: email,
					password: hash,
					deviceIdentifier: randomUUID(),
					deviceName: 'Fixture',
					deviceType: '8',
				}),
			});
			expect(tokenResponse.status).toBe(200);
			const auth = (await tokenResponse.json()) as { access_token: string };
			expect(
				(await post('/api/settings/domains', {
					equivalentDomains: [['example.com', 'alias.test']],
					excludedGlobalEquivalentDomains: [],
				}, auth.access_token)).status,
			).toBe(200);
			const enc = (s: string) => encrypt(Buffer.from(s), itemKey);
			const orgKey = randomBytes(64);
			const organizationResponse = await post('/api/organizations', {
				name: 'Compatibility organization',
				billingEmail: email,
				planType: 0,
				collectionName: encrypt(Buffer.from('Organization collection'), orgKey),
				key: `3.${
					publicEncrypt({
						key: createPublicKey({ key: rsa.publicKey, format: 'der', type: 'spki' }),
						padding: constants.RSA_PKCS1_OAEP_PADDING,
						oaepHash: 'sha256',
					}, orgKey).toString('base64')
				}`,
			}, auth.access_token);
			expect(organizationResponse.status).toBe(200);
			const organization = await organizationResponse.json() as { id: string };
			// The reference device-approval command uses organization routes, not personal auth requests.
			const organizationApprovals = await fetch(`${server}/api/organizations/${organization.id}/auth-requests`, {
				headers: { Authorization: `Bearer ${auth.access_token}` },
			});
			expect(organizationApprovals.status).toBe(404);
			const personalApprovals = await fetch(`${server}/api/auth-requests`, {
				headers: { Authorization: `Bearer ${auth.access_token}` },
			});
			expect(personalApprovals.status).toBe(200);
			expect((await personalApprovals.json()).data).toEqual([]);
			const profileResponse = await fetch(`${server}/api/accounts/profile`, {
				headers: { Authorization: `Bearer ${auth.access_token}` },
			});
			const profile = (await profileResponse.json()) as {
				id: string;
				organizations: { id: string; organizationUserId: string }[];
			};
			const created = await post(
				'/api/ciphers',
				{
					encryptedFor: profile.id,
					type: 1,
					organizationId: null,
					folderId: null,
					name: enc('Compatibility fixture'),
					notes: enc('fixture notes'),
					key: encrypt(itemKey, userKey),
					favorite: false,
					reprompt: 0,
					login: {
						username: enc('fixture-user'),
						password: enc('fixture-secret'),
						uris: [{
							uri: enc('https://example.com'),
							uriChecksum: enc(createHash('sha256').update('https://example.com').digest('base64')),
							match: null,
						}],
					},
					fields: [],
				},
				auth.access_token,
			);
			expect(created.status).toBe(200);
			const item = (await created.json()) as { id: string };
			const dir = await mkdtemp(join(tmpdir(), 'vw-live-'));
			const ca = join(dir, 'ca.pem');
			const keyPath = join(dir, 'key.pem');
			await writeTestCertificate(ca, keyPath);
			const certificate = await readFile(ca);
			const privateKey = await readFile(keyPath);
			const proxy = createHttpsServer({ cert: certificate, key: privateKey }, (incoming, outgoing) => {
				const path = incoming.url ?? '/';
				if (!path.startsWith('/') || path.startsWith('//') || path.startsWith('/\\')) {
					outgoing.writeHead(400);
					outgoing.end();
					return;
				}
				const requestHeaders = { ...incoming.headers };
				const requestConnectionHeaders = requestHeaders.connection
					?.split(',')
					.map(value => value.trim().toLowerCase()) ?? [];
				for (
					const name of [
						'connection',
						'keep-alive',
						'proxy-authenticate',
						'proxy-authorization',
						'te',
						'trailer',
						'transfer-encoding',
						'upgrade',
						'host',
						...requestConnectionHeaders,
					]
				) delete requestHeaders[name];
				if (incoming.headers.host) requestHeaders.host = incoming.headers.host;
				requestHeaders['x-forwarded-proto'] = 'https';
				const upstream = httpRequest(url, {
					path,
					method: incoming.method,
					headers: requestHeaders,
				}, response => {
					const responseHeaders = { ...response.headers };
					const responseConnectionHeaders = responseHeaders.connection
						?.split(',')
						.map(value => value.trim().toLowerCase()) ?? [];
					for (
						const name of [
							'connection',
							'keep-alive',
							'proxy-authenticate',
							'proxy-authorization',
							'te',
							'trailer',
							'transfer-encoding',
							'upgrade',
							...responseConnectionHeaders,
						]
					) delete responseHeaders[name];
					outgoing.writeHead(response.statusCode ?? 502, responseHeaders);
					response.pipe(outgoing);
				});
				upstream.on('error', () => {
					if (!outgoing.headersSent) outgoing.writeHead(502);
					outgoing.end();
				});
				incoming.on('aborted', () => upstream.destroy());
				incoming.pipe(upstream);
			});
			await new Promise<void>((resolve, reject) => {
				proxy.once('error', reject);
				proxy.listen(0, '127.0.0.1', resolve);
			});
			const proxyAddress = proxy.address();
			if (proxyAddress === null || typeof proxyAddress === 'string') {
				throw new Error('Could not determine the TLS compatibility-proxy port.');
			}
			const tlsServer = `https://127.0.0.1:${proxyAddress.port}`;
			async function closeProxy(): Promise<void> {
				if (!proxy.listening) return;
				proxy.closeAllConnections();
				await new Promise<void>((resolve, reject) => {
					proxy.close(error => error ? reject(error) : resolve());
				});
			}
			async function run(
				args: string[],
				session?: string,
				secret = password,
				input?: string,
				apiOptions?: { directory: string; clientId: string; clientSecret: string },
				appDataDir = apiOptions?.directory ?? dir,
			) {
				const child = Bun.spawn(
					[
						'node',
						fileURLToPath(import.meta.resolve('#main')),
						...args,
					],
					{
						env: {
							PATH: process.env.PATH,
							VW_APPDATA_DIR: appDataDir,
							NODE_EXTRA_CA_CERTS: ca,
							VW_PASSWORD: secret,
							...(apiOptions ? { VW_CLIENTID: apiOptions.clientId, VW_CLIENTSECRET: apiOptions.clientSecret } : {}),
							...(session ? { VW_SESSION: session } : {}),
						},
						stdin: 'pipe',
						stdout: 'pipe',
						stderr: 'pipe',
					},
				);
				if (input) child.stdin.write(input);
				child.stdin.end();
				const [code, stdout, stderr] = await Promise.all([
					child.exited,
					new Response(child.stdout).text(),
					new Response(child.stderr).text(),
				]);
				return { code, stdout, stderr };
			}
			try {
				expect((await run(['config', 'server', tlsServer])).code).toBe(0);
				const firstLogin = await run(['login', email, '--raw']);
				if (firstLogin.code) throw new Error(`Initial login failed: ${firstLogin.stderr}`);
				expect(firstLogin.stdout.trim()).toMatch(/^[A-Za-z0-9+/]{43}=$/);
				expect((await run(['get', 'password', item.id], firstLogin.stdout.trim())).stdout).toBe('fixture-secret');
				expect(await run(['get', 'password', item.id, '--quiet'], firstLogin.stdout.trim())).toEqual({
					code: 0,
					stdout: '',
					stderr: '',
				});
				expect((await run(['login', '--check'])).code).toBe(0);
				expect((await run(['unlock', '--check'], firstLogin.stdout.trim())).code).toBe(0);

				expect((await run(['sync', '--force'])).code).toBe(0);
				const lastSync = await run(['sync', '--last']);
				expect(lastSync.code).toBe(0);
				expect(lastSync.stdout.trim()).toBe(JSON.parse((await run(['status'])).stdout).lastSync);
				await withStore(dir, async (state, save) => {
					state.account!.expiresAt = 0;
					await save();
				});
				expect((await run(['sync'])).code).toBe(0);
				await withStore(dir, async (state, save) => {
					state.account!.accessToken = 'expired-fixture-token';
					await save();
				});
				expect((await run(['sync'])).code).toBe(0);
				expect(
					(await run(['unlock', '--raw'], undefined, 'incorrect-password'))
						.code,
				).toBe(1);
				const unlocked = await run(['unlock', '--raw']);
				expect(unlocked.code).toBe(0);
				const session = unlocked.stdout.trim();
				expect(session).toMatch(/^[A-Za-z0-9+/]{43}=$/);
				expect(JSON.parse((await run(['status'], session)).stdout).status).toBe(
					'unlocked',
				);
				const list = await run(['list', 'items'], session);
				expect(list.code).toBe(0);
				expect(JSON.parse(list.stdout)[0].name).toBe('Compatibility fixture');
				expect((await run(['get', 'password', item.id], session)).stdout).toBe(
					'fixture-secret',
				);
				const encode = (data: unknown) => Buffer.from(JSON.stringify(data)).toString('base64');
				const checked = async (args: string[], input?: string) => {
					const result = await run(args, session, password, input);
					if (result.code !== 0) throw new Error(`CLI operation failed (exit ${result.code}): ${result.stderr}`);
					return result.stdout;
				};
				expect((await checked(['encode'], JSON.stringify({ name: 'Encoded' }))).trim()).toBe(
					encode({ name: 'Encoded' }),
				);
				const folder = JSON.parse(await checked(['create', 'folder'], encode({ name: 'Private folder' })));
				expect(folder.name).toBe('Private folder');
				expect(JSON.parse(await checked(['list', 'organizations']))[0].name).toBe('Compatibility organization');
				const collections = JSON.parse(await checked(['list', 'collections']));
				expect(collections[0].name).toBe('Organization collection');
				expect(JSON.parse(await checked(['get', 'folder', 'PRIVATE FOL'])).id).toBe(folder.id);
				expect(JSON.parse(await checked(['get', 'collection', 'GANIZATION COL'])).id).toBe(collections[0].id);
				expect(JSON.parse(await checked(['get', 'organization', 'PATIBILITY ORG'])).id).toBe(organization.id);
				const sharedItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({
							type: 1,
							name: 'Shared by vw',
							organizationId: organization.id,
							collectionIds: [collections[0].id],
							login: { username: 'organization-user', password: 'organization-secret' },
						}),
					]),
				);
				expect((await checked(['get', 'password', sharedItem.id])).trim()).toBe('organization-secret');
				const collection = JSON.parse(
					await checked([
						'create',
						'org-collection',
						encode({ name: 'Managed collection' }),
						'--organizationid',
						organization.id,
					]),
				);
				expect(collection.name).toBe('Managed collection');
				const organizationProfile = profile.organizations.find(value => value.id === organization.id);
				expect(organizationProfile?.organizationUserId).toBeTruthy();
				const collectionDetails = await fetch(
					`${server}/api/organizations/${organization.id}/collections/details`,
					{ headers: { Authorization: `Bearer ${auth.access_token}` } },
				);
				expect(collectionDetails.status).toBe(200);
				const detail = ((await collectionDetails.json()).data as Record<string, unknown>[]).find(
					value => value.id === collection.id,
				);
				expect(detail?.users).toContainEqual({
					id: organizationProfile!.organizationUserId,
					readOnly: false,
					hidePasswords: false,
					manage: true,
				});
				expect(
					JSON.parse(await checked(['get', 'org-collection', collection.id, '--organizationid', organization.id])).name,
				).toBe('Managed collection');
				expect(
					JSON.parse(await checked(['list', 'org-collections', '--organizationid', organization.id])).some((
						c: { id: string },
					) => c.id === collection.id),
				).toBe(true);
				const movable = JSON.parse(
					await checked([
						'create',
						'item',
						encode({ type: 1, name: 'Move fixture', login: { password: 'moved-secret' } }),
					]),
				);
				const attachmentBytes = Buffer.alloc(2 * 1024 * 1024, Buffer.from([0, 1, 2, 255, 128, 10, 13, 0, 42]));
				const uploadPath = join(dir, 'fixture.bin');
				await writeFile(uploadPath, attachmentBytes, { mode: 0o600 });
				const upload = JSON.parse(
					await checked(['create', 'attachment', '--file', uploadPath, '--itemid', movable.id]),
				);
				const attachmentId = upload.attachments[0].id;
				expect(upload.attachments[0].fileName).toBe('fixture.bin');
				const downloadPath = join(dir, 'download.bin');
				await checked(['get', 'attachment', attachmentId, '--itemid', movable.id, '--output', downloadPath, '--quiet']);
				const beforeMove = await readFile(downloadPath);
				expect(beforeMove.equals(attachmentBytes)).toBe(true);
				expect((await stat(downloadPath)).mode & 0o777).toBe(0o600);
				const collisionBytes = Buffer.from('filename collision must not replace the ID-selected attachment');
				const collisionPath = join(dir, attachmentId);
				await writeFile(collisionPath, collisionBytes, { mode: 0o600 });
				const collision = JSON.parse(
					await checked(['create', 'attachment', '--file', collisionPath, '--itemid', movable.id]),
				);
				expect(collision.attachments).toContainEqual(expect.objectContaining({ fileName: attachmentId }));
				const collisionId = collision.attachments.find((value: { fileName: string }) => value.fileName === attachmentId)
					?.id;
				expect(collisionId).toBeTruthy();
				expect(collisionId).not.toBe(attachmentId);
				const collisionDownloadPath = join(dir, 'attachment-id-collision.bin');
				await checked([
					'get',
					'attachment',
					attachmentId,
					'--itemid',
					movable.id,
					'--output',
					collisionDownloadPath,
				]);
				expect((await readFile(collisionDownloadPath)).equals(attachmentBytes)).toBe(true);
				const replacementItemKey = randomBytes(64);
				try {
					const itemForRotation = JSON.parse(await checked(['get', 'item', movable.id]));
					const rekeyed = JSON.parse(
						await checked([
							'edit',
							'item',
							movable.id,
							encode({ ...itemForRotation, key: replacementItemKey.toString('base64') }),
						]),
					);
					expect(rekeyed.key).toBeUndefined();
					const rekeyedDownload = join(dir, 'rekeyed.bin');
					await checked([
						'get',
						'attachment',
						attachmentId,
						'--itemid',
						movable.id,
						'--output',
						rekeyedDownload,
					]);
					expect((await readFile(rekeyedDownload)).equals(attachmentBytes)).toBe(true);
				} finally {
					replacementItemKey.fill(0);
				}
				const moved = JSON.parse(await checked(['move', movable.id, organization.id, encode([collection.id])]));
				expect(moved.organizationId).toBe(organization.id);
				expect(moved.login.password).toBe('moved-secret');
				const movedDownload = join(dir, 'moved.bin');
				await checked(['get', 'attachment', 'FIXTURE', '--itemid', 'MOVE FIXTURE', '--output', movedDownload]);
				expect((await readFile(movedDownload)).equals(attachmentBytes)).toBe(true);
				const legacyItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({
							type: 1,
							name: 'Legacy attachment move',
							login: { username: 'legacy-user', password: 'legacy-move-secret' },
						}),
					]),
				);
				const beforeLegacyUpdate = await fetch(`${server}/api/sync?excludeDomains=false`, {
					headers: { Authorization: `Bearer ${auth.access_token}` },
				});
				expect(beforeLegacyUpdate.status).toBe(200);
				const beforeLegacyCiphers = (await beforeLegacyUpdate.json()).ciphers as Record<string, unknown>[];
				const currentLegacyCipher = beforeLegacyCiphers.find(cipher => cipher.id === legacyItem.id);
				if (!currentLegacyCipher) throw new Error('Could not read the legacy attachment fixture cipher.');
				const legacyPlain = {
					type: 1,
					name: 'Legacy attachment move',
					login: { username: 'legacy-user', password: 'legacy-move-secret' },
				};
				const legacyUpdate = await fetch(`${server}/api/ciphers/${legacyItem.id}`, {
					method: 'PUT',
					headers: {
						Authorization: `Bearer ${auth.access_token}`,
						'Content-Type': 'application/json',
					},
					body: JSON.stringify({
						...currentLegacyCipher,
						...encryptItem(legacyPlain, userKey),
						encryptedFor: profile.id,
						encryptedByKeyId: null,
						key: null,
						lastKnownRevisionDate: currentLegacyCipher.revisionDate,
					}),
				});
				expect(legacyUpdate.status).toBe(200);
				const legacyAttachmentBytes = Buffer.from('legacy attachment bytes encrypted with the account key');
				const legacyFileName = encrypt(Buffer.from('legacy-move.bin'), userKey);
				const legacyForm = new FormData();
				legacyForm.set('key', '');
				legacyForm.set(
					'data',
					new Blob([new Uint8Array(encryptAttachment(legacyAttachmentBytes, userKey))]),
					legacyFileName,
				);
				const legacyUpload = await fetch(`${server}/api/ciphers/${legacyItem.id}/attachment`, {
					method: 'POST',
					headers: { Authorization: `Bearer ${auth.access_token}` },
					body: legacyForm,
				});
				expect(legacyUpload.status).toBe(200);
				const legacyWire = (await legacyUpload.json()).attachments[0];
				expect(legacyWire.key).toBe('');
				await checked(['sync']);
				const replacementLegacyItemKey = randomBytes(64);
				try {
					const legacyForRotation = JSON.parse(await checked(['get', 'item', legacyItem.id]));
					await checked([
						'edit',
						'item',
						legacyItem.id,
						encode({ ...legacyForRotation, key: replacementLegacyItemKey.toString('base64') }),
					]);
					const legacyRekeyedPath = join(dir, 'legacy-rekeyed.bin');
					await checked([
						'get',
						'attachment',
						'legacy-move.bin',
						'--itemid',
						legacyItem.id,
						'--output',
						legacyRekeyedPath,
					]);
					expect((await readFile(legacyRekeyedPath)).equals(legacyAttachmentBytes)).toBe(true);
				} finally {
					replacementLegacyItemKey.fill(0);
				}
				const migratedLegacyItem = JSON.parse(
					await checked(['move', legacyItem.id, organization.id, encode([collection.id])]),
				);
				expect(migratedLegacyItem.organizationId).toBe(organization.id);
				expect(migratedLegacyItem.login.password).toBe('legacy-move-secret');
				const legacyDownloadPath = join(dir, 'legacy-move.bin');
				await checked([
					'get',
					'attachment',
					'legacy-move.bin',
					'--itemid',
					legacyItem.id,
					'--output',
					legacyDownloadPath,
				]);
				expect((await readFile(legacyDownloadPath)).equals(legacyAttachmentBytes)).toBe(true);
				const binaryChild = Bun.spawn([
					'node',
					fileURLToPath(import.meta.resolve('#main')),
					'get',
					'attachment',
					attachmentId,
					'--itemid',
					movable.id,
					'--raw',
				], {
					env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, VW_SESSION: session, NODE_EXTRA_CA_CERTS: ca },
					stdout: 'pipe',
					stderr: 'pipe',
				});
				const [binaryCode, binaryOutput] = await Promise.all([
					binaryChild.exited,
					new Response(binaryChild.stdout).arrayBuffer(),
					new Response(binaryChild.stderr).text(),
				]);
				expect(binaryCode).toBe(0);
				expect(Buffer.from(binaryOutput).equals(attachmentBytes)).toBe(true);
				expect(await run(['get', 'attachment', attachmentId, '--itemid', movable.id, '--raw', '--quiet'], session))
					.toEqual({ code: 0, stdout: '', stderr: '' });
				await checked(['edit', 'item-collections', movable.id, encode([collections[0].id])]);
				expect(JSON.parse(await checked(['get', 'item', movable.id])).collectionIds).toEqual([collections[0].id]);
				const renamedCollection = JSON.parse(
					await checked([
						'edit',
						'org-collection',
						collection.id,
						encode({ name: 'Renamed collection' }),
						'--organizationid',
						organization.id,
					]),
				);
				expect(renamedCollection.name).toBe('Renamed collection');
				await checked(['delete', 'org-collection', collection.id, '--organizationid', organization.id]);
				const members = JSON.parse(await checked(['list', 'org-members', '--organizationid', organization.id]));
				expect(members.some((m: { email: string }) => m.email === email)).toBe(true);
				// Register a second real account, invite it, and verify confirmation wraps the org key for that account.
				const memberEmail = `member-${randomUUID()}@example.com`;
				const memberKey = randomBytes(64);
				const memberMaster = await deriveMasterKey(password, memberEmail, { type: 0, iterations: 600000 });
				const memberStretch = stretchKey(memberMaster);
				const memberHash = await masterPasswordHash(memberMaster, password);
				const memberRsa = generateKeyPairSync('rsa', {
					modulusLength: 2048,
					publicKeyEncoding: { type: 'spki', format: 'der' },
					privateKeyEncoding: { type: 'pkcs8', format: 'der' },
				});
				try {
					const verifyMember = await post('/identity/accounts/register/send-verification-email', {
						email: memberEmail,
						name: 'Member fixture',
					});
					expect(verifyMember.status).toBe(200);
					const memberRegistered = await post('/identity/accounts/register/finish', {
						email: memberEmail,
						masterPasswordHash: memberHash,
						key: encrypt(memberKey, memberStretch),
						kdf: 0,
						kdfIterations: 600000,
						emailVerificationToken: await registrationVerificationToken(verifyMember),
						keys: {
							publicKey: memberRsa.publicKey.toString('base64'),
							encryptedPrivateKey: encrypt(memberRsa.privateKey, memberKey),
						},
					});
					expect(memberRegistered.status).toBe(200);
					const invited = await post(`/api/organizations/${organization.id}/users/invite`, {
						emails: [memberEmail],
						type: 2,
						groups: [],
						collections: [{ id: collections[0].id, readOnly: false, hidePasswords: false, manage: false }],
					}, auth.access_token);
					expect(invited.status).toBe(200);
					const pending = JSON.parse(await checked(['list', 'org-members', '--organizationid', organization.id])).find((
						m: { email: string },
					) => m.email === memberEmail);
					expect(pending.status).toBe(1);
					await checked(['confirm', 'org-member', pending.id, '--organizationid', organization.id]);
					const confirmed = JSON.parse(await checked(['list', 'org-members', '--organizationid', organization.id]))
						.find((m: { email: string }) => m.email === memberEmail);
					expect(confirmed.status).toBe(2);
					const memberLogin = await fetch(`${server}/identity/connect/token`, {
						method: 'POST',
						body: new URLSearchParams({
							grant_type: 'password',
							client_id: 'cli',
							scope: 'api offline_access',
							username: memberEmail,
							password: memberHash,
							deviceIdentifier: randomUUID(),
							deviceName: 'Member fixture',
							deviceType: '8',
						}),
					});
					expect(memberLogin.status).toBe(200);
					const memberAuth = await memberLogin.json() as { access_token: string };
					const memberCliDir = join(dir, 'member-cli');
					expect(
						(await run(['config', 'server', tlsServer], undefined, password, undefined, undefined, memberCliDir)).code,
					)
						.toBe(0);
					const memberCliLogin = await run(
						['login', memberEmail, '--raw'],
						undefined,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (memberCliLogin.code) throw new Error(`Member CLI login failed: ${memberCliLogin.stderr}`);
					const memberSession = memberCliLogin.stdout.trim();
					const sharedAttachmentItem = JSON.parse(
						await checked([
							'create',
							'item',
							encode({
								type: 1,
								name: `Shared attachment ID fixture ${randomUUID()}`,
								organizationId: organization.id,
								collectionIds: [collections[0].id],
								login: { username: 'shared-attachment-fixture' },
							}),
						]),
					);
					const sharedExpectedBytes = Buffer.from('owner attachment selected by its explicit ID');
					const sharedSubstituteBytes = Buffer.from('member attachment whose filename collides with that ID');
					const sharedExpectedPath = join(dir, 'shared-attachment-owner.bin');
					await writeFile(sharedExpectedPath, sharedExpectedBytes, { mode: 0o600 });
					const sharedAttachment = JSON.parse(
						await checked([
							'create',
							'attachment',
							'--file',
							sharedExpectedPath,
							'--itemid',
							sharedAttachmentItem.id,
						]),
					);
					const sharedAttachmentId = sharedAttachment.attachments[0].id as string;
					const memberSharedSync = await run(
						['sync', '--force'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (memberSharedSync.code) throw new Error(`Member shared-item sync failed: ${memberSharedSync.stderr}`);
					const sharedSubstitutePath = join(dir, sharedAttachmentId);
					await writeFile(sharedSubstitutePath, sharedSubstituteBytes, { mode: 0o600 });
					const memberSharedAttachment = await run(
						[
							'create',
							'attachment',
							'--file',
							sharedSubstitutePath,
							'--itemid',
							sharedAttachmentItem.id,
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (memberSharedAttachment.code) {
						throw new Error(`Member could not add the shared attachment collision: ${memberSharedAttachment.stderr}`);
					}
					const memberAttachmentRows = JSON.parse(memberSharedAttachment.stdout).attachments as {
						id: string;
						fileName: string;
					}[];
					const memberSubstitute = memberAttachmentRows.find(row => row.fileName === sharedAttachmentId);
					expect(memberSubstitute).toBeDefined();
					expect(memberSubstitute!.id).not.toBe(sharedAttachmentId);
					expect(memberAttachmentRows.some(row => row.id === sharedAttachmentId)).toBe(true);
					await checked(['sync', '--force']);
					const ownerSharedDownload = join(dir, 'shared-attachment-by-id.bin');
					await checked([
						'get',
						'attachment',
						sharedAttachmentId,
						'--itemid',
						sharedAttachmentItem.id,
						'--output',
						ownerSharedDownload,
					]);
					expect(await readFile(ownerSharedDownload)).toEqual(sharedExpectedBytes);
					await checked(['delete', 'item', sharedAttachmentItem.id, '--permanent']);
					await checked(['sync']);
					const policyMarker = Buffer.from(`restricted-policy-attachment-${randomUUID()}`);
					const restrictedLoginName = `Policy restricted fixture login ${randomUUID()}`;
					const restrictedLoginResult = await run(
						[
							'create',
							'item',
							encode({
								type: 1,
								name: restrictedLoginName,
								login: { username: 'fixture-user', password: 'synthetic-password' },
							}),
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedLoginResult.code).toBe(0);
					const restrictedLogin = JSON.parse(restrictedLoginResult.stdout) as { id: string };
					const restrictedCardResult = await run(
						[
							'create',
							'item',
							encode({ type: 3, name: 'Policy restricted fixture card', card: { number: 'synthetic-number' } }),
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedCardResult.code).toBe(0);
					const restrictedCard = JSON.parse(restrictedCardResult.stdout) as { id: string };
					const policyAttachmentPath = join(dir, 'restricted-policy-marker.txt');
					await writeFile(policyAttachmentPath, policyMarker, { mode: 0o600 });
					const policyAttachment = await run(
						['create', 'attachment', '--file', policyAttachmentPath, '--itemid', restrictedCard.id],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(policyAttachment.code).toBe(0);
					const restrictedAttachmentId = (JSON.parse(policyAttachment.stdout) as {
						attachments: { id: string }[];
					}).attachments[0]!.id;
					const policyResponse = await fetch(`${server}/api/organizations/${organization.id}/policies/15`, {
						method: 'PUT',
						headers: {
							'Content-Type': 'application/json',
							Authorization: `Bearer ${auth.access_token}`,
						},
						body: JSON.stringify(
							serverVersion === '1.36.0'
								? { enabled: true, data: [1, 3] }
								: { policy: { enabled: true, data: [1, 3] } },
						),
					});
					expect(policyResponse.status).toBe(200);
					expect(await policyResponse.json()).toMatchObject({ enabled: true, data: [1, 3] });
					const policySync = await run(
						['sync', '--force'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(policySync.code).toBe(0);
					const passwordHealth = await run(
						['report', 'password-health', '--no-check-exposed'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(passwordHealth.code).toBe(0);
					const passwordHealthRows = JSON.parse(passwordHealth.stdout) as { id: string; name: string }[];
					expect(passwordHealthRows.some(row => row.id === restrictedLogin.id || row.name === restrictedLoginName))
						.toBe(false);
					const restorePolicy = await fetch(`${server}/api/organizations/${organization.id}/policies/15`, {
						method: 'PUT',
						headers: {
							'Content-Type': 'application/json',
							Authorization: `Bearer ${auth.access_token}`,
						},
						body: JSON.stringify(
							serverVersion === '1.36.0'
								? { enabled: true, data: [3] }
								: { policy: { enabled: true, data: [3] } },
						),
					});
					expect(restorePolicy.status).toBe(200);
					const restorePolicySync = await run(
						['sync', '--force'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restorePolicySync.code).toBe(0);
					const restrictedList = await run(
						['list', 'items'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedList.code).toBe(0);
					expect(JSON.parse(restrictedList.stdout).some((value: { id: string }) => value.id === restrictedCard.id))
						.toBe(false);
					const restrictedGet = await run(
						['get', 'item', restrictedCard.id],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedGet.code).toBe(1);
					expect(restrictedGet.stderr).toContain('Access to this item type is restricted by organizational policy.');
					const restrictedAttachmentPath = join(dir, 'restricted-policy-download.txt');
					const restrictedAttachmentGet = await run(
						[
							'get',
							'attachment',
							restrictedAttachmentId,
							'--itemid',
							restrictedCard.id,
							'--output',
							restrictedAttachmentPath,
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedAttachmentGet.code).toBe(1);
					expect(restrictedAttachmentGet.stderr).toContain(
						'Access to this item type is restricted by organizational policy.',
					);
					await expect(stat(restrictedAttachmentPath)).rejects.toMatchObject({ code: 'ENOENT' });
					const restrictedCreate = await run(
						[
							'create',
							'item',
							encode({ type: 3, name: 'Must not create policy restricted card', card: { number: 'synthetic-number' } }),
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedCreate.code).toBe(1);
					expect(restrictedCreate.stderr).toContain('Creating this item type is restricted by organizational policy.');
					const restrictedZipPath = join(dir, 'restricted-policy.zip');
					const restrictedZip = await run(
						['export', '--format', 'zip', '--output', restrictedZipPath],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(restrictedZip.code).toBe(0);
					const zipEntries = unzipSync(await readFile(restrictedZipPath));
					const zipData = JSON.parse(Buffer.from(zipEntries['data.json']!).toString('utf8'));
					expect(zipData.items.some((value: { id: string }) => value.id === restrictedCard.id)).toBe(false);
					expect(Object.values(zipEntries).some(contents => Buffer.from(contents).includes(policyMarker))).toBe(false);
					const memberImportName = `Member import into existing collection ${randomUUID()}`;
					const memberImportPath = join(dir, 'member-existing-collection-import.json');
					await writeFile(
						memberImportPath,
						JSON.stringify({
							encrypted: false,
							collections: [{ id: collections[0].id, name: 'Imported existing collection' }],
							items: [{
								type: 1,
								name: memberImportName,
								login: { password: 'member-import-secret' },
								collectionIds: [collections[0].id],
							}],
						}),
						{ mode: 0o600 },
					);
					const memberImport = await run(
						[
							'import',
							'bitwardenjson',
							memberImportPath,
							'--organizationid',
							organization.id,
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (memberImport.code) throw new Error(`Member collection import failed: ${memberImport.stderr}`);
					expect(JSON.parse(memberImport.stdout)).toMatchObject({ items: 1, collections: 1 });
					const memberImportSync = await run(
						['sync'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (memberImportSync.code) throw new Error(`Member import sync failed: ${memberImportSync.stderr}`);
					const memberItemList = await run(
						['list', 'items'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (memberItemList.code) throw new Error(`Member item list failed: ${memberItemList.stderr}`);
					const importedMemberItem = JSON.parse(memberItemList.stdout).find((value: { name: string }) =>
						value.name === memberImportName
					);
					expect(importedMemberItem).toMatchObject({
						organizationId: organization.id,
						collectionIds: [collections[0].id],
					});
					await checked(['sync']);
					await checked(['delete', 'item', importedMemberItem.id, '--permanent']);
					const memberItem = JSON.parse(
						(await run(
							[
								'create',
								'item',
								encode({ type: 1, name: 'Member collectionless move', login: { password: 'member-secret' } }),
							],
							memberSession,
							password,
							undefined,
							undefined,
							memberCliDir,
						)).stdout,
					) as { id: string };
					const memberCollectionlessMove = await run(
						['move', memberItem.id, organization.id],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (Bun.semver.satisfies(serverVersion, '<1.37.4')) {
						expect(memberCollectionlessMove.code).toBe(0);
						const moved = JSON.parse(memberCollectionlessMove.stdout) as {
							organizationId: string;
							collectionIds: string[];
						};
						expect(moved.organizationId).toBe(organization.id);
						expect(moved.collectionIds).toEqual([]);
					} else {
						expect(memberCollectionlessMove.code).toBe(1);
						expect(memberCollectionlessMove.stderr).toContain('Vaultwarden request failed (HTTP 400).');
					}
					const memberShareItem = JSON.parse(
						(await run(
							[
								'create',
								'item',
								encode({ type: 1, name: 'Member collectionless share', login: { password: 'member-secret' } }),
							],
							memberSession,
							password,
							undefined,
							undefined,
							memberCliDir,
						)).stdout,
					) as { id: string };
					const memberCollectionlessShare = await run(
						['share', memberShareItem.id, organization.id],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (Bun.semver.satisfies(serverVersion, '<1.37.4')) {
						expect(memberCollectionlessShare.code).toBe(0);
						expect(JSON.parse(memberCollectionlessShare.stdout).collectionIds).toEqual([]);
					} else {
						expect(memberCollectionlessShare.code).toBe(1);
						expect(memberCollectionlessShare.stderr).toContain('Vaultwarden request failed (HTTP 400).');
					}
					const memberCollectionlessCreate = await run(
						[
							'create',
							'item',
							encode({
								type: 1,
								name: 'Member collectionless create',
								organizationId: organization.id,
								collectionIds: [],
								login: { password: 'member-secret' },
							}),
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					if (Bun.semver.satisfies(serverVersion, '<1.37.4')) {
						expect(memberCollectionlessCreate.code).toBe(0);
						expect(JSON.parse(memberCollectionlessCreate.stdout).collectionIds).toEqual([]);
					} else {
						expect(memberCollectionlessCreate.code).toBe(1);
						expect(memberCollectionlessCreate.stderr).toContain('Vaultwarden request failed (HTTP 400).');
					}
					const memberSync = await fetch(`${server}/api/sync`, {
						headers: { Authorization: `Bearer ${memberAuth.access_token}`, 'Bitwarden-Client-Version': '2026.10.0' },
					});
					expect(memberSync.status).toBe(200);
					const memberVault = await memberSync.json() as { profile: { organizations: { id: string; key: string }[] } };
					const wrapped = memberVault.profile.organizations.find(o => o.id === organization.id)!;
					const shared = await decryptSharedKey(wrapped.key, memberRsa.privateKey);
					try {
						expect(shared).toEqual(orgKey);
					} finally {
						shared.fill(0);
					}
					const accessResponse = await fetch(`${server}/api/organizations/${organization.id}/collections/details`, {
						headers: { Authorization: `Bearer ${auth.access_token}` },
					});
					expect(accessResponse.status).toBe(200);
					const accessRows = (await accessResponse.json()).data as Record<string, unknown>[];
					const defaultCollectionAccess = accessRows.find(row => row.id === collections[0].id)!;
					const memberAssignments = (defaultCollectionAccess.users as Record<string, unknown>[]).map(user => ({
						id: user.id,
						readOnly: user.readOnly,
						hidePasswords: user.id === confirmed.id ? true : user.hidePasswords,
						manage: user.manage,
					}));
					expect(memberAssignments.some(user => user.id === confirmed.id && user.hidePasswords === true)).toBe(true);
					await checked([
						'edit',
						'org-collection',
						collections[0].id,
						encode({ name: collections[0].name, users: memberAssignments }),
						'--organizationid',
						organization.id,
					]);
					const privateKeyMarker = `synthetic-passkey-private-key-${randomUUID()}`;
					const passkeyItem = JSON.parse(
						await checked([
							'create',
							'item',
							encode({
								type: 1,
								name: 'Hidden passkey fixture',
								organizationId: organization.id,
								collectionIds: [collections[0].id],
								login: {
									username: 'passkey-fixture-user',
									fido2Credentials: [{
										credentialId: 'synthetic-credential-id',
										keyType: 'public-key',
										keyAlgorithm: 'ECDSA',
										keyCurve: 'P-256',
										keyValue: privateKeyMarker,
										rpId: 'example.test',
										userName: 'passkey-fixture-user',
										counter: '0',
										creationDate: '2026-10-27T00:00:00.000Z',
									}],
								},
							}),
						]),
					);
					const passkeySync = await run(
						['sync', '--force'],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(passkeySync.code).toBe(0);
					const hiddenPasskeyGet = await run(
						['get', 'item', passkeyItem.id],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(hiddenPasskeyGet.code).toBe(0);
					const hiddenPasskey = JSON.parse(hiddenPasskeyGet.stdout);
					expect(hiddenPasskey.login.fido2Credentials[0].keyValue).toBeNull();
					expect(hiddenPasskeyGet.stdout).not.toContain(privateKeyMarker);
					const deniedExportPath = join(dir, 'member-organization-export.json');
					const deniedOrganizationExport = await run(
						[
							'export',
							'--format',
							'json',
							'--organizationid',
							organization.id,
							'--output',
							deniedExportPath,
						],
						memberSession,
						password,
						undefined,
						undefined,
						memberCliDir,
					);
					expect(deniedOrganizationExport.code).toBe(1);
					expect(deniedOrganizationExport.stderr).toContain('HTTP 401');
					await expect(stat(deniedExportPath)).rejects.toMatchObject({ code: 'ENOENT' });
					// This minimal credential only tests password-visibility redaction. Remove it before
					// comparisons with bw, which deserializes the full FIDO2 credential model.
					await checked(['delete', 'item', passkeyItem.id, '--permanent']);
					await checked(['sync']);
					if (process.env.VW_TEST_POLICY_REDACTION_ONLY === '1') return;
				} finally {
					memberKey.fill(0);
					memberMaster.fill(0);
					memberStretch.fill(0);
					memberRsa.privateKey.fill(0);
				}
				expect(JSON.parse(await checked(['list', 'folders']))[0].name).toBe('Private folder');
				const createdItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({
							type: 1,
							name: 'Created by vw',
							notes: 'new notes',
							folderId: folder.id,
							login: {
								username: 'new-user',
								password: 'new-secret',
								totp: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
								uris: [{ uri: 'https://created.example.com' }],
							},
							fields: [{ type: 0, name: 'private-field', value: 'private-value' }],
						}),
					]),
				);
				expect(createdItem.object).toBe('item');
				expect(createdItem.key).toBeUndefined();
				expect(createdItem.name).toBe('Created by vw');
				expect(JSON.parse(await checked(['list', 'items', '--folderid', folder.id])).length).toBe(1);
				const editedItem = JSON.parse(
					await checked([
						'edit',
						'item',
						createdItem.id,
						encode({
							...createdItem,
							name: 'Edited by vw',
							login: { ...createdItem.login, password: 'edited-secret' },
						}),
					]),
				);
				expect(editedItem.object).toBe('item');
				expect(editedItem.key).toBeUndefined();
				expect(editedItem.login.password).toBe('edited-secret');
				const stale = await run([
					'edit',
					'item',
					createdItem.id,
					encode({ ...editedItem, name: 'Stale overwrite', revisionDate: '2000-01-01T00:00:00Z' }),
				], session);
				expect(stale.code).toBe(1);
				expect(JSON.parse(await checked(['get', 'item', createdItem.id])).name).toBe('Edited by vw');
				expect((await checked(['get', 'totp', createdItem.id])).trim()).toMatch(/^\d{6}$/);
				const newerItems: { id: string; type: number; section: string; fields: Record<string, unknown> }[] = [];
				for (
					const [type, section, fields] of [
						[2, 'secureNote', { type: 0 }],
						[3, 'card', { number: '4111111111111111', code: '123', cardholderName: 'Fixture' }],
						[4, 'identity', { firstName: 'Fixture', ssn: 'synthetic-id' }],
						[5, 'sshKey', {
							privateKey: 'synthetic-private-key',
							publicKey: 'synthetic-public-key',
							keyFingerprint: 'synthetic-fingerprint',
						}],
						[6, 'bankAccount', {
							accountNumber: 'synthetic-bank-number',
							accountType: 'checking',
							bankName: 'Fixture Bank',
						}],
						[7, 'driversLicense', { licenseNumber: 'synthetic-license', firstName: 'Fixture', issuingState: 'NH' }],
						[8, 'passport', { passportNumber: 'synthetic-passport', givenName: 'Fixture', issuingCountry: 'NL' }],
					] as const
				) {
					const result = await run(
						[
							'create',
							'item',
							encode({ type, name: `Type ${type}`, notes: 'typed notes', [section]: fields }),
						],
						session,
						password,
					);
					if (type >= 6 && Bun.semver.satisfies(serverVersion, '<1.37.4')) {
						expect(result.code).toBe(1);
						expect(result.stderr).toContain('requires Vaultwarden 1.37.4 or newer');
						continue;
					}
					if (result.code !== 0) throw new Error(`CLI operation failed: ${result.stderr}`);
					const value = JSON.parse(result.stdout);
					expect(value[section]).toMatchObject(fields);
					expect(JSON.parse(await checked(['get', 'item', value.id]))[section]).toMatchObject(fields);
					if (type >= 6) newerItems.push({ id: value.id, type, section, fields });
					else await checked(['delete', 'item', value.id, '--permanent']);
				}
				const organizationImport = join(dir, 'organization-import.json');
				await writeFile(
					organizationImport,
					JSON.stringify({
						encrypted: false,
						collections: [{ id: 'source-collection', name: 'Imported collection' }],
						items: [{
							id: 'source-note',
							type: 2,
							name: 'Imported organization note',
							notes: 'organization import secret',
							secureNote: { type: 0 },
							collectionIds: ['source-collection'],
						}],
					}),
					{ mode: 0o600 },
				);
				const importedOrg = JSON.parse(
					await checked(['import', 'bitwardenjson', organizationImport, '--organizationid', organization.id]),
				);
				expect(importedOrg).toMatchObject({ items: 1, collections: 1 });
				const organizationExport = JSON.parse(
					await checked(['export', '--format', 'json', '--organizationid', organization.id, '--raw']),
				);
				const importedNote = organizationExport.items.find((value: { name: string }) =>
					value.name === 'Imported organization note'
				);
				expect(importedNote.notes).toBe('organization import secret');
				const importedCollection = organizationExport.collections.find((value: { name: string }) =>
					value.name === 'Imported collection'
				);
				expect(importedNote.collectionIds).toContain(importedCollection.id);
				await checked(['delete', 'item', importedNote.id, '--permanent']);
				await checked(['delete', 'org-collection', importedCollection.id, '--organizationid', organization.id]);
				const keyResponse = await post('/api/accounts/api-key', { masterPasswordHash: hash }, auth.access_token);
				expect(keyResponse.status).toBe(200);
				const issuedKey = await keyResponse.json() as { apiKey: string };
				const apiDir = join(dir, 'api-profile');
				const apiOptions = { directory: apiDir, clientId: `user.${profile.id}`, clientSecret: issuedKey.apiKey };
				const apiRun = (args: string[], token?: string, secret = password) =>
					run(args, token, secret, undefined, apiOptions);
				expect((await apiRun(['config', 'server', tlsServer])).code).toBe(0);
				expect((await apiRun(['login', '--check'])).code).toBe(1);
				const wrongApi = await run(['login', '--apikey', '--nointeraction'], undefined, password, undefined, {
					...apiOptions,
					clientSecret: 'incorrect-api-secret',
				});
				expect(wrongApi.code).toBe(1);
				expect(wrongApi.stderr.includes(issuedKey.apiKey)).toBe(false);
				const apiLogin = await apiRun(['login', '--apikey', '--nointeraction']);
				if (apiLogin.code) throw new Error(`API login failed: ${apiLogin.stderr}`);
				expect(JSON.parse((await apiRun(['status'])).stdout)).toMatchObject({ status: 'locked', userEmail: email });
				expect((await apiRun(['login', '--check'])).code).toBe(0);
				await withStore(apiDir, async (state) => {
					expect(state.vault).toBeDefined();
					expect(state.lastSync).toBeDefined();
				});
				await withStore(apiDir, async (state, save) => {
					state.account!.expiresAt = 0;
					await save();
				});
				expect((await apiRun(['sync'])).code).toBe(0);
				await withStore(apiDir, async (state, save) => {
					state.account!.accessToken = 'expired-api-token';
					await save();
				});
				expect((await apiRun(['sync'])).code).toBe(0);
				const masterFile = join(dir, 'master-password.txt');
				await writeFile(masterFile, `${password}\r\nignored-second-line`, { mode: 0o600 });
				const apiUnlocked = await apiRun(
					['unlock', '--passwordfile', masterFile, '--raw'],
					undefined,
					'incorrect-environment-value',
				);
				if (apiUnlocked.code) throw new Error(`API unlock failed: ${apiUnlocked.stderr}`);
				const apiSession = apiUnlocked.stdout.trim();
				expect((await apiRun(['unlock', '--check'], apiSession)).code).toBe(0);
				expect((await apiRun(['unlock', '--check'])).code).toBe(1);
				expect((await apiRun(['get', 'password', item.id], apiSession)).stdout).toBe('fixture-secret');
				await withStore(apiDir, async (state, save) => {
					state.account!.encryptedUserKey = 'outdated-local-key-wrapper';
					state.account!.expiresAt = 0;
					await save();
				});
				const changedKey = await apiRun(['sync']);
				expect(changedKey.code).toBe(1);
				expect(changedKey.stderr).toContain('key settings changed');
				expect((await apiRun(['get', 'password', item.id], apiSession)).code).toBe(1);
				expect((await apiRun(['sync'])).code).toBe(0);
				const newApiSession = (await apiRun(['unlock', password, '--raw'])).stdout.trim();
				expect((await apiRun(['get', 'password', item.id], newApiSession)).stdout).toBe('fixture-secret');
				await withStore(apiDir, async state => {
					expect(state.account?.auth).toBe('api-key');
					expect('refreshToken' in state.account!).toBe(false);
					expect(JSON.stringify(state).includes(password)).toBe(false);
					expect(JSON.stringify(state).includes(newApiSession)).toBe(false);
				});
				expect((await stat(join(apiDir, 'state.json'))).mode & 0o777).toBe(0o600);
				expect((await apiRun(['lock'])).code).toBe(0);
				expect((await apiRun(['sync'])).code).toBe(0);
				expect((await apiRun(['logout'])).code).toBe(0);
				await withStore(apiDir, async state => {
					expect(state.account).toBeUndefined();
					expect(JSON.stringify(state).includes(issuedKey.apiKey)).toBe(false);
				});
				const textSend = JSON.parse(
					await checked([
						'send',
						'Synthetic Send payload',
						'--name',
						'CLI text Send',
						'--hidden',
						'--fullObject',
						'--passwordenv',
						'VW_PASSWORD',
						'--maxAccessCount',
						'20',
					]),
				);
				expect(textSend.text).toMatchObject({ text: 'Synthetic Send payload', hidden: true });
				expect(textSend.passwordSet).toBe(true);
				expect(JSON.parse(await checked(['send', 'list'])).length).toBe(1);
				expect(await checked(['send', 'get', textSend.id, '--text'])).toBe('Synthetic Send payload');
				const receiveText = await run(['receive', textSend.accessUrl, '--passwordenv', 'VW_PASSWORD']);
				if (receiveText.code) throw new Error(`Receive failed: ${receiveText.stderr}`);
				expect(receiveText.stdout).toBe('Synthetic Send payload');
				expect((await run(['receive', textSend.accessUrl, '--password', 'incorrect-send-password'])).code).toBe(1);
				const editedSend = JSON.parse(
					await checked([
						'send',
						'edit',
						encode({ ...textSend, name: 'Edited text Send', notes: 'Private Send notes' }),
					]),
				);
				expect(editedSend.name).toBe('Edited text Send');
				expect(editedSend.passwordSet).toBe(true);
				const fileSend = JSON.parse(
					await checked(['send', uploadPath, '--file', '--fullObject', '--name', 'CLI file Send']),
				);
				expect(fileSend.file.fileName).toBe('fixture.bin');
				const sendDestination = join(dir, 'send-file.bin');
				const receiveFile = await run(['receive', fileSend.accessUrl, '--output', sendDestination]);
				if (receiveFile.code) throw new Error(`Receive file failed: ${receiveFile.stderr}`);
				expect((await readFile(sendDestination)).equals(attachmentBytes)).toBe(true);
				expect((await stat(sendDestination)).mode & 0o777).toBe(0o600);
				const malformedUriSearch = `Malformed URI ${randomUUID()}`;
				const malformedUriItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({ type: 1, name: malformedUriSearch, login: { uris: [{ match: 0 }] } }),
					]),
				) as { id: string };
				const validUriItem = JSON.parse(
					await checked([
						'create',
						'item',
						encode({
							type: 1,
							name: malformedUriSearch,
							login: { uris: [{ uri: 'https://valid.example.test', match: 0 }] },
						}),
					]),
				) as { id: string };
				await checked(['sync']);
				expect(await checked(['get', 'uri', malformedUriSearch])).toBe('https://valid.example.test');
				if (process.env.VW_TEST_BW) {
					const officialDir = join(dir, 'official');
					async function official(args: string[], token?: string) {
						const executable = process.env.VW_TEST_BW!;
						const command = executable.endsWith('.js') ? ['node', executable, ...args] : [executable, ...args];
						const child = Bun.spawn(command, {
							env: {
								PATH: process.env.PATH,
								HOME: dir,
								VOLTA_HOME: process.env.VOLTA_HOME,
								BITWARDENCLI_APPDATA_DIR: officialDir,
								BW_NOINTERACTION: 'true',
								BW_PASSWORD: password,
								BW_CLIENTID: apiOptions.clientId,
								BW_CLIENTSECRET: issuedKey.apiKey,
								NODE_EXTRA_CA_CERTS: ca,
								...(token ? { BW_SESSION: token } : {}),
							},
							stdout: 'pipe',
							stderr: 'pipe',
						});
						const [code, stdout, stderr] = await Promise.all([
							child.exited,
							new Response(child.stdout).text(),
							new Response(child.stderr).text(),
						]);
						return { code, stdout, stderr };
					}
					expect((await official(['config', 'server', tlsServer])).code).toBe(
						0,
					);
					const login = await official([
						'login',
						email,
						'--passwordenv',
						'BW_PASSWORD',
						'--raw',
					]);
					if (login.code !== 0) {
						throw new Error(`Official bw login failed: ${login.stderr}`);
					}
					const missingObjectId = 'abcdef01-0000-0000-0000-000000000099';
					const lookupFolders: { id: string }[] = [];
					for (const name of ['Lookup Bucket', 'Lookup Bucket Archive', missingObjectId]) {
						lookupFolders.push(JSON.parse(await checked(['create', 'folder', encode({ name })])));
					}
					expect((await official(['sync', '--force'], login.stdout.trim())).code).toBe(0);
					for (const item of newerItems) {
						const reference = await official(['get', 'item', item.id], login.stdout.trim());
						if (reference.code) throw new Error(`Reference item ${item.type} read failed: ${reference.stderr}`);
						expect(JSON.parse(reference.stdout)).toMatchObject({ type: item.type, [item.section]: item.fields });
					}
					for (const [type, query] of [[6, 'Fixture Bank'], [7, 'Fixture NH'], [8, 'Fixture NL']] as const) {
						// Older servers reject these item types above, so they have no records to search.
						const supportedItem = newerItems.find(item => item.type === type);
						if (!supportedItem) continue;
						const listed = JSON.parse(await checked(['list', 'items', '--search', query])) as { id: string }[];
						const reference = await official(['list', 'items', '--search', query], login.stdout.trim());
						if (reference.code) throw new Error(`Reference item search failed: ${reference.stderr}`);
						const referenceIds = (JSON.parse(reference.stdout) as { id: string }[]).map(item => item.id);
						expect(listed.map(item => item.id)).toEqual(referenceIds);
						expect(referenceIds).toContain(supportedItem.id);
					}
					for (const query of [`>shortid:${item.id.slice(0, 8)}`, '>name:Compatibility']) {
						const listed = JSON.parse(await checked(['list', 'items', '--search', query])) as { id: string }[];
						const reference = await official(['list', 'items', '--search', query], login.stdout.trim());
						if (reference.code) throw new Error(`Reference advanced item search failed: ${reference.stderr}`);
						const referenceIds = (JSON.parse(reference.stdout) as { id: string }[]).map(value => value.id);
						expect(listed.map(value => value.id)).toEqual(referenceIds);
						expect(referenceIds).toEqual([]);
					}
					for (
						const [kind, query] of [
							['folder', 'BUCKET ARCH'],
							['folder', lookupFolders[0]!.id.toUpperCase()],
							['collection', 'GANIZATION COL'],
							['organization', 'PATIBILITY ORG'],
						]
					) {
						const reference = await official(['get', kind!, query!], login.stdout.trim());
						expect(reference.code).toBe(0);
						expect(JSON.parse(await checked(['get', kind!, query!])).id).toBe(JSON.parse(reference.stdout).id);
					}
					for (const query of ['Lookup Bucket', missingObjectId]) {
						const ours = await run(['get', 'folder', query], session);
						const reference = await official(['get', 'folder', query], login.stdout.trim());
						expect(ours.code).toBe(1);
						expect(reference.code).toBe(1);
					}
					for (const value of lookupFolders) await checked(['delete', 'folder', value.id]);
					const fingerprint = await checked(['get', 'fingerprint', 'me']);
					const referenceFingerprint = await official(['get', 'fingerprint', 'me'], login.stdout.trim());
					expect(referenceFingerprint.code).toBe(0);
					expect(fingerprint).toBe(referenceFingerprint.stdout);
					expect(await checked(['get', 'fingerprint', profile.id])).toBe(fingerprint);
					const uriFixtures = [
						['Domain', 'https://account.example.com/path', 0],
						['Host', 'https://host.example.net:8443/a', 1],
						['Prefix', 'https://start.example.org/a', 2],
						['Exact', 'https://exact.example.net/a', 3],
						['Regex', '^https://regex[.]example[.]net/[a-z]+$', 4],
						['Never', 'https://never.example.net', 5],
						['Private', 'https://alice.github.io', 0],
						['Unicode', 'https://测试.com', 0],
						['Google', 'https://accounts.google.com', 0],
					];
					const lookupFile = join(dir, 'lookup-fixture.json');
					await writeFile(
						lookupFile,
						JSON.stringify({
							encrypted: false,
							folders: [],
							items: [
								...uriFixtures.map(([name, uri, match]) => ({
									type: 1,
									name: `URI ${name}`,
									login: { password: 'uri-secret', uris: [{ uri, match }] },
								})),
								{
									type: 1,
									name: 'Lookup Café',
									notes: 'Client project',
									login: { username: 'alice@company.com', password: 'lookup-secret' },
								},
								{ type: 2, name: 'Lookup Café', notes: 'Other note', secureNote: { type: 0 } },
							],
						}),
						{ mode: 0o600 },
					);
					await checked(['import', 'bitwardenjson', lookupFile]);
					const lookupItems = JSON.parse(await checked(['list', 'items'])).filter((value: { name: string }) =>
						value.name.startsWith('URI ') || value.name.startsWith('Lookup ')
					);
					expect(
						(await post('/api/settings/domains', {
							equivalentDomains: [['example.com', 'alias.test']],
							excludedGlobalEquivalentDomains: [],
						}, auth.access_token)).status,
					).toBe(200);
					await checked(['sync']);
					expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
					const ids = (source: string) => JSON.parse(source).map((value: { id: string }) => value.id).sort();
					for (
						const filter of [
							['--folderid', 'null'],
							['--organizationid', 'notnull'],
							['--collectionid', 'null'],
							['--collectionid', 'notnull'],
							['--folderid', folder.id, '--organizationid', 'notnull'],
							['--search', 'Shared', '--folderid', folder.id, '--organizationid', 'notnull'],
						]
					) {
						const reference = await official(['list', 'items', ...filter], login.stdout.trim());
						if (reference.code) {
							throw new Error(`Official list filter failed (${filter.join(' ')}): ${reference.stderr}`);
						}
						const actualItems = JSON.parse(await checked(['list', 'items', ...filter])) as Record<string, unknown>[];
						const referenceItems = JSON.parse(reference.stdout) as Record<string, unknown>[];
						const referenceIds = new Set(referenceItems.map(value => value.id));
						const localOnly = actualItems.filter(value => !referenceIds.has(value.id)).map(value => ({
							id: value.id,
							name: value.name,
							type: value.type,
							folderId: value.folderId,
							organizationId: value.organizationId,
							collectionIds: value.collectionIds,
							deletedDate: value.deletedDate,
							archivedDate: value.archivedDate,
						}));
						if (localOnly.length) {
							const referenceItem = await official(['get', 'item', String(localOnly[0]!.id)], login.stdout.trim());
							let referenceSummary: Record<string, unknown>;
							try {
								const value = JSON.parse(referenceItem.stdout) as Record<string, unknown>;
								referenceSummary = Object.fromEntries([
									'id',
									'type',
									'folderId',
									'organizationId',
									'collectionIds',
									'deletedDate',
									'archivedDate',
									'viewPassword',
								].map(key => [key, value[key]]));
							} catch {
								referenceSummary = { code: referenceItem.code, error: referenceItem.stderr.trim() };
							}
							throw new Error(
								`Local-only results for ${filter.join(' ')}: ${
									JSON.stringify({ localOnly, referenceItem: referenceSummary })
								}`,
							);
						}
						expect(
							actualItems.map(value => value.id).sort(),
							`list items ${filter.join(' ')}`,
						).toEqual(referenceItems.map(value => value.id).sort());
					}
					for (
						const url of [
							'https://www.example.com/other',
							'http://host.example.net:8443/b',
							'https://host.example.net/b',
							'https://start.example.org/abc',
							'https://start.example.org/b',
							'https://exact.example.net/a',
							'https://exact.example.net/a/',
							'HTTPS://REGEX.EXAMPLE.NET/path',
							'https://never.example.net',
							'https://bob.github.io',
							'https://xn--0zwm56d.com',
							'https://script.google.com',
							'https://mail.google.com',
						]
					) {
						const reference = await official(['list', 'items', '--url', url], login.stdout.trim());
						if (reference.code) throw new Error(`Official URL filter failed: ${reference.stderr}`);
						expect(ids(await checked(['list', 'items', '--url', url])), `URL filter: ${url}`).toEqual(
							ids(reference.stdout),
						);
					}
					// bw's CLI deliberately excludes domain settings from sync; vw honors the server groups.
					const aliases = ids(await checked(['list', 'items', '--url', 'https://alias.test/path']));
					expect(aliases).toEqual(ids(await checked(['list', 'items', '--url', 'https://www.example.com/other'])));
					expect(aliases).toHaveLength(3);
					const referenceAliases = await official(
						['list', 'items', '--url', 'https://alias.test/path'],
						login.stdout.trim(),
					);
					expect(referenceAliases.code).toBe(0);
					expect(ids(referenceAliases.stdout)).toEqual([]);
					const lookupLogin = lookupItems.find((value: { name: string; type: number }) =>
						value.name === 'Lookup Café' && value.type === 1
					);
					for (const query of ['cafe alice', 'project company', lookupLogin.id.slice(0, 8)]) {
						const reference = await official(['get', 'password', query], login.stdout.trim());
						expect(reference.code).toBe(0);
						expect(await checked(['get', 'password', query])).toBe(reference.stdout);
					}
					expect(await checked(['get', 'uri', malformedUriSearch])).toBe('https://valid.example.test');
					const referenceMalformedUri = await official(['get', 'uri', malformedUriSearch], login.stdout.trim());
					expect(referenceMalformedUri.code).toBe(0);
					expect(referenceMalformedUri.stdout).toBe('https://valid.example.test');
					await checked(['delete', 'item', malformedUriItem.id, '--permanent']);
					await checked(['delete', 'item', validUriItem.id, '--permanent']);
					expect((await run(['get', 'item', 'lookup cafe'], session)).code).toBe(1);
					expect((await official(['get', 'item', 'lookup cafe'], login.stdout.trim())).code).toBe(1);
					expect(ids(await checked(['list', 'items', '--search', 'cafe alice']))).toEqual([lookupLogin.id]);
					for (const value of lookupItems) await checked(['delete', 'item', value.id, '--permanent']);
					expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
					const healthInputs = [
						['password', 'person'],
						['password11', 'person'],
						['Weakpass2', 'person'],
						['GoodPass3!', 'person'],
						['VeryStrong123@#', 'person'],
						['asdfjkhkjwer!', 'asdfjkhkjwer@example.com'],
						['asdfjkhkjwer!', 'unrelated'],
						['password', 'other'],
						['🔑Unicode-example-19', 'unicode'],
						['Xy7$'.repeat(100), 'oversized'],
						['', 'empty'],
						['password', 'archived'],
						['password', 'trashed'],
					];
					const healthFile = join(dir, 'health-fixture.json');
					await writeFile(
						healthFile,
						JSON.stringify({
							encrypted: false,
							folders: [],
							items: [
								...healthInputs.map(([secret, username], index) => ({
									type: 1,
									name: `Health ${index}`,
									login: { password: secret, username },
								})),
								{ type: 2, name: 'Health note', secureNote: { type: 0 } },
							],
						}),
						{ mode: 0o600 },
					);
					await checked(['import', 'bitwardenjson', healthFile]);
					const healthItems = JSON.parse(await checked(['list', 'items'])).filter((value: { name: string }) =>
						value.name.startsWith('Health ')
					);
					await checked([
						'archive',
						'item',
						healthItems.find((value: { name: string }) => value.name === 'Health 11').id,
					]);
					await checked([
						'delete',
						'item',
						healthItems.find((value: { name: string }) => value.name === 'Health 12').id,
					]);
					const localHealth = JSON.parse(await checked(['report', 'password-health', '--no-check-exposed']));
					expect(localHealth.some((value: { name: string }) => value.name === 'Health 11')).toBe(true);
					for (const name of ['Health 10', 'Health 12', 'Health note']) {
						expect(localHealth.some((value: { name: string }) => value.name === name)).toBe(false);
					}
					expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
					const referenceHealth = await official(
						['report', 'password-health', '--no-check-exposed'],
						login.stdout.trim(),
					);
					if (referenceHealth.code) throw new Error(`Official report failed: ${referenceHealth.stderr}`);
					const byId = (a: { id: string }, b: { id: string }) => a.id.localeCompare(b.id);
					expect([...localHealth].sort(byId)).toEqual(JSON.parse(referenceHealth.stdout).sort(byId));
					let exposureRequests = 0;
					let exposureFailure = false;
					const exposureApi = Bun.serve({
						hostname: '127.0.0.1',
						port: 0,
						fetch(request) {
							exposureRequests++;
							expect(request.headers.has('Authorization')).toBe(false);
							expect(request.headers.get('Add-Padding')).toBe('true');
							expect(new URL(request.url).pathname).toMatch(/^\/range\/[A-F0-9]{5}$/);
							if (exposureFailure) return new Response('Synthetic upstream failure', { status: 503 });
							const rows = [['password', 37], ['edited-secret', 4]].map(([value, count]) => {
								const hash = createHash('sha1').update(String(value)).digest('hex').toUpperCase();
								return new URL(request.url).pathname.endsWith(hash.slice(0, 5))
									? `${hash.slice(5)}:${count}`
									: undefined;
							}).filter(Boolean);
							return new Response([...rows, `${'0'.repeat(35)}:0`].join('\r\n'));
						},
					});
					try {
						await checked(['report', 'password-health', '--no-check-exposed', '--hibp-url', exposureApi.url.origin]);
						expect(exposureRequests).toBe(0);
						const exposedHealth = JSON.parse(
							await checked(['report', 'password-health', '--hibp-url', exposureApi.url.origin]),
						);
						const exposed = exposedHealth.find((value: { name: string }) => value.name === 'Health 0');
						expect(exposed).toMatchObject({ exposed: true, exposedCount: 37, exposedError: null, reuseCount: 3 });
						expect(await checked(['get', 'exposed', createdItem.id, '--hibp-url', exposureApi.url.origin])).toBe('4');
						exposureFailure = true;
						const failedHealth = JSON.parse(
							await checked(['report', 'password-health', '--hibp-url', exposureApi.url.origin]),
						);
						expect(
							failedHealth.every((value: { exposedCount: number | null; exposedError: string | null }) =>
								value.exposedCount === null && value.exposedError !== null
							),
						).toBe(true);
						expect((await run(['get', 'exposed', createdItem.id, '--hibp-url', exposureApi.url.origin], session)).code)
							.toBe(1);
					} finally {
						exposureApi.stop(true);
					}
					for (const value of healthItems) await checked(['delete', 'item', value.id, '--permanent']);
					expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
					const officialSend = await official(['send', 'get', textSend.id], login.stdout.trim());
					if (officialSend.code) throw new Error(`Official Send read failed: ${officialSend.stderr}`);
					expect(JSON.parse(officialSend.stdout).text.text).toBe('Synthetic Send payload');
					const accessId = new URL(fileSend.accessUrl).hash.split('/')[2];
					const accessTokenResponse = await fetch(`${server}/identity/connect/token`, {
						method: 'POST',
						body: new URLSearchParams({
							grant_type: 'send_access',
							client_id: 'send',
							scope: 'api.send.access',
							send_id: accessId!,
						}),
					});
					expect(accessTokenResponse.status).toBe(200);
					const sendAccessToken = (await accessTokenResponse.json()).access_token as string;
					const fileDownloadData = await fetch(`${server}/api/sends/access/file/${fileSend.file.id}`, {
						method: 'POST',
						headers: { Authorization: `Bearer ${sendAccessToken}` },
					});
					expect(fileDownloadData.status).toBe(200);
					const signedFileUrl = new URL((await fileDownloadData.json()).url as string);
					const directFileResponse = await fetch(`${server}${signedFileUrl.pathname}${signedFileUrl.search}`);
					expect(directFileResponse.status).toBe(200);
					expect((await directFileResponse.arrayBuffer()).byteLength).toBeGreaterThan(0);
					const officialReceive = await official(['receive', textSend.accessUrl, '--passwordenv', 'BW_PASSWORD']);
					if (officialReceive.code) throw new Error(`Official Send receive failed: ${officialReceive.stderr}`);
					expect(officialReceive.stdout.trim()).toBe('Synthetic Send payload');
					const officialSendFile = join(dir, 'official-send-file.bin');
					const officialFileReceive = await official(['receive', fileSend.accessUrl, '--output', officialSendFile]);
					if (officialFileReceive.code) {
						throw new Error(`Official Send file receive failed (exit ${officialFileReceive.code}).`);
					}
					expect((await readFile(officialSendFile)).equals(attachmentBytes)).toBe(true);
					const officialCreated = await official([
						'send',
						'From official bw',
						'--name',
						'Official text Send',
						'--password',
						password,
						'--fullObject',
					], login.stdout.trim());
					if (officialCreated.code) throw new Error(`Official Send create failed: ${officialCreated.stderr}`);
					const fromOfficial = JSON.parse(officialCreated.stdout);
					const receivedOfficial = await run(['receive', fromOfficial.accessUrl, '--passwordenv', 'VW_PASSWORD']);
					if (receivedOfficial.code) {
						throw new Error(`Official-created Send receive failed: ${receivedOfficial.stderr}`);
					}
					expect(receivedOfficial.stdout).toBe('From official bw');
					await checked(['sync']);
					expect(JSON.parse(await checked(['send', 'get', fromOfficial.id])).text.text).toBe('From official bw');
					await checked(['send', 'delete', fromOfficial.id]);
					const result = await official(
						['get', 'password', item.id],
						login.stdout.trim(),
					);
					expect(result.code).toBe(0);
					expect(result.stdout.trim()).toBe('fixture-secret');
					const written = await official(['get', 'item', createdItem.id], login.stdout.trim());
					expect(written.code).toBe(0);
					expect(JSON.parse(written.stdout).login.password).toBe('edited-secret');
					expect(JSON.parse(written.stdout).fields[0].value).toBe('private-value');
					const sharedRead = await official(['get', 'password', sharedItem.id], login.stdout.trim());
					expect(sharedRead.code).toBe(0);
					expect(sharedRead.stdout.trim()).toBe('organization-secret');
					const officialFolder = await official(['get', 'folder', folder.id], login.stdout.trim());
					expect(officialFolder.code).toBe(0);
					expect(JSON.parse(officialFolder.stdout).name).toBe('Private folder');
					const officialAttachment = join(dir, 'official.bin');
					const officialDownload = await official([
						'get',
						'attachment',
						attachmentId,
						'--itemid',
						movable.id,
						'--output',
						officialAttachment,
					], login.stdout.trim());
					expect(officialDownload.code).toBe(0);
					// bw 2026.10.0 selects the colliding filename here, despite the requested ID matching A.
					expect((await readFile(officialAttachment)).equals(collisionBytes)).toBe(true);
					const officialLegacyAttachment = join(dir, 'official-legacy.bin');
					const officialLegacyDownload = await official([
						'get',
						'attachment',
						'legacy-move.bin',
						'--itemid',
						legacyItem.id,
						'--output',
						officialLegacyAttachment,
					], login.stdout.trim());
					if (officialLegacyDownload.code) {
						throw new Error(`Official legacy attachment read failed: ${officialLegacyDownload.stderr}`);
					}
					expect((await readFile(officialLegacyAttachment)).equals(legacyAttachmentBytes)).toBe(true);
					const officialMoved = await official(['get', 'password', movable.id], login.stdout.trim());
					expect(officialMoved.code).toBe(0);
					expect(officialMoved.stdout.trim()).toBe('moved-secret');
					// Exercise both directions with independent bw serialization and KDF handling.
					const filePassword = join(dir, 'transfer-password.txt');
					await writeFile(filePassword, 'Synthetic-export-password-456!\n', { mode: 0o600 });
					const baseExportNames = ['Compatibility fixture', 'Edited by vw'];
					const fullExportNames = [...baseExportNames, ...newerItems.map(item => `Type ${item.type}`)];
					const originalItems = new Set(JSON.parse(await checked(['list', 'items'])).map((v: { id: string }) => v.id));
					const originalFolders = new Set(
						JSON.parse(await checked(['list', 'folders'])).map((v: { id: string }) => v.id),
					);
					async function verifyImported(
						withAttachment = false,
						expectedNames: string[] = fullExportNames,
						syncFirst = true,
					) {
						if (syncFirst) await checked(['sync']);
						const added = JSON.parse(await checked(['list', 'items'])).filter((v: { id: string }) =>
							!originalItems.has(v.id)
						);
						expect(added.map((v: { name: string }) => v.name).sort()).toEqual([...expectedNames].sort());
						expect(added.find((v: { name: string }) => v.name === 'Edited by vw').login.password).toBe('edited-secret');
						expect(added.find((v: { name: string }) => v.name === 'Compatibility fixture').login.password).toBe(
							'fixture-secret',
						);
						for (const item of newerItems) {
							if (!expectedNames.includes(`Type ${item.type}`)) continue;
							expect(added.find((value: { name: string }) => value.name === `Type ${item.type}`)).toMatchObject({
								type: item.type,
								[item.section]: item.fields,
							});
						}
						if (withAttachment) {
							const copy = added.find((v: { name: string }) => v.name === 'Compatibility fixture');
							expect(copy.attachments.length).toBe(1);
							const destination = join(dir, `restored-${randomUUID()}.bin`);
							await checked([
								'get',
								'attachment',
								copy.attachments[0].id,
								'--itemid',
								copy.id,
								'--output',
								destination,
							]);
							expect((await readFile(destination)).equals(attachmentBytes)).toBe(true);
						}
						for (const value of added) await checked(['delete', 'item', value.id, '--permanent']);
						const folders = JSON.parse(await checked(['list', 'folders']));
						for (const value of folders) {
							if (!originalFolders.has(value.id)) await checked(['delete', 'folder', value.id]);
						}
					}
					for (const format of ['json', 'csv', 'encrypted_json', 'password'] as const) {
						const expectedNames = format === 'csv' ? baseExportNames : fullExportNames;
						const transferFormat = format === 'password' ? 'encrypted_json' : format;
						const importFormat = format === 'csv' ? 'bitwardencsv' : 'bitwardenjson';
						const ours = join(dir, `vw-${format}.export`);
						await checked([
							'export',
							'--format',
							transferFormat,
							'--output',
							ours,
							...(format === 'password' ? ['--passwordfile', filePassword] : []),
						]);
						const imported = await official([
							'import',
							importFormat,
							ours,
							...(format === 'password' ? ['--passwordfile', filePassword] : []),
						], login.stdout.trim());
						if (imported.code) throw new Error(`Official import ${format} failed: ${imported.stderr}`);
						await verifyImported(false, expectedNames);
						// Refresh bw after deleting the imported copies, then export its authoritative cache.
						expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
						const theirs = join(dir, `bw-${format}.export`);
						const exported = await official([
							'export',
							'--format',
							transferFormat,
							'--output',
							theirs,
							...(format === 'password' ? ['--password', 'Synthetic-export-password-456!'] : []),
						], login.stdout.trim());
						if (exported.code) throw new Error(`Official export ${format} failed: ${exported.stderr}`);
						const result = JSON.parse(
							await checked([
								'import',
								importFormat,
								theirs,
								...(format === 'password' ? ['--passwordfile', filePassword] : []),
							]),
						);
						expect(result.items).toBe(expectedNames.length);
						await verifyImported(false, expectedNames, false);
					}
					const attached = JSON.parse(
						await checked(['create', 'attachment', '--file', uploadPath, '--itemid', item.id]),
					);
					for (const source of ['vw', 'bw']) {
						const path = join(dir, `${source}-backup.zip`);
						if (source === 'vw') await checked(['export', '--format', 'zip', '--output', path]);
						else {
							expect((await official(['sync'], login.stdout.trim())).code).toBe(0);
							const result = await official(['export', '--format', 'zip', '--output', path], login.stdout.trim());
							if (result.code) throw new Error(`Official ZIP export failed: ${result.stderr}`);
						}
						const restored = JSON.parse(await checked(['import', 'bitwardenzip', path]));
						expect(restored.attachments).toBe(1);
						await verifyImported(true, fullExportNames, false);
					}
					const noCollectionItems = [] as { id: string }[];
					for (const name of ['Move without collection: vw', 'Move without collection: bw']) {
						noCollectionItems.push(JSON.parse(
							await checked([
								'create',
								'item',
								encode({ type: 1, name, login: { username: 'move-user', password: 'move-secret' } }),
							]),
						));
					}
					expect((await official(['sync', '--force'], login.stdout.trim())).code).toBe(0);
					const moveWithoutCollection = await run(['move', noCollectionItems[0]!.id, organization.id], session);
					// 1.37.5 added a nonempty-collection check to the single-cipher share endpoint.
					// https://github.com/dani-garcia/vaultwarden/commit/64ae55ceb2e33aa08e7291d50ca010c679064842
					if (Bun.semver.satisfies(serverVersion, '<1.37.5')) {
						expect(moveWithoutCollection.code).toBe(0);
						const movedWithoutCollection = JSON.parse(moveWithoutCollection.stdout);
						expect(movedWithoutCollection.organizationId).toBe(organization.id);
						expect(movedWithoutCollection.collectionIds).toEqual([]);
					} else {
						expect(moveWithoutCollection.code).toBe(1);
						expect(moveWithoutCollection.stderr).toContain('Vaultwarden request failed (HTTP 400).');
						const unchanged = JSON.parse(await checked(['get', 'item', noCollectionItems[0]!.id]));
						expect(unchanged.organizationId).toBeNull();
						expect(unchanged.login.password).toBe('move-secret');
						const movedWithCollection = JSON.parse(
							await checked([
								'move',
								noCollectionItems[0]!.id,
								organization.id,
								encode([collections[0].id]),
							]),
						);
						expect(movedWithCollection.organizationId).toBe(organization.id);
						expect(movedWithCollection.collectionIds).toEqual([collections[0].id]);
						expect(movedWithCollection.login.password).toBe('move-secret');
					}
					const referenceMoveWithoutCollection = await official(
						['move', noCollectionItems[1]!.id, organization.id],
						login.stdout.trim(),
					);
					expect(referenceMoveWithoutCollection.code).toBe(1);
					expect(referenceMoveWithoutCollection.stderr).toContain('`requestJson` was not provided.');
					await checked(['sync']);
					await checked(['delete', 'attachment', attached.attachments[0].id, '--itemid', item.id]);
					expect((await official(['logout'])).code).toBe(0);
					const referenceApiLogin = await official(['login', '--apikey']);
					if (referenceApiLogin.code) throw new Error(`Official API login failed: ${referenceApiLogin.stderr}`);
					const referenceApiUnlock = await official(['unlock', '--passwordenv', 'BW_PASSWORD', '--raw']);
					if (referenceApiUnlock.code) throw new Error(`Official API unlock failed: ${referenceApiUnlock.stderr}`);
					expect((await official(['get', 'password', item.id], referenceApiUnlock.stdout.trim())).stdout.trim()).toBe(
						'fixture-secret',
					);
				}
				expect(
					(
						await run(['list', 'items', '--search', 'no match'], session)
					).stdout.trim(),
				).toBe('[]');
				const removedPassword = JSON.parse(await checked(['send', 'remove-password', textSend.id]));
				expect(removedPassword.passwordSet).toBe(false);
				expect((await run(['send', 'receive', textSend.accessUrl])).stdout).toBe('Synthetic Send payload');
				for (
					const [name, patch] of [
						['access-limit', { maxAccessCount: 1 }],
						['expired', { expirationDate: '2000-01-01T00:00:00Z' }],
						['disabled', { disabled: true }],
					] as const
				) {
					const limited = JSON.parse(
						await checked(['send', 'create', encode({ type: 0, name, text: { text: name }, ...patch })]),
					);
					const first = await run(['receive', limited.accessUrl]);
					expect(first.code).toBe(name === 'access-limit' ? 0 : 1);
					if (name === 'access-limit') expect((await run(['receive', limited.accessUrl])).code).toBe(1);
					await checked(['send', 'delete', limited.id]);
				}
				await checked(['send', 'delete', textSend.id]);
				await checked(['send', 'delete', fileSend.id]);
				expect(JSON.parse(await checked(['send', 'list']))).toEqual([]);
				expect((await run(['receive', textSend.accessUrl])).code).toBe(1);
				await checked(['archive', 'item', createdItem.id]);
				expect(JSON.parse(await checked(['list', 'items', '--archived']))[0].id).toBe(createdItem.id);
				await checked(['restore', 'item', createdItem.id]);
				await checked(['delete', 'item', createdItem.id]);
				expect(JSON.parse(await checked(['list', 'items', '--trash']))[0].id).toBe(createdItem.id);
				await checked(['restore', 'item', createdItem.id]);
				expect((await checked(['get', 'password', createdItem.id])).trim()).toBe('edited-secret');
				await checked(['delete', 'item', createdItem.id, '--permanent']);
				expect((await run(['get', 'item', createdItem.id], session)).code).toBe(1);
				const renamed = JSON.parse(await checked(['edit', 'folder', folder.id, encode({ name: 'Renamed folder' })]));
				expect(renamed.name).toBe('Renamed folder');
				await checked(['delete', 'folder', folder.id]);
				expect(JSON.parse(await checked(['list', 'folders']))).toEqual([]);
				await checked(['delete', 'attachment', attachmentId, '--itemid', movable.id]);
				await checked(['delete', 'attachment', collisionId, '--itemid', movable.id]);
				expect((await run(['get', 'attachment', attachmentId, '--itemid', movable.id, '--raw'], session)).code).toBe(1);
				const persisted = await readFile(join(dir, 'state.json'), 'utf8');
				for (
					const secret of [
						password,
						'fixture-secret',
						'fixture notes',
						userKey.toString('base64'),
						session,
					]
				) {
					expect(persisted).not.toContain(secret);
				}
				expect((await stat(join(dir, 'state.json'))).mode & 0o777).toBe(0o600);
				await closeProxy();
				expect((await run(['get', 'password', item.id], session)).stdout).toBe(
					'fixture-secret',
				);
				expect((await run(['lock'])).code).toBe(0);
				expect((await run(['get', 'password', item.id], session)).code).toBe(1);
				expect((await run(['logout'])).code).toBe(0);
				expect(JSON.parse((await run(['status'])).stdout).status).toBe(
					'unauthenticated',
				);
			} finally {
				await closeProxy();
				orgKey.fill(0);
				userKey.fill(0);
				itemKey.fill(0);
				await rm(dir, { recursive: true, force: true });
			}
		},
		600000,
	);
}
