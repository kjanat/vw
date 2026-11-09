import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { randomBytes, randomUUID, generateKeyPairSync } from 'node:crypto';
import { mkdtemp, rm, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { spawn } from 'node:child_process';
import { runCapturedProcess } from '#test/process';
import {
	ApiError,
	VaultwardenClient,
	deriveMasterKey,
	masterPasswordHash,
	stretchKey,
	encrypt,
	loginWithPassword,
	unlockAccount,
	totp,
	field,
	object,
	text,
	writeCsv,
	createAccountKeyMaterial,
} from '@kjanat/vaultwarden';
import { writeTestCertificate } from '#test/fixtures/tls';
import { registrationVerificationToken } from '#test/fixtures/registration';

const server = process.env.VW_TEST_SERVER;
const live = server ? test : test.skip;
async function waitForTotpWindowStart(): Promise<void> {
	const elapsed = Date.now() % 30000;
	const delay = elapsed < 5000 ? 5000 - elapsed : 0;
	if (delay) await new Promise(resolve => setTimeout(resolve, delay));
}
async function waitForNextTotpWindow(): Promise<void> {
	const elapsed = Date.now() % 30000;
	await new Promise(resolve => setTimeout(resolve, 35000 - elapsed));
}
live('real Vaultwarden: recovery-code challenge through the production library', async () => {
	const location = new URL(server!);
	if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1') {
		throw new Error('Live tests require a disposable HTTP loopback server.');
	}
	const email = `recovery-${randomUUID()}@example.com`, password = 'Synthetic-recovery-password-123!';
	const kdf = { type: 0, iterations: 600000 } as const;
	const material = await createAccountKeyMaterial(password, email, kdf);
	try {
		const post = (path: string, body: unknown) =>
			fetch(`${server}${path}`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
				body: JSON.stringify(body),
				signal: AbortSignal.timeout(10000),
			});
		const verify = await post('/identity/accounts/register/send-verification-email', { email });
		expect(verify.status).toBe(200);
		const registered = await post('/identity/accounts/register/finish', {
			email,
			masterPasswordHash: material.masterPasswordHash,
			key: material.encryptedUserKey,
			keys: { publicKey: material.publicKey, encryptedPrivateKey: material.encryptedPrivateKey },
			kdf: kdf.type,
			kdfIterations: kdf.iterations,
			emailVerificationToken: await registrationVerificationToken(verify),
		});
		expect(registered.status).toBe(200);
		const client = new VaultwardenClient(server!);
		const initial = await loginWithPassword(client, email, password);
		const proof = { masterPasswordHash: material.masterPasswordHash };
		const setup = await client.api(initial.accessToken, 'POST', '/two-factor/get-authenticator', proof);
		const secret = text(field(object(setup.authenticator ?? setup), 'key'));
		await waitForTotpWindowStart();
		await client.api(initial.accessToken, 'PUT', '/two-factor/authenticator', {
			...proof,
			key: secret,
			token: totp(secret),
			userVerificationToken: setup.userVerificationToken,
		});
		const recovery = await client.api(initial.accessToken, 'POST', '/two-factor/get-recover', proof);
		const code = text(field(recovery, 'code'));
		let challenges = 0;
		const recovered = await loginWithPassword(client, email, password, undefined, {
			onTwoFactor: async challenge => {
				challenges++;
				expect(challenge.providers).toEqual([0]);
				return { provider: 8, token: `  ${code.toUpperCase().split('').join(' ')}  ` };
			},
		});
		expect(challenges).toBe(1);
		const key = await unlockAccount(recovered, password);
		try {
			expect(key.equals(material.userKey)).toBe(true);
		} finally {
			key.fill(0);
		}
		const methods = await client.api(recovered.accessToken, 'GET', '/two-factor');
		expect(field(methods, 'data')).toEqual([]);
		await expect(loginWithPassword(client, email, password)).resolves.toMatchObject({ email });
	} finally {
		material.userKey.fill(0);
	}
}, 30000);
live('real Vaultwarden: authentication, external imports, and REST compatibility', async () => {
	const location = new URL(server!);
	if (location.protocol !== 'http:' || location.hostname !== '127.0.0.1') {
		throw new Error('Live tests require a disposable HTTP loopback server.');
	}
	const email = `challenge-${randomUUID()}@example.com`, password = 'Synthetic-fixture-password-123!';
	const kdf = { type: 0, iterations: 600000 } as const;
	const master = await deriveMasterKey(password, email, kdf);
	const hash = await masterPasswordHash(master, password), userKey = randomBytes(64), stretched = stretchKey(master);
	const wrapped = encrypt(userKey, stretched);
	master.fill(0);
	stretched.fill(0);
	const post = (path: string, body: unknown) =>
		fetch(`${server}${path}`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
			body: JSON.stringify(body),
		});
	const verify = await post('/identity/accounts/register/send-verification-email', { email, name: 'TOTP fixture' });
	expect(verify.status).toBe(200);
	const registered = await post('/identity/accounts/register/finish', {
		email,
		name: 'TOTP fixture',
		masterPasswordHash: hash,
		key: wrapped,
		keys: (() => {
			const pair = generateKeyPairSync('rsa', {
				modulusLength: 2048,
				publicKeyEncoding: { type: 'spki', format: 'der' },
				privateKeyEncoding: { type: 'pkcs8', format: 'der' },
			});
			try {
				return { publicKey: pair.publicKey.toString('base64'), encryptedPrivateKey: encrypt(pair.privateKey, userKey) };
			} finally {
				pair.privateKey.fill(0);
			}
		})(),
		kdf: kdf.type,
		kdfIterations: kdf.iterations,
		emailVerificationToken: await registrationVerificationToken(verify),
	});
	expect(registered.status).toBe(200);
	const client = new VaultwardenClient(server!);
	const initial = await loginWithPassword(client, email, password);
	const setup = await client.api(initial.accessToken, 'POST', '/two-factor/get-authenticator', {
		masterPasswordHash: hash,
	});
	const secret = text(field(object(setup.authenticator ?? setup), 'key'));
	await waitForTotpWindowStart();
	await client.api(initial.accessToken, 'PUT', '/two-factor/authenticator', {
		key: secret,
		token: totp(secret),
		userVerificationToken: setup.userVerificationToken,
		masterPasswordHash: hash,
	});
	await expect(loginWithPassword(client, email, password)).rejects.toBeInstanceOf(ApiError);
	let challenges = 0;
	const account = await loginWithPassword(client, email, password, undefined, {
		onTwoFactor: async challenge => {
			challenges++;
			expect(challenge.providers).toContain(0);
			await expect(challenge.requestEmail()).rejects.toThrow('unavailable');
			return { provider: 0, token: totp(secret, Date.now() + 30000) };
		},
	});
	expect(challenges).toBe(1);
	const unlocked = await unlockAccount(account, password);
	try {
		expect(unlocked.equals(userKey)).toBe(true);
	} finally {
		unlocked.fill(0);
	}
	const dir = await mkdtemp(join(tmpdir(), 'vw-live-challenge-'));
	const executable = fileURLToPath(import.meta.resolve('#main'));
	const run = (args: string[], importPassword?: string) =>
		runCapturedProcess(['node', executable, ...args], {
			env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir, VW_PASSWORD: password, VW_IMPORT_PASSWORD: importPassword },
		});
	try {
		expect(
			(await run(['config', 'server', server!, '--api', `${server}/api`, '--identity', `${server}/identity`])).code,
		).toBe(0);
		const missing = await run(['login', email, '--nointeraction']);
		expect(missing.code).toBe(1);
		expect(missing.stderr).toContain('Two-factor authentication is required');
		await waitForNextTotpWindow();
		const login = await run([
			'login',
			email,
			'--method',
			'0',
			'--code',
			totp(secret, Date.now() + 30000),
			'--nointeraction',
			'--raw',
		]);
		expect(login.code).toBe(0);
		expect(login.stdout.trim()).not.toBe('');
		expect(login.stderr.includes(password)).toBe(false);
		const portProbe = createServer();
		await new Promise<void>(resolve => portProbe.listen(0, '127.0.0.1', resolve));
		const address = portProbe.address();
		if (!address || typeof address === 'string') throw new Error('Could not reserve a local API port.');
		const servePort = address.port;
		await new Promise<void>((resolve, reject) => portProbe.close(error => error ? reject(error) : resolve()));
		const serving = spawn('node', [
			executable,
			'serve',
			'--hostname',
			'127.0.0.1',
			'--port',
			String(servePort),
			'--session',
			login.stdout.trim(),
		], {
			detached: true,
			env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir },
			stdio: ['ignore', 'ignore', 'pipe'],
		});
		const ready = Promise.withResolvers<string>();
		let diagnostic = '';
		serving.stderr?.setEncoding('utf8');
		serving.stderr?.on('data', (part: string) => {
			diagnostic += part;
			const address = diagnostic.match(/Listening on (http:\/\/127\.0\.0\.1:\d+)/);
			if (address) ready.resolve(address[1]!);
		});
		serving.once('error', error => ready.reject(error));
		serving.once('exit', () => ready.reject(new Error(`Local API exited before listening. ${diagnostic}`)));
		const deadline = setTimeout(() => ready.reject(new Error('Local API did not start.')), 5000);
		try {
			const base = await ready.promise;
			clearTimeout(deadline);
			const call = (path: string, method = 'GET', body?: unknown) =>
				fetch(`${base}${path}`, {
					method,
					headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
					body: body === undefined ? undefined : JSON.stringify(body),
					signal: AbortSignal.timeout(10000),
				});
			expect(await (await call('/status')).json()).toMatchObject({
				success: true,
				data: { object: 'template', template: { status: 'unlocked' } },
			});
			expect((await fetch(`${base}/status`, { headers: { Origin: '' } })).status).toBe(403);
			expect((await fetch(`${base}/status`, { headers: { Host: 'attacker.example' } })).status).toBe(403);
			const folder = await (await call('/object/folder', 'POST', { name: 'REST folder' })).json();
			expect(folder.success).toBe(true);
			const folderId = folder.data.id;
			expect((await (await call(`/object/folder/${folderId}`, 'PUT', { name: 'REST renamed' })).json()).success).toBe(
				true,
			);
			const created = await (await call('/object/item', 'POST', {
				type: 1,
				name: 'REST login',
				folderId,
				login: { username: 'rest-user', password: '  rest-secret  ', uris: [] },
			})).json();
			expect(created.success).toBe(true);
			const itemId = created.data.id;
			expect(await (await call(`/object/password/${itemId}`)).json()).toMatchObject({
				data: { object: 'string', data: '  rest-secret  ' },
			});
			expect(await (await call('/list/object/items?search=REST')).json()).toMatchObject({
				data: { object: 'list', data: [{ id: itemId }] },
			});
			const bytes = new Uint8Array(262144).fill(171), form = new FormData();
			form.set('file', new Blob([bytes]), 'REST binary.bin');
			const uploaded = await (await fetch(`${base}/attachment?itemid=${itemId}`, { method: 'POST', body: form }))
				.json();
			expect(uploaded.success).toBe(true);
			const attachmentId = uploaded.data.attachments[0].id;
			const attachment = await call(`/object/attachment/${attachmentId}?itemid=${itemId}`);
			expect(attachment.headers.get('Content-Type')).toBe('application/octet-stream');
			expect(Buffer.from(await attachment.arrayBuffer()).equals(bytes)).toBe(true);
			expect((await (await call(`/object/attachment/${attachmentId}?itemid=${itemId}`, 'DELETE')).json()).success)
				.toBe(true);
			const send = await (await call('/object/send', 'POST', {
				type: 0,
				name: 'REST Send',
				deletionDate: new Date(Date.now() + 86400000).toISOString(),
				text: { text: 'REST payload' },
			}))
				.json();
			expect(send.success).toBe(true);
			expect(await (await call('/send/list')).json()).toMatchObject({ data: { data: [{ id: send.data.id }] } });
			expect((await (await call(`/object/send/${send.data.id}`, 'DELETE')).json()).success).toBe(true);
			expect((await (await call(`/archive/item/${itemId}`, 'POST')).json()).success).toBe(true);
			expect(await (await call('/list/object/items?archived=true')).json()).toMatchObject({
				data: { data: [{ id: itemId }] },
			});
			expect((await (await call(`/restore/item/${itemId}`, 'POST')).json()).success).toBe(true);
			await call('/lock', 'POST');
			expect((await call('/list/object/items')).status).toBe(400);
			expect((await call('/sync', 'POST')).status).toBe(200);
			expect((await call('/unlock?passwordEnv=HOME', 'POST', {})).status).toBe(400);
			const restUnlock = await call('/unlock', 'POST', { password });
			expect(restUnlock.status).toBe(200);
			const restSession = (await restUnlock.json()).data.raw as string;
			if (process.env.VW_TEST_BW) {
				// Use an independent profile. Remove 2FA only on this disposable account,
				// so the reference login does not need to replay our already consumed OTP.
				// 1.37.5 binds the verification token to the authenticator's enabled state.
				const disable = await client.api(initial.accessToken, 'POST', '/two-factor/get-authenticator', {
					masterPasswordHash: hash,
				});
				expect(text(field(object(disable.authenticator ?? disable), 'key'))).toBe(secret);
				await client.api(initial.accessToken, 'DELETE', '/two-factor/authenticator', {
					masterPasswordHash: hash,
					key: secret,
					type: 0,
					userVerificationToken: disable.userVerificationToken,
				});
				const ca = join(dir, 'reference-ca.pem'), keyPath = join(dir, 'reference-key.pem');
				await writeTestCertificate(ca, keyPath);
				const proxy = Bun.serve({
					hostname: '127.0.0.1',
					port: 0,
					tls: { cert: Bun.file(ca), key: Bun.file(keyPath) },
					async fetch(request) {
						const target = new URL(request.url);
						const response = await fetch(`${server}${target.pathname}${target.search}`, {
							method: request.method,
							headers: { ...Object.fromEntries(request.headers), 'X-Forwarded-Proto': 'https' },
							body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
							redirect: 'manual',
						});
						return new Response(response.body, { status: response.status, headers: response.headers });
					},
				});
				try {
					const referenceDirectory = join(dir, 'reference');
					const official = async (args: string[], session?: string, importPassword?: string) => {
						const child = Bun.spawn([process.env.VW_TEST_BW!, ...args], {
							env: {
								PATH: process.env.PATH,
								BITWARDENCLI_APPDATA_DIR: referenceDirectory,
								BW_PASSWORD: password,
								NODE_EXTRA_CA_CERTS: ca,
								BW_SESSION: session,
								BW_IMPORT_PASSWORD: importPassword,
							},
							stdout: 'pipe',
							stderr: 'pipe',
							stdin: 'ignore',
						});
						const [code, stdout, stderr] = await Promise.all([
							child.exited,
							new Response(child.stdout).text(),
							new Response(child.stderr).text(),
						]);
						if (code) throw new Error(`Reference CLI failed: ${stderr}`);
						return stdout;
					};
					await official(['config', 'server', `https://127.0.0.1:${proxy.port}`]);
					const referenceSession =
						(await official(['login', email, '--passwordenv', 'BW_PASSWORD', '--raw', '--nointeraction'])).trim();
					if (process.env.VW_TEST_SKIP_IMPORTS === '1') {
						const filters = [
							['--folderid', folderId],
							['--folderid', 'null'],
							['--organizationid', 'null'],
							['--organizationid', 'notnull'],
							['--collectionid', 'null'],
							['--collectionid', 'notnull'],
							['--search', 'REST', '--folderid', folderId],
							['--search', 'no matching item', '--folderid', 'null'],
						];
						const ids = (source: string) =>
							(JSON.parse(source) as Record<string, unknown>[]).map(item => String(item.id)).sort();
						for (const filter of filters) {
							const own = await run(['list', 'items', ...filter, '--session', restSession]);
							if (own.code) throw new Error(`Custom CLI list filter failed (${filter.join(' ')}): ${own.stderr}`);
							const native = await official(['list', 'items', ...filter], referenceSession);
							expect(ids(own.stdout), `list items ${filter.join(' ')}`).toEqual(ids(native));
						}
						if (process.env.VW_TEST_LIST_FILTERS_ONLY === '1') return;
					}
					const prefix = `csv${randomUUID().replaceAll('-', '').slice(0, 8)}`;
					const csvCases: { format: string; rows: string[][] }[] = [
						{
							format: 'chromecsv',
							rows: [
								['name', 'url', 'username', 'password', 'note'],
								[`${prefix} Chrome`, 'https://example.com/a,b', 'alice', '  csv-secret  ', 'line1\nline2'],
								['', `android://hash@com.${prefix}.app/`, 'app-user', 'app-secret', ''],
							],
						},
						{
							format: 'firefoxcsv',
							rows: [
								['url', 'username', 'password'],
								[`https://www.${prefix}.example.com/login`, 'alice', 'csv-secret'],
								['chrome://FirefoxAccounts', 'internal', 'ignored'],
							],
						},
						{
							format: 'safaricsv',
							rows: [
								['Title', 'Url', 'Username', 'Password', 'Notes', 'OTPAuth'],
								[
									`${prefix} Safari`,
									'https://example.com',
									'alice',
									'csv-secret',
									'Safari notes',
									'otpauth://totp/example?secret=JBSWY3DPEHPK3PXP',
								],
							],
						},
						{
							format: 'keepassxcsv',
							rows: [
								['Group', 'Title', 'Username', 'Password', 'URL', 'Notes', 'TOTP'],
								[
									`Root/${prefix} Folder`,
									`${prefix} KeePass`,
									'alice',
									'csv-secret',
									'https://example.com/a,b',
									'KeePass notes',
									'JBSWY3DPEHPK3PXP',
								],
							],
						},
						{
							format: 'lastpasscsv',
							rows: [
								['url', 'username', 'password', 'extra', 'name', 'grouping', 'fav', 'totp'],
								[
									'https://example.com/a,b',
									'alice',
									'csv-secret',
									'Site notes',
									`${prefix} LastPass`,
									`${prefix} Folder`,
									'1',
									'JBSWY3DPEHPK3PXP',
								],
								[
									'http://sn',
									'',
									'',
									'NoteType:Credit Card\nNumber:4111111111111111\nName on Card:Alice\nSecurity Code:123\nExpiration Date:June,2030\nIssuer:Example\nNotes:card note\ncontinued:marker',
									`${prefix} Card`,
									`${prefix} Folder`,
									'0',
									'',
								],
								[
									'http://sn',
									'',
									'',
									'NoteType:Address\nFirst Name:Alice\nLast Name:Example\nUnknown:marker',
									`${prefix} Identity`,
									'(none)',
									'0',
									'',
								],
								['http://sn', '', '', 'NoteType:Generic\nNotes:entire text', `${prefix} Note`, '(none)', '0', ''],
							],
						},
						{
							format: 'lastpasscsv',
							rows: [
								['profilename', 'profilelanguage', 'ccname', 'ccnum', 'cccsc', 'ccexp'],
								[`${prefix} FormFill`, 'en', 'Alice', '4111111111111111', '123', '2030-06'],
							],
						},
					];
					csvCases.push({
						format: 'encryptrcsv',
						rows: [
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
							[
								`${prefix} Encryptr login`,
								'login note',
								'extra login text',
								'Password',
								'alice',
								'  encryptr-secret  ',
								'https://example.com',
								'',
								'',
								'',
								'',
							],
							[
								`${prefix} Encryptr card`,
								'card note',
								'extra card text',
								'Credit Card',
								'',
								'',
								'',
								'Alice Example',
								'4111111111111111',
								'123',
								'06/30',
							],
							[`${prefix} Encryptr note`, 'note body', 'extra note text', 'Secure Note', '', '', '', '', '', '', ''],
							[`${prefix} Encryptr empty login`, '', 'note from text', 'Password', '', '', '', '', '', '', ''],
						],
					});
					csvCases.push({
						format: 'passkeepcsv',
						rows: [
							['title', 'username', 'password', 'site', 'description', 'password2', 'category'],
							[
								`${prefix} PassKeep`,
								'alice',
								'  passkeep-secret  ',
								'https://example.com/passkeep',
								'PassKeep note',
								'backup-secret',
								`${prefix} PassKeep/Logins`,
							],
						],
					});
					csvCases.push({
						format: 'passwordwallettxt',
						rows: [[
							`${prefix} PasswordWallet`,
							'https://example.com/passwordwallet',
							'alice',
							'  passwordwallet-secret  ',
							'line one¬line two',
							`${prefix} PasswordWallet/Logins`,
						]],
					});
					csvCases.push({
						format: 'passpackcsv',
						rows: [
							['Tags', 'Entry Name', 'User ID', 'Password', 'URL', 'Notes', 'Shared Notes', 'Extra Fields'],
							[
								JSON.stringify({ tags: [JSON.stringify({ tag: `${prefix} Passpack folder` })] }),
								`${prefix} Passpack login`,
								'alice',
								'  passpack-secret  ',
								'https://example.com/passpack',
								'Private note',
								'Shared note',
								JSON.stringify({ extraFields: [JSON.stringify({ name: 'Answer', data: 'custom value' })] }),
							],
						],
					});
					csvCases.push({
						format: 'ascendocsv',
						rows: [[
							`${prefix} Ascendo`,
							'User Name',
							'alice',
							'Password',
							'  ascendo-secret  ',
							'Website',
							'https://example.com/ascendo',
							'Ascendo note',
						]],
					});
					csvCases.push({
						format: 'blackberrycsv',
						rows: [
							['name', 'grouping', 'fav', 'extra', 'url', 'username', 'password'],
							[
								`${prefix} BlackBerry`,
								'password',
								'1',
								'BlackBerry note',
								'https://example.com/blackberry',
								'alice',
								'secret',
							],
							[`${prefix} BlackBerry note`, 'note', '0', 'Secure note', '', '', ''],
							[`${prefix} BlackBerry list`, 'list', '0', '', '', '', ''],
						],
					});
					csvCases.push({
						format: 'blurcsv',
						rows: [
							['label', 'domain', 'email', 'username', 'password'],
							['null', `https://www.${prefix}.blur.example/path`, '', 'legacy user', '  blur-secret  '],
						],
					});
					csvCases.push({
						format: 'codebookcsv',
						rows: [[
							'Category',
							'Favorite',
							'Entry',
							'Note',
							'Username',
							'Email',
							'Password',
							'TOTP',
							'Website',
							'Phone',
							'PIN',
						], [
							`${prefix} Codebook`,
							'True',
							'Account',
							'Codebook note',
							'alice',
							'alice@example.com',
							'  codebook-secret  ',
							'JBSWY3DPEHPK3PXP',
							'https://example.com/codebook',
							'123456',
							'4321',
						]],
					});
					csvCases.push({
						format: 'avastcsv',
						rows: [
							['name', 'web', 'login', 'password'],
							[`${prefix} Avast`, 'https://example.com/avast', 'alice', '  avast-secret  '],
						],
					});
					csvCases.push({
						format: 'buttercupcsv',
						rows: [[
							'!group_id',
							'!group_name',
							'!type',
							'title',
							'username',
							'password',
							'URL',
							'note',
							'id',
							'Recovery Code',
						], [
							'g1',
							`${prefix} Buttercup`,
							'login',
							`${prefix} Buttercup entry`,
							'alice',
							'  buttercup-secret  ',
							'https://example.com/buttercup',
							'Buttercup notes',
							'id1',
							'backup',
						]],
					});
					csvCases.push({
						format: 'padlockcsv',
						rows: [
							['Name', 'Tags', 'username', 'website', 'password', 'Recovery'],
							[
								`${prefix} Padlock`,
								`${prefix} Padlock,${prefix} Shared`,
								'alice',
								'example.com/padlock',
								'secret',
								'backup',
							],
						],
					});
					csvCases.push({
						format: 'yoticsv',
						rows: [
							['Name', 'User name', 'Password', 'URL'],
							[`${prefix} Yoti`, 'alice', '  yoti-secret  ', 'https://example.com/yoti'],
						],
					});
					csvCases.push({
						format: 'saferpasscsv',
						rows: [
							['url', 'notes', 'username', 'password'],
							[`https://www.${prefix}.saferpass.example/login`, 'SaferPass note', 'alice', 'saferpass-secret'],
						],
					});
					csvCases.push({
						format: 'securesafecsv',
						rows: [
							['Title', 'Comment', 'Username', 'Password', 'Web URL'],
							[
								`${prefix} SecureSafe`,
								'SecureSafe note',
								'alice',
								'securesafe-secret',
								'https://example.com/securesafe',
							],
						],
					});
					csvCases.push({
						format: 'meldiumcsv',
						rows: [
							['DisplayName', 'Notes', 'UserName', 'Password', 'Url'],
							[`${prefix} Meldium`, 'Meldium note', 'alice', 'meldium-secret', 'https://example.com/meldium'],
						],
					});
					csvCases.push({
						format: 'truekeycsv',
						rows: [[
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
						], [
							'login',
							`${prefix} True Key login`,
							'',
							'true',
							'True Key login note',
							'',
							'alice',
							'  truekey-secret  ',
							'https://example.com/truekey',
							'',
							'',
							'',
							'',
							'',
						], [
							'cc',
							'',
							`${prefix} True Key card`,
							'false',
							'',
							'',
							'',
							'',
							'',
							'Alice Example',
							'4111111111111111',
							'2030-06-01',
							'',
							'',
						], [
							'note',
							'',
							`${prefix} True Key note`,
							'false',
							'',
							'Caption',
							'',
							'',
							'',
							'',
							'',
							'',
							'Document body',
							'note reference',
						]],
					});
					csvCases.push({
						format: 'splashidcsv',
						rows: [
							[
								'Web Logins',
								`${prefix} SplashID login`,
								'alice',
								'secret',
								'https://example.com/splashid',
								'recovery: 123',
								'owner: Alice',
								'tail note',
								`${prefix} SplashID folder`,
							],
							[
								'Secure Note',
								`${prefix} SplashID note`,
								'Note body',
								'ignored',
								'tail note',
								`${prefix} SplashID folder`,
							],
						],
					});
					csvCases.push({
						format: 'remembearcsv',
						rows: [[
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
						], [
							'LoginItem',
							'false',
							`${prefix} RememBear login`,
							'login notes',
							'https://example.com/remembear',
							'alice',
							'remembear-secret',
							'',
							'',
							'',
							'',
							'',
							'',
							'',
						], [
							'CreditCardItem',
							'false',
							`${prefix} RememBear card`,
							'card notes',
							'',
							'',
							'',
							'Alice Example',
							'4111111111111111',
							'123',
							'06',
							'2030',
							'9876',
							'12345',
						]],
					});
					csvCases.push({
						format: 'upmcsv',
						rows: [[`${prefix} UPM`, 'alice', 'secret', 'https://example.com/upm', 'UPM note']],
					});
					csvCases.push({
						format: 'logmeoncecsv',
						rows: [
							['name', 'username', 'password', 'url', 'group'],
							[
								`${prefix} LogMeOnce`,
								'alice',
								'  logmeonce-secret  ',
								'https://example.com/logmeonce',
								`${prefix} LogMeOnce folder`,
							],
						],
					});
					csvCases.push({
						format: 'mykicsv',
						rows: [
							['nickname', 'url', 'username', 'password', 'additionalInfo', 'twofaSecret', 'status', 'tags'],
							[
								`${prefix} Myki login`,
								'www.example.com',
								'alice',
								'myki-secret',
								'Account note',
								'JBSWY3DPEHPK3PXP',
								'active',
								'personal',
							],
						],
					});
					csvCases.push({
						format: 'mykicsv',
						rows: [[
							'nickname',
							'status',
							'tags',
							'cardNumber',
							'cardName',
							'exp_month',
							'exp_year',
							'cvv',
							'additionalInfo',
						], [
							`${prefix} Myki card`,
							'active',
							'personal',
							'4111111111111111',
							'Alice Example',
							'06',
							'30',
							'123',
							'Card note',
						]],
					});
					csvCases.push({
						format: 'msecurecsv',
						rows: [
							[
								`${prefix} mSecure login|810974637`,
								'Login',
								`${prefix} mSecure folder`,
								'',
								'Website|2|https://example.com/msecure',
								'Username|7|alice',
								'Password|8|  msecure-secret  ',
							],
							[
								`${prefix} mSecure card|155089404`,
								'Credit Card',
								`${prefix} mSecure folder`,
								'',
								'Card Number|12|4111111111111111',
								'Expiration Date|11|06/2030',
								'Security Code|9|123',
								'Name on Card|0|Alice Example',
								'PIN|9|1234',
								'Issuing Bank|0|Visa',
								'Phone Number|4|',
								'Billing Address|0|',
							],
							[
								`${prefix} mSecure note|155089405`,
								'Secure Note',
								`${prefix} mSecure folder`,
								'',
								'line one',
								'line two',
							],
						],
					});
					csvCases.push({
						format: 'passwordagentcsv',
						rows: [[
							`${prefix} Password Agent`,
							'alice',
							'  passwordagent-secret  ',
							'Password Agent note',
							'https://example.com/passwordagent',
							'',
							'',
							'',
							`${prefix} Password Agent/Logins`,
						]],
					});
					csvCases.push({
						format: 'dashlanecsv',
						rows: [[
							'username',
							'username2',
							'username3',
							'title',
							'password',
							'note',
							'url',
							'category',
							'otpSecret',
						], [
							'alice',
							'alternate',
							'',
							`${prefix} Dashlane login`,
							'  dashlane-secret  ',
							'login note',
							'https://example.com/dashlane',
							`${prefix} Dashlane folder`,
							'JBSWY3DPEHPK3PXP',
						]],
					});
					csvCases.push({
						format: 'dashlanecsv',
						rows: [[
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
						], [
							'bank',
							`${prefix} Dashlane bank`,
							'Alice Example',
							'',
							'',
							'',
							'',
							'123456789',
							'account-123',
							'US',
							'Example Bank',
						], [
							'credit_card',
							`${prefix} Dashlane card`,
							'',
							'4111111111111111',
							'321',
							'06',
							'2030',
							'',
							'',
							'US',
							'',
						]],
					});
					csvCases.push({
						format: 'dashlanecsv',
						rows: [
							[
								'type',
								'number',
								'name',
								'issue_date',
								'expiration_date',
								'place_of_issue',
								'state',
							],
							['card', 'ID12345', 'Alice Example', '2022-1-30', '2032-1-30', '', ''],
							['passport', 'P123456', 'Alice Example', '2022-1-30', '2032-1-30', 'Netherlands', ''],
							['license', 'L98765', 'Alice Example', '2022-8-10', '2032-10-10', '', 'CA'],
							['social_security', '123-45-6789', 'Alice Example', '', '', '', ''],
							['tax_number', 'TAX123', '', '', '', '', ''],
						],
					});
					csvCases.push({
						format: 'dashlanecsv',
						rows: [[
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
						], [
							'name',
							'Ms',
							'Alice',
							'Q',
							'Example',
							'alice',
							'1990-01-02',
							'Town',
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
						], [
							'email',
							'',
							'',
							'',
							'',
							'',
							'',
							'',
							'alice@example.com',
							'personal',
							`${prefix} email`,
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
						], [
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
							`${prefix} phone`,
							'+15551234567',
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
						], [
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
							`${prefix} address`,
							'',
							'One Street',
							'US',
							'CA',
							'Town',
							'12345',
							'Alice Example',
							'1',
							'2',
							'3',
							'1234',
							'',
							'',
						]],
					});
					csvCases.push({
						format: 'dashlanecsv',
						rows: [['title', 'note'], [`${prefix} Dashlane note`, 'Dashlane secure note']],
					});
					csvCases.push({
						format: 'enpasscsv',
						rows: [
							[
								`${prefix} Enpass login`,
								'Username',
								'alice',
								'E-mail',
								'alice@example.com',
								'*Password',
								'  enpass-csv-secret  ',
								'Website',
								'https://example.com/enpass-csv',
								'One-time code',
								'ENPASS_CSV_TOTP',
								'*Security answer',
								'42',
								'Enpass CSV login note',
							],
							[
								`${prefix} Enpass card`,
								'Cardholder',
								'Alice Example',
								'*Number',
								'4111111111111111',
								'Type',
								'Visa',
								'*CVC',
								'123',
								'Expiry date',
								'08/2030',
							],
							[`${prefix} Enpass note`, 'Enpass CSV secure note'],
						],
					});
					csvCases.push({
						format: 'passwordagentcsv',
						rows: [[
							'0',
							`${prefix} Password Agent alternate`,
							'bob',
							'alternate-secret',
							'https://example.com/passwordagent-alt',
							'Alternate note',
							'',
							'',
							'',
							`${prefix} Password Agent/Logins`,
						]],
					});
					csvCases.push({
						format: 'mykicsv',
						rows: [[
							'nickname',
							'status',
							'tags',
							'firstName',
							'middleName',
							'lastName',
							'email',
							'firstAddressLine',
							'secondAddressLine',
							'title',
							'gender',
							'number',
							'city',
							'country',
							'zipCode',
							'additionalInfo',
						], [
							`${prefix} Myki identity`,
							'active',
							'personal',
							'Alice',
							'Q',
							'Example',
							'alice@example.com',
							'One Street',
							'Unit 2',
							'Ms',
							'Female',
							'5551234',
							'Town',
							'Netherlands',
							'1234 AB',
							'Identity note',
						]],
					});
					csvCases.push({
						format: 'mykicsv',
						rows: [[
							'nickname',
							'status',
							'tags',
							'idType',
							'idNumber',
							'idName',
							'idIssuanceDate',
							'idExpirationDate',
							'idCountry',
							'additionalInfo',
						], [
							`${prefix} Myki passport`,
							'active',
							'personal',
							'Passport',
							'P123456',
							'Alice Q Example',
							'03/07/2022',
							'03/07/2028',
							'Netherlands',
							'Passport note',
						]],
					});
					csvCases.push({
						format: 'mykicsv',
						rows: [['nickname', 'status', 'content'], [`${prefix} Myki note`, 'active', 'Myki secure note']],
					});
					csvCases.push({
						format: 'mykicsv',
						rows: [
							['nickname', 'status', 'tags', 'authToken', 'additionalInfo'],
							[`${prefix} Myki 2FA`, 'active', 'personal', 'JBSWY3DPEHPK3PXP', 'Recovery note'],
						],
					});
					for (const format of ['edgecsv', 'operacsv', 'vivaldicsv', 'bravecsv']) {
						csvCases.push({ format, rows: csvCases.find(value => value.format === 'chromecsv')!.rows });
					}
					csvCases.push({ format: 'passboltcsv', rows: csvCases.find(value => value.format === 'lastpasscsv')!.rows });
					csvCases.push({
						format: 'arccsv',
						rows: [
							['name', 'url', 'username', 'password', 'note'],
							['Ignored title', `https://www.${prefix}.arc.example/a,b`, ' alice ', '  arc-secret  ', 'line1\nline2'],
						],
					});
					csvCases.push({
						format: 'aviracsv',
						rows: [
							['name', 'website', 'username', 'secondary_username', 'password'],
							[`${prefix} Avira`, 'example.com/a,b', ' alice ', 'alternate@example.com', '  avira-secret  '],
							['', `https://www.${prefix}.avira.example/path`, ' ', ' alternate ', 'secret'],
						],
					});
					const nordPassRecords: Record<string, string>[] = [
						{
							type: 'password',
							name: `${prefix} NordPass login`,
							username: ' alice ',
							password: '  nordpass-secret  ',
							url: 'example.com/a,b',
							additional_urls: JSON.stringify(['https://second.example', '']),
							folder: `\\${prefix} NordPass\\Web`,
							note: 'original notes',
							custom_fields: JSON.stringify([
								{ label: 'Hidden', type: 'hidden', value: ' literal ' },
								{ label: 'Long', type: 'text', value: 'x'.repeat(201) },
								{ label: 'Multiline', type: 'text', value: 'line1\r\nline2' },
							]),
						},
						{
							type: 'credit_card',
							name: `${prefix} NordPass card`,
							cardnumber: '4111111111111111',
							cardholdername: 'Alice',
							cvc: '123',
							expirydate: '06/30',
							folder: `${prefix} NordPass/Web`,
						},
						{
							type: 'identity',
							name: `${prefix} NordPass identity`,
							full_name: 'Alice Middle Last Name',
							address1: 'Street',
							address2: 'Unit',
							city: 'City',
							state: 'State',
							zipcode: '1234',
							country: 'nl',
							email: 'alice@example.com',
							phone_number: '123',
						},
						{ type: 'note', name: `${prefix} NordPass note`, note: 'first\nsecond' },
						{ type: 'unsupported', name: `${prefix} NordPass ignored`, folder: 'Ignored' },
					];
					const nordPassHeaders = [...new Set(nordPassRecords.flatMap(value => Object.keys(value)))];
					csvCases.push({
						format: 'nordpasscsv',
						rows: [nordPassHeaders, ...nordPassRecords.map(value => nordPassHeaders.map(key => value[key] ?? ''))],
					});
					const clean = (value: unknown): unknown =>
						Array.isArray(value) ? value.map(clean) : value && typeof value === 'object'
							? Object.fromEntries(
								Object.entries(value).filter(([, value]) => value != null).map(([key, value]) => [key, clean(value)]),
							)
							: value;
					const project = (items: Record<string, unknown>[], folders: Record<string, unknown>[]) =>
						items.map(item => {
							const login = item.login as Record<string, unknown> | undefined;
							return clean({
								name: item.name,
								type: item.type,
								notes: item.notes,
								favorite: item.favorite,
								reprompt: item.reprompt,
								passwordHistory: item.passwordHistory ?? [],
								archived: !!item.archivedDate,
								sshKey: item.sshKey
									? {
										publicKey: (item.sshKey as Record<string, unknown>).publicKey,
										keyFingerprint: (item.sshKey as Record<string, unknown>).keyFingerprint,
									}
									: undefined,
								fields: [...((item.fields ?? []) as Record<string, unknown>[])].sort((a, b) =>
									String(a.name).localeCompare(String(b.name))
								),
								folder: folders.find(folder => folder.id === item.folderId)?.name,
								login: login
									? {
										username: login.username,
										password: login.password,
										totp: login.totp,
										uris: (login.uris as Record<string, unknown>[] | undefined)?.map(uri => ({
											uri: uri.uri,
											match: uri.match,
										})) ?? [],
									}
									: undefined,
								secureNote: item.secureNote,
								card: item.card,
								identity: item.identity,
							});
						}).sort((a, b) =>
							String((a as Record<string, unknown>).name).localeCompare(String((b as Record<string, unknown>).name))
						);
					const importCases: {
						format: string;
						contents: string | Uint8Array;
						extension: string;
						search?: string;
						password?: string;
						keyFile?: string;
						compareNative?: boolean;
						archived?: boolean;
					}[] = csvCases.map(value => ({
						format: value.format,
						contents: writeCsv(value.rows),
						extension: 'csv',
					}));
					importCases.push({
						format: 'avastjson',
						extension: 'json',
						contents: JSON.stringify({
							logins: [{
								custName: `${prefix} Avast JSON login`,
								note: 'Avast JSON login note',
								url: 'https://example.com/avast-json',
								pwd: '  avast-json-secret  ',
								loginName: 'alice',
							}],
							notes: [{ label: `${prefix} Avast JSON note`, text: 'Avast JSON secure note' }],
							cards: [{
								custName: `${prefix} Avast JSON card`,
								note: 'Avast JSON card note',
								holderName: 'Alice Example',
								cardNumber: '4111111111111111',
								cvv: '123',
								expirationDate: { month: 6, year: 2030 },
							}],
						}),
					});
					importCases.push({
						format: 'enpassjson',
						extension: 'json',
						contents: JSON.stringify({
							folders: [
								{ uuid: 'parent', title: `${prefix} Enpass`, parent_uuid: '' },
								{ uuid: 'child', title: 'Social', parent_uuid: 'parent' },
							],
							items: [
								{
									title: `${prefix} Enpass login`,
									template_type: 'login.default',
									favorite: 1,
									folders: ['child'],
									note: 'Enpass login note',
									fields: [
										{ type: 'username', label: 'Username', value: 'enpass-user' },
										{ type: 'password', label: 'Password', value: '  enpass-secret  ', sensitive: 1 },
										{ type: 'totp', label: 'TOTP', value: 'ENPASS_TEST_SEED' },
										{ type: 'url', label: 'Website', value: 'https://example.com/enpass' },
										{ type: 'text', label: 'Recovery code', value: 'ENPASS_RECOVERY', sensitive: 1 },
									],
								},
								{
									title: `${prefix} Enpass note`,
									template_type: 'note.default',
									fields: [{ type: 'multiline', label: 'Details', value: 'private note detail' }],
								},
								{
									title: `${prefix} Enpass card`,
									template_type: 'creditcard.default',
									fields: [
										{ type: 'ccName', label: 'Name', value: 'Alice Example' },
										{ type: 'ccNumber', label: 'Number', value: '4111111111111111' },
										{ type: 'ccCvc', label: 'CVC', value: '321' },
										{ type: 'ccExpiry', label: 'Expiry', value: '08/30' },
									],
								},
							],
						}),
					});
					importCases.push({
						format: 'gnomejson',
						extension: 'json',
						search: prefix,
						contents: JSON.stringify({
							[`${prefix}/Browser`]: [
								{
									display_name: `https://${prefix}.example.test/login`,
									secret: '  gnome-json-secret  ',
									attributes: {
										username_value: 'gnome-user',
										'xdg:schema': 'org.gnome.Password',
										account: 'primary',
									},
								},
								{ display_name: 'not a URL', secret: 'ignored' },
							],
						}),
					});
					importCases.push({
						format: 'passmanjson',
						extension: 'json',
						search: prefix,
						contents: JSON.stringify([{
							label: `${prefix} Passman login`,
							username: 'passman-user',
							email: 'passman@example.test',
							password: '  passman-json-secret  ',
							url: `https://${prefix}.example.test/passman`,
							description: 'Passman description',
							otp: { secret: 'PASSMAN_TEST_SEED' },
							tags: [{ text: `${prefix}/Passman` }],
							custom_fields: [
								{ field_type: 'text', label: 'Recovery code', value: 'passman-recovery' },
								{ field_type: 'password', label: 'Custom secret', value: 'passman-custom-secret' },
							],
						}]),
					});
					importCases.push({
						format: 'passkyjson',
						extension: 'json',
						search: prefix,
						contents: JSON.stringify({
							encrypted: false,
							passwords: [{
								website: `https://${prefix}.example.test/passky`,
								username: 'passky-user',
								password: '  passky-json-secret  ',
								message: 'Passky note',
							}],
						}),
					});
					importCases.push({
						format: 'keeperjson',
						extension: 'json',
						search: prefix,
						contents: JSON.stringify({
							shared_folders: [{ path: `${prefix}\\Team` }],
							records: [
								{
									$type: 'login',
									uid: 'keeper-live-login',
									title: `${prefix} Keeper login`,
									login: 'keeper-user',
									password: '  keeper-json-secret  ',
									login_url: `https://${prefix}.example.test/keeper-json`,
									notes: 'Keeper JSON login note',
									custom_fields: {
										'$oneTimeCode': ['KEEPER_JSON_TEST_SEED'],
										'$text:Recovery code': 'keeper-json-recovery',
									},
									folders: [{ folder: `${prefix}/Keeper` }],
								},
								{
									$type: 'bankCard',
									title: `${prefix} Keeper card`,
									custom_fields: {
										'$text:cardholderName': 'Alice Example',
										'$paymentCard': {
											cardNumber: '4111111111111111',
											cardSecurityCode: '321',
											cardExpirationDate: '08/2031',
										},
									},
								},
							],
						}),
					});
					importCases.push({
						format: 'dashlanejson',
						extension: 'json',
						search: prefix,
						contents: JSON.stringify({
							AUTHENTIFIANT: [{
								title: `${prefix} Dashlane login`,
								login: 'dashlane-user',
								email: 'dashlane@example.test',
								password: '  dashlane-json-secret  ',
								domain: `https://${prefix}.example.test/dashlane`,
								note: 'Dashlane login note',
							}],
							ADDRESS: [{
								addressName: `${prefix} Dashlane address`,
								addressFull: '12 Example Road',
								city: 'Amsterdam',
								country: 'nl',
							}],
							IDENTITY: [{ fullName: `${prefix} Alice Example`, pseudo: 'dashlane-alice' }],
							PAYMENTMEANS_CREDITCARD: [{
								bank: 'Example Bank',
								owner: 'Alice Example',
								cardNumber: '4111111111111111',
							}],
						}),
					});
					importCases.push({
						format: 'passwordxpcsv',
						extension: 'csv',
						search: prefix,
						contents: writeCsv([
							['Title', 'Username', 'URL', 'Password', 'Description', 'Account', 'Private'],
							[`[${prefix}/PasswordXP]`, '', '', '', '', '', ''],
							[
								`${prefix} PasswordXP login`,
								'passwordxp-user',
								`https://${prefix}.example.test/passwordxp`,
								'  passwordxp-secret  ',
								'PasswordXP login note',
								'checking',
								'private',
							],
							[`${prefix} PasswordXP note`, '', '', '', 'PasswordXP note body', 'reference', ''],
						]),
					});
					importCases.push({
						format: 'delineaxml',
						extension: 'xml',
						search: prefix,
						contents:
							`<?xml version="1.0"?><Export><ImportFile><Folders><Folder><FolderPath>${prefix}/Delinea XML</FolderPath></Folder></Folders><Secrets>
<Secret><SecretName>${prefix} Delinea XML login</SecretName><FolderPath>${prefix}/Delinea XML</FolderPath><SecretItems>
<SecretItem><Slug>username</Slug><Value>delinea-xml-user</Value></SecretItem><SecretItem><Slug>password</Slug><Value>  delinea-xml-secret  </Value></SecretItem>
<SecretItem><Slug>url</Slug><Value>https://${prefix}.example.test/delinea-xml</Value></SecretItem><SecretItem><Slug>notes</Slug><Value>Delinea XML login note</Value></SecretItem>
<SecretItem><Slug>Recovery code</Slug><Value>delinea-xml-recovery</Value></SecretItem></SecretItems></Secret>
<Secret><SecretName>${prefix} Delinea XML note</SecretName><SecretItems><SecretItem><Slug>password</Slug><Value>note-password</Value></SecretItem>
<SecretItem><Slug>notes</Slug><Value>Delinea XML secure note</Value></SecretItem></SecretItems></Secret></Secrets></ImportFile></Export>`,
					});
					importCases.push({
						format: 'netwrixpasswordsecure',
						extension: 'csv',
						search: prefix,
						contents: [
							'Organisationseinheit;Beschreibung;Benutzername;Passwort;Website;Informationen;One-Time Passwort;DataTags',
							`${prefix}/Netwrix;${prefix} Netwrix login;netwrix-user;"  netwrix-secret  ";https://${prefix}.example.test/netwrix;Netwrix note;NETWRIX_LIVE_TEST;private-tag`,
						].join('\r\n'),
					});
					importCases.push({
						format: 'passwordbossjson',
						extension: 'json',
						search: prefix,
						// bw 2026.10.0 rejects both known flat-array export shapes before upload.
						compareNative: false,
						contents: JSON.stringify([
							{
								itemType: 'Login',
								itemTypeName: 'Login',
								folder: `${prefix}/Password Boss`,
								name: `${prefix} Password Boss login`,
								email: 'passwordboss-user',
								password: '  passwordboss-secret  ',
								url: `https://${prefix}.example.test/passwordboss`,
								notes: 'Password Boss login note',
								customFields: [{ name: 'Recovery', value: 'passwordboss-recovery' }],
								tags: [],
							},
							{
								itemTypeName: 'CreditCard',
								name: `${prefix} Password Boss card`,
								cardNumber: '4111111111111111',
								nameOnCard: 'Alice Example',
								securityCode: '321',
								expirationDate: '2031-08-31T23:59:59Z',
							},
						]),
					});
					importCases.push({
						format: 'passworddragonxml',
						extension: 'xml',
						search: prefix,
						contents: `<?xml version="1.0"?><PasswordManager><record><Category>${prefix}/Password Dragon</Category>
<Account-Name>${prefix} Password Dragon login</Account-Name><User-Id>passworddragon-user</User-Id>
<Password>  passworddragon-secret  </Password><URL>https://${prefix}.example.test/passworddragon</URL>
<Notes>Password Dragon login note</Notes><Attribute-1>passworddragon-recovery</Attribute-1></record></PasswordManager>`,
					});
					importCases.push({
						format: 'delineacsv',
						extension: 'csv',
						search: prefix,
						contents: writeCsv([
							['Secret Name', 'URL', 'Username', 'Password', 'Notes', 'Folder', 'Custom'],
							[
								`${prefix} Delinea login`,
								`https://${prefix}.example.test/delinea`,
								'delinea-user',
								'  delinea-secret  ',
								'Delinea login note',
								`${prefix}/Delinea`,
								'delinea-private-field',
							],
							[
								`${prefix} Delinea note`,
								'',
								'',
								'note-password',
								'Delinea secure note',
								`${prefix}/Delinea`,
								'note-ref',
							],
						]),
					});
					importCases.push({
						format: 'zohovaultcsv',
						extension: 'csv',
						search: prefix,
						contents: writeCsv([
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
								`${prefix} Zoho login`,
								'Fallback name',
								'1',
								'Zoho entry note',
								`https://${prefix}.example.test/zoho`,
								'',
								'',
								'ZOHO_TEST_SEED',
								'Username: zoho-user\nPassword:  zoho-secret\nService: personal',
								'Password: custom-password',
								`${prefix}/Zoho`,
							],
							[
								'',
								`${prefix} Zoho note`,
								'0',
								'Zoho secure note',
								'',
								'',
								'',
								'',
								'SecretType: note\nReference: zoho-note',
								'',
								`${prefix}/Zoho`,
							],
						]),
					});
					importCases.push({
						format: 'roboformcsv',
						extension: 'csv',
						search: prefix,
						contents: writeCsv([
							[
								'Name',
								'Login',
								'Pwd',
								'Password',
								'Url',
								'URL',
								'Folder',
								'Note',
								'Rf_fields',
								'RfFieldsV2',
							],
							[
								`${prefix} RoboForm legacy`,
								'legacy-user',
								'',
								'legacy-secret',
								'',
								`https://${prefix}.example.test/robo-legacy`,
								`/${prefix}/RoboForm`,
								'RoboForm legacy note',
								'Color:label:blue',
								'',
								'Recovery:code:rck:unused',
							],
							[
								`${prefix} RoboForm V2`,
								'main-user',
								'main-secret',
								'',
								`https://${prefix}.example.test/robo-v2`,
								'',
								`${prefix}/RoboForm`,
								'',
								'',
								'TOTP KEY$,Name,totp,text,ROBOFORM_TEST_SEED',
								'User ID$,Name,user,text,alternate-user',
								'User ID$,Name,user,text,main-user',
								'Password$,Name,pwd,pwd,alternate-secret',
								'Password$,Name,pwd,pwd,main-secret',
							],
						]),
					});
					importCases.push({
						format: 'keepercsv',
						extension: 'csv',
						search: prefix,
						contents: writeCsv([
							[
								`${prefix}/Keeper`,
								`${prefix} Keeper login`,
								'keeper-user',
								'  keeper-secret  ',
								`https://${prefix}.example.test/keeper`,
								'Keeper note',
								'Shared ignored',
								'TFC:Keeper',
								'KEEPER_TEST_SEED',
								'Recovery code',
								'keeper-recovery',
							],
						]),
					});
					importCases.push({
						format: 'kasperskytxt',
						extension: 'txt',
						search: prefix,
						contents: [
							'Websites',
							'',
							'',
							'---',
							`Website name: ${prefix} Kaspersky login`,
							'Login name: Web',
							`Website URL: https://${prefix}.example.test/kaspersky`,
							'Login: kaspersky-user',
							'Password:   kaspersky-secret  ',
							'Comment: Kaspersky login note',
							'Applications',
							'',
							'',
							'---',
							`Application: ${prefix} Kaspersky app`,
							'Login: app-user',
							'Password: app-secret',
							'Notes',
							'',
							'',
							'---',
							`Name: ${prefix} Kaspersky note`,
							'Text: note body',
						].join('\n'),
					});
					importCases.push({
						format: 'keepass2xml',
						extension: 'xml',
						contents: `<?xml version="1.0" encoding="utf-8"?>
<KeePassFile><Meta><Binaries><Binary ID="0">aWdub3JlZA==</Binary></Binaries></Meta><Root><Group><Name>Ignored root</Name>
<Entry><String><Key>Title</Key><Value>${prefix} XML root</Value></String><String><Key>Password</Key><Value>  xml-secret  </Value></String>
<History><Entry><String><Key>Title</Key><Value>${prefix} XML history must not import</Value></String></Entry></History></Entry>
<Group><Name>${prefix} XML folder</Name><Entry><String><Key>Title</Key><Value><![CDATA[${prefix} Café <login>]]></Value></String>
<String><Key>UserName</Key><Value>alice</Value></String><String><Key>URL</Key><Value>example.com/a,b</Value></String>
<String><Key>otp</Key><Value>key=JBSWY3DPEHPK3PXP</Value></String><String><Key>Notes</Key><Value>first&#10;second</Value></String>
<String><Key>Private</Key><Value ProtectInMemory="True">${'hidden\n' + 'x'.repeat(220)}</Value></String>
<String><Key>Multiline</Key><Value>line1&#10;line2</Value></String><String><Key>Literal</Key><Value>one&amp;two</Value></String></Entry>
<Group><Name>Nested</Name><Entry><String><Key>Title</Key><Value>${prefix} XML nested</Value></String></Entry></Group>
</Group><Group><Name/><Entry><String><Key>Title</Key><Value>${prefix} XML empty folder</Value></String></Entry></Group>
</Group></Root></KeePassFile>`,
					});
					for (const kind of ['aes3', 'aes4', 'argon2d', 'argon2id']) {
						const file = new URL(`./fixtures/kdbx/${kind}.kdbx`, import.meta.url);
						const key = kind === 'aes4' ? 'keyfile-v2.bin' : kind === 'argon2d' ? 'keyfile-raw.bin' : undefined;
						importCases.push({
							format: 'keepasskdbx',
							extension: 'kdbx',
							contents: await readFile(file),
							search: 'KDBX compatibility',
							password: kind === 'argon2d' ? undefined : 'synthetic-database-password',
							keyFile: key ? new URL(`./fixtures/kdbx/${key}`, import.meta.url).pathname : undefined,
							compareNative: kind !== 'argon2d',
						});
					}
					importCases.push({
						format: '1password1pux',
						extension: '1pux',
						search: '1PUX compatibility',
						archived: true,
						contents: await readFile(new URL('./fixtures/onepassword/synthetic.1pux', import.meta.url)),
					});
					const selected = process.env.VW_TEST_IMPORT_FORMAT?.split(',');
					for (
						const [format, file, search] of [
							['1password1pif', 'legacy.1pif', '1PIF compatibility'],
							['1passwordmaccsv', 'mac.csv', 'Legacy CSV compatibility'],
							['1passwordwincsv', 'windows.csv', 'Legacy CSV compatibility'],
						]
					) {
						importCases.push({
							format: format!,
							extension: file!.split('.').at(-1)!,
							search,
							contents: await readFile(new URL(`./fixtures/onepassword/${file}`, import.meta.url)),
						});
					}
					if (selected?.some(format => !importCases.some(value => value.format === format))) {
						throw new Error('Unknown test import format.');
					}
					const shard = process.env.VW_TEST_IMPORT_SHARD;
					const shardMatch = shard?.match(/^(\d+)\/(\d+)$/);
					if (shard && (!shardMatch || Number(shardMatch[1]) >= Number(shardMatch[2]) || Number(shardMatch[2]) < 1)) {
						throw new Error('VW_TEST_IMPORT_SHARD must use the form index/count.');
					}
					const shardFormats = shardMatch
						? [...new Set(importCases.map(value => value.format))].filter((_, index) =>
							index % Number(shardMatch[2]) === Number(shardMatch[1])
						)
						: undefined;
					// The managed compatibility runner uses a disposable server and account.
					// Address imported records by ID instead of spawning a CLI process
					// to delete every item and folder after every importer case.
					const importedItemIds = new Set<string>();
					for (const [index, importCase] of importCases.entries()) {
						if (process.env.VW_TEST_SKIP_IMPORTS === '1') continue;
						if (selected && !selected.includes(importCase.format)) continue;
						if (shardFormats && !shardFormats.includes(importCase.format)) continue;
						console.log(`Comparing external import: ${importCase.format}`);
						const search = importCase.search ?? prefix;
						const input = join(dir, `external-${index}.${importCase.extension}`);
						await writeFile(input, importCase.contents, { mode: 0o600 });
						const credentials = importCase.keyFile ? ['--keyfile', importCase.keyFile] : [];
						const imported = await run(
							['import', importCase.format, input, '--session', restSession, ...credentials],
							importCase.password,
						);
						if (imported.code) throw new Error(`External import failed (${importCase.format}): ${imported.stderr}`);
						const own = ((await (await call(`/list/object/items?search=${encodeURIComponent(search)}`)).json()).data
							.data as Record<
								string,
								unknown
							>[]).filter(item => !importedItemIds.has(String(item.id)));
						if (importCase.archived) {
							own.push(
								...(await (await call(`/list/object/items?archived=true&search=${encodeURIComponent(search)}`)).json())
									.data.data.filter((item: Record<string, unknown>) => !importedItemIds.has(String(item.id))),
							);
							expect(own).toHaveLength(11);
							expect(JSON.parse(imported.stdout).errors).toEqual([{ id: 'bad-ssh', reason: 'sshKeyParseFailed' }]);
						}
						const ownFolders = (await (await call('/list/object/folders')).json()).data.data as Record<
							string,
							unknown
						>[];
						const expected = project(own, ownFolders);
						if (importCase.format === 'keepasskdbx') expect(own).toHaveLength(2);
						for (const item of own) importedItemIds.add(String(item.id));
						// The reference CLI requires a nonempty password before calling its SDK.
						if (importCase.compareNative === false) continue;
						const passwordArgs = importCase.password ? ['--passwordenv', 'BW_IMPORT_PASSWORD', '--nointeraction'] : [];
						try {
							await official(
								['import', importCase.format, input, ...credentials, ...passwordArgs],
								referenceSession,
								importCase.password,
							);
						} catch (error) {
							throw new Error(
								`Reference import failed (${importCase.format}): ${error instanceof Error ? error.message : error}`,
							);
						}
						const native =
							(JSON.parse(await official(['list', 'items', '--search', search], referenceSession)) as Record<
								string,
								unknown
							>[]).filter(item => !importedItemIds.has(String(item.id)));
						if (importCase.archived) {
							native.push(
								...(JSON.parse(
									await official(['list', 'items', '--archived', '--search', search], referenceSession),
								) as Record<string, unknown>[]).filter(item => !importedItemIds.has(String(item.id))),
							);
						}
						const nativeFolders = JSON.parse(await official(['list', 'folders'], referenceSession));
						expect(project(native, nativeFolders)).toEqual(expected);
						for (const item of native) importedItemIds.add(String(item.id));
					}
					if (selected || shardFormats) return;
					const reservation = createServer();
					await new Promise<void>(resolve => reservation.listen(0, '127.0.0.1', resolve));
					const address = reservation.address();
					if (!address || typeof address === 'string') throw new Error('Missing reference listener address.');
					const referencePort = address.port;
					await new Promise<void>(resolve => reservation.close(() => resolve()));
					const reference = spawn(process.env.VW_TEST_BW!, [
						'serve',
						'--hostname',
						'127.0.0.1',
						'--port',
						String(referencePort),
					], {
						detached: true,
						env: {
							PATH: process.env.PATH,
							BITWARDENCLI_APPDATA_DIR: referenceDirectory,
							BW_SESSION: referenceSession,
							NODE_EXTRA_CA_CERTS: ca,
						},
						stdio: ['ignore', 'ignore', 'pipe'],
					});
					let referenceDiagnostic = '';
					reference.stderr?.setEncoding('utf8');
					reference.stderr?.on('data', (part: string) => {
						referenceDiagnostic += part;
					});
					const referenceBase = `http://127.0.0.1:${referencePort}`;
					const referenceRequest = (path: string, init: RequestInit = {}) =>
						fetch(`${referenceBase}${path}`, {
							...init,
							signal: init.signal ?? AbortSignal.timeout(10000),
						});
					try {
						const deadline = Date.now() + 15000;
						let ready = false;
						while (
							Date.now() < deadline && reference.exitCode === null && reference.signalCode === null
						) {
							try {
								if ((await referenceRequest('/status', { signal: AbortSignal.timeout(500) })).ok) {
									ready = true;
									break;
								}
							} catch { /* Wait for the known child to bind. */ }
							await Bun.sleep(50);
						}
						if (!ready) {
							throw new Error(
								`Reference Serve did not become ready (exit ${reference.exitCode}, signal ${reference.signalCode}): `
									+ referenceDiagnostic,
							);
						}
						const nativeStatus = await (await referenceRequest('/status')).json();
						const ownStatus = await (await call('/status')).json();
						expect(ownStatus.data.object).toBe(nativeStatus.data.object);
						expect(ownStatus.data.template.status).toBe(nativeStatus.data.template.status);
						const nativeItem = await (await referenceRequest(`/object/item/${itemId}`)).json();
						const ownItem = await (await call(`/object/item/${itemId}`)).json();
						expect(ownItem.data.object).toBe(nativeItem.data.object);
						expect(ownItem.data.id).toBe(nativeItem.data.id);
						expect(ownItem.data.login.password).toBe(nativeItem.data.login.password);
						expect(ownItem.data).not.toHaveProperty('key');
						const referenceItemData = { ...nativeItem.data };
						delete referenceItemData.key;
						expect(ownItem.data).toEqual(referenceItemData);
						expect(
							await (await call(`/object/item/${itemId}`, 'PUT', { ...ownItem.data, name: 'REST revision round-trip' }))
								.json(),
						).toMatchObject({ success: true, data: { name: 'REST revision round-trip' } });
						expect(await (await call(`/object/password/${itemId}`)).json()).toEqual(
							await (await referenceRequest(`/object/password/${itemId}`)).json(),
						);
						const errorRequests: [string, string, unknown?][] = [
							['GET', '/list/object/missing'],
							['GET', '/object/missing/synthetic-id'],
							['POST', '/object/missing', {}],
							['DELETE', '/object/missing/synthetic-id'],
							['GET', '/object/item/00000000-0000-0000-0000-000000000099'],
							['GET', '/object/folder/no-such-folder'],
							['GET', '/object/collection/no-such-collection'],
							['GET', '/object/organization/no-such-organization'],
							['GET', '/object/password/00000000-0000-0000-0000-000000000099'],
						];
						for (const [method, path, body] of errorRequests) {
							const [nativeError, ownError] = await Promise.all([
								referenceRequest(path, {
									method,
									...(body === undefined ? {} : {
										headers: { 'Content-Type': 'application/json' },
										body: JSON.stringify(body),
									}),
								}),
								call(path, method, body),
							]);
							expect(ownError.status).toBe(nativeError.status);
							expect(await ownError.json()).toEqual(await nativeError.json());
						}
						const fileSend = {
							type: 1,
							name: 'Unsupported through REST',
							deletionDate: new Date(Date.now() + 86400000).toISOString(),
							file: { fileName: 'synthetic-path-that-must-not-be-opened' },
						};
						const ownRejected = await call('/object/send', 'POST', fileSend);
						expect(ownRejected.status).toBe(400);
						expect(await ownRejected.json()).toEqual({
							success: false,
							message: 'Creating a file-based Send is unsupported through the `serve` command at this time.',
						});
						for (const names of [['file', 'file'], ['file', 'unexpected']] as const) {
							const makeForm = () => {
								const form = new FormData();
								for (const [index, name] of names.entries()) {
									form.append(name, new Blob([`synthetic upload ${index}`]), `probe-${index}.bin`);
								}
								return form;
							};
							const nativeUpload = await referenceRequest(`/attachment?itemid=${itemId}`, {
								method: 'POST',
								body: makeForm(),
							});
							const ownUpload = await fetch(`${base}/attachment?itemid=${itemId}`, {
								method: 'POST',
								body: makeForm(),
								signal: AbortSignal.timeout(10000),
							});
							expect(nativeUpload.ok).toBe(false);
							expect(ownUpload.status).toBe(400);
							const ownAfter = await (await call(`/object/item/${itemId}`)).json();
							const nativeAfter = await (await referenceRequest(`/object/item/${itemId}`)).json();
							expect(ownAfter.data.attachments).toEqual(ownItem.data.attachments);
							expect(nativeAfter.data.attachments).toEqual(nativeItem.data.attachments);
						}
					} finally {
						if (reference.pid !== undefined) {
							try {
								process.kill(process.platform === 'win32' ? reference.pid : -reference.pid, 'SIGTERM');
							} catch { /* The reference process group has already exited. */ }
						}
						if (reference.exitCode === null && reference.signalCode === null) {
							await new Promise<void>(resolve => reference.once('exit', () => resolve()));
						}
					}
				} finally {
					proxy.stop(true);
				}
			}
			expect((await call(`/object/item/${itemId}?permanent=true`, 'DELETE')).status).toBe(200);
			expect((await call(`/object/folder/${folderId}`, 'DELETE')).status).toBe(200);
		} finally {
			clearTimeout(deadline);
			if (serving.pid !== undefined) {
				try {
					process.kill(process.platform === 'win32' ? serving.pid : -serving.pid, 'SIGTERM');
				} catch { /* The local API process group has already exited. */ }
			}
			if (serving.exitCode === null && serving.signalCode === null) {
				await new Promise<void>(resolve => serving.once('exit', () => resolve()));
			}
		}
		expect((await run(['config', 'server', server!])).code).toBe(1);
		expect((await run(['logout'])).code).toBe(0);
	} finally {
		userKey.fill(0);
		await rm(dir, { recursive: true, force: true });
	}
}, 600000);
