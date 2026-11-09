import { fileURLToPath } from 'node:url';
import { deriveMasterKey, encrypt, masterPasswordHash, stretchKey } from '@kjanat/vaultwarden';
import { expect, test } from 'bun:test';
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writeTestCertificate } from '#test/fixtures/tls';
import { registrationVerificationToken } from '#test/fixtures/registration';

const server = process.env.VW_TEST_SERVER;
const live = server ? test : test.skip;

live('focused external import matches the independent bw importer', async () => {
	const format = process.env.VW_TEST_IMPORT_FORMAT;
	if (
		![
			'safeincloudxml',
			'psonojson',
			'pwsafexml',
			'stickypasswordxml',
			'clipperzhtml',
			'passworddepot17xml',
			'fsecurefsk',
			'protonpass',
			'passwordbossjson',
			'passworddragonxml',
		].includes(format ?? '')
	) {
		throw new Error('Focused importer suite received an unsupported format.');
	}
	if (!server || !process.env.VW_TEST_BW) throw new Error('Live importer comparison requires Vaultwarden and bw.');
	const directory = await mkdtemp(join(tmpdir(), 'vw-import-live-'));
	const referenceDirectory = join(directory, 'reference'), ca = join(directory, 'reference-ca.pem');
	const keyPath = join(directory, 'reference-key.pem');
	const password = 'Synthetic-import-fixture-password-123!';
	const email = `import-fixture-${randomUUID()}@example.com`;
	const prefix = `Import fixture ${randomUUID().replaceAll('-', '').slice(0, 8)}`;
	const kdf = { type: 0, iterations: 600000 } as const;
	const master = await deriveMasterKey(password, email, kdf);
	const hash = await masterPasswordHash(master, password), userKey = randomBytes(64), stretched = stretchKey(master);
	const wrapped = encrypt(userKey, stretched);
	master.fill(0);
	stretched.fill(0);
	const spawnCli = async (executable: string, profile: string, args: string[], extra: Record<string, string> = {}) => {
		const command = /\.[cm]?[jt]s$/.test(executable) ? ['node', executable, ...args] : [executable, ...args];
		const child = Bun.spawn(command, {
			env: {
				PATH: process.env.PATH,
				VW_APPDATA_DIR: profile,
				BITWARDENCLI_APPDATA_DIR: profile,
				BW_PASSWORD: password,
				NODE_EXTRA_CA_CERTS: ca,
				...extra,
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
		if (code !== 0) throw new Error(`CLI ${args[0]} failed: ${stderr}`);
		return stdout;
	};
	let proxy: ReturnType<typeof Bun.serve> | undefined;
	try {
		const verify = await fetch(`${server}/identity/accounts/register/send-verification-email`, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ email, name: prefix }),
		});
		expect(verify.status).toBe(200);
		const pair = generateKeyPairSync('rsa', {
			modulusLength: 2048,
			publicKeyEncoding: { type: 'spki', format: 'der' },
			privateKeyEncoding: { type: 'pkcs8', format: 'der' },
		});
		try {
			const registered = await fetch(`${server}/identity/accounts/register/finish`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					email,
					name: prefix,
					masterPasswordHash: hash,
					key: wrapped,
					keys: {
						publicKey: pair.publicKey.toString('base64'),
						encryptedPrivateKey: encrypt(pair.privateKey, userKey),
					},
					kdf: kdf.type,
					kdfIterations: kdf.iterations,
					emailVerificationToken: await registrationVerificationToken(verify),
				}),
			});
			expect(registered.status).toBe(200);
		} finally {
			pair.privateKey.fill(0);
		}
		await writeTestCertificate(ca, keyPath);
		proxy = Bun.serve({
			hostname: '127.0.0.1',
			port: 0,
			tls: { cert: Bun.file(ca), key: Bun.file(keyPath) },
			async fetch(request) {
				const target = new URL(request.url);
				return await fetch(`${server}${target.pathname}${target.search}`, {
					method: request.method,
					headers: { ...Object.fromEntries(request.headers), 'X-Forwarded-Proto': 'https' },
					body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
					redirect: 'manual',
				});
			},
		});
		const official = process.env.VW_TEST_BW;
		const own = join(directory, 'own');
		const ownExecutable = fileURLToPath(import.meta.resolve('#main'));
		await spawnCli(ownExecutable, own, ['config', 'server', server]);
		const ownSession = (await spawnCli(ownExecutable, own, [
			'login',
			email,
			'--passwordenv',
			'BW_PASSWORD',
			'--raw',
			'--nointeraction',
		])).trim();
		await spawnCli(official, referenceDirectory, ['config', 'server', `https://127.0.0.1:${proxy.port}`]);
		const referenceSession = (await spawnCli(official, referenceDirectory, [
			'login',
			email,
			'--passwordenv',
			'BW_PASSWORD',
			'--raw',
			'--nointeraction',
		])).trim();
		const safeInCloud = `<?xml version="1.0"?><database>
<card title="${prefix} Login" star="true"><field name="Username" type="login">alice</field>
<field name="Password" type="password">  safeincloud-secret  </field><field name="Website" type="website">example.test</field>
<field name="OTP" type="one_time_password">SAFEIN_TEST_SEED</field><notes>safeincloud note</notes></card>
<card title="${prefix} Card"><field name="Name" autofill="cc-name">Alice Example</field>
<field name="Number" autofill="cc-number">4111111111111111</field><field name="Expiry" autofill="cc-exp">06/2030</field></card>
			<card title="${prefix} Note" type="note"><notes>secure note contents</notes></card>
</database>`;
		const psono = JSON.stringify({
			items: [{
				type: 'website_password',
				website_password_title: `${prefix} Psono login`,
				website_password_notes: 'Psono note',
				website_password_username: 'psono-user',
				website_password_password: 'psono-secret',
				website_password_url: 'psono.example.test',
			}],
			folders: [{
				name: `${prefix} Psono folder`,
				items: [{ type: 'note', note_title: `${prefix} Psono secure note`, note_notes: 'folder note' }],
			}],
		});
		const passwordSafe = `<?xml version="1.0"?><passwordsafe delimiter="~"><entry>
<group>${prefix}.Password Safe</group><title>${prefix} Password Safe login</title><username>psafe-user</username>
<email>psafe@example.test</email><password>psafe-secret</password><url>psafe.example.test</url><notes>first~second</notes>
</entry><entry><title>${prefix} Password Safe email fallback</title><email>fallback@example.test</email></entry></passwordsafe>`;
		const stickyPassword = `<?xml version="1.0"?><root><Database><Logins>
<Login ID="${prefix}-login" Name="sticky-user" Password="sticky-secret"/></Logins><Accounts>
<Account Name="${prefix} Sticky login" Link="sticky.example.test" ParentID="${prefix}-group" Comments="first/nsecond">
<LoginLinks><Login SourceLoginID="${prefix}-login"/></LoginLinks></Account></Accounts><Groups>
<Group ID="${prefix}-group" Name="${prefix} Group"/></Groups></Database></root>`;
		const clipperz = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://dtd.example.com/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><body><textarea>${
	JSON.stringify([{
		label: `${prefix} Clipperz login \uE009 Username`,
		data: { notes: 'first\\nsecond' },
		currentVersion: {
			fields: {
				username: { actionType: 'username', value: 'clipperz-user' },
				password: { actionType: 'password', value: 'clipperz-secret' },
				url: { actionType: 'url', value: 'clipperz.example.test' },
			},
		},
	}, {
		label: `${prefix} Clipperz note`,
		data: { notes: 'clipperz secure note' },
		currentVersion: { fields: {} },
	}]).replaceAll('&', '&amp;').replaceAll('<', '&lt;')
}</textarea></body></html>`;
		const passwordDepot =
			`<?xml version="1.0"?><passwordfile><header><version>17.0</version><encrypted>False</encrypted></header>
<favorites>${
	Buffer.from(`${prefix}-favorite`).toString('base64')
}</favorites><passwords><group fingerprint="${prefix}-group" name="${prefix} Depot folder">
<item><type>0</type><description>${prefix} Password Depot login</description><comment>Depot note</comment><fingerprint>${prefix}-favorite</fingerprint>
<username>depot-user</username><password>depot-secret</password><url>depot.example.test</url><customfields>
<field><name>Recovery</name><value>depot-recovery</value><type>2</type></field></customfields></item>
<item><type>1</type><description>${prefix} Password Depot card</description><customfields>
<field name="IDS_CardHolder" value="Alice Example"/><field name="IDS_CardNumber" value="4111111111111111"/>
<field name="IDS_CardExpires" value="06/2030"/><field name="IDS_CardCode" value="123"/></customfields></item>
</group></passwords></passwordfile>`;
		const fsecure = JSON.stringify({
			data: {
				login: {
					type: 1,
					service: `${prefix} F-Secure login`,
					username: 'fsecure-user',
					password: 'fsecure-secret',
					url: 'fsecure.example.test',
					notes: 'F-Secure note',
					favorite: 1700000000,
				},
				card: {
					type: 2,
					service: `${prefix} F-Secure card`,
					username: 'Alice Example',
					creditNumber: '4111111111111111',
					creditCvv: '123',
					creditExpiry: '06/2030',
					password: '4321',
					notes: 'Card note',
					favorite: 0,
				},
			},
		});
		const protonPass = JSON.stringify({
			version: '1.0',
			userId: 'fixture-user',
			encrypted: false,
			vaults: {
				personal: {
					name: `${prefix} Proton vault`,
					items: [
						{
							state: 1,
							pinned: true,
							data: {
								type: 'login',
								metadata: { name: `${prefix} Proton login`, note: 'Proton login note' },
								content: {
									itemUsername: 'proton-user',
									itemEmail: 'proton@example.test',
									password: 'proton-secret',
									urls: ['proton.example.test'],
									totpUri: 'otpauth://totp/proton',
								},
								extraFields: [{ fieldName: 'Recovery', type: 'text', data: { content: 'proton-recovery' } }],
							},
						},
						{
							state: 1,
							pinned: false,
							data: {
								type: 'creditCard',
								metadata: { name: `${prefix} Proton card` },
								content: {
									cardholderName: 'Alice Example',
									number: '4111111111111111',
									verificationNumber: '123',
									expirationDate: '2030-06-01',
									pin: '5678',
								},
								extraFields: [],
							},
						},
						{
							state: 1,
							pinned: false,
							data: {
								type: 'note',
								metadata: { name: `${prefix} Proton note`, note: 'Proton secure note' },
								content: {},
								extraFields: [{ fieldName: 'Note field', type: 'hidden', data: { content: 'hidden-note-value' } }],
							},
						},
						{
							state: 2,
							data: { type: 'note', metadata: { name: `${prefix} Proton trashed` }, content: {}, extraFields: [] },
						},
					],
				},
			},
		});
		const passwordBoss = JSON.stringify({
			folders: [{ id: 'password-boss-folder', name: `${prefix} Password Boss folder` }],
			items: [
				{
					type: 'Login',
					name: `${prefix} Password Boss login`,
					folder: 'password-boss-folder',
					login_url: 'boss.example.test',
					identifiers: {
						email: 'boss@example.test',
						password: 'boss-secret',
						notes: 'Password Boss note',
						custom_fields: [{ name: 'Recovery', value: 'boss-recovery' }],
					},
				},
				{
					type: 'CreditCard',
					name: `${prefix} Password Boss card`,
					identifiers: {
						cardNumber: '4111111111111111',
						nameOnCard: 'Alice Example',
						security_code: '123',
						expires: '2030-06-01T00:00:00Z',
					},
				},
			],
		});
		const passwordDragon = `<?xml version="1.0"?><PasswordManager><record>
<Category>${prefix} Password Dragon/Bank</Category><Account-Name>${prefix} Password Dragon login</Account-Name>
<User-Id>dragon-user</User-Id><Password>dragon-secret</Password><URL>dragon.example.test</URL>
<Notes>Password Dragon note</Notes><Attribute-1>dragon-recovery</Attribute-1>
</record></PasswordManager>`;
		const input = join(
			directory,
			`external.${
				['psonojson', 'fsecurefsk', 'protonpass', 'passwordbossjson'].includes(format!)
					? 'json'
					: format === 'clipperzhtml'
					? 'html'
					: 'xml'
			}`,
		);
		const contents = format === 'psonojson'
			? psono
			: format === 'fsecurefsk'
			? fsecure
			: format === 'protonpass'
			? protonPass
			: format === 'passwordbossjson'
			? passwordBoss
			: format === 'passworddragonxml'
			? passwordDragon
			: format === 'pwsafexml'
			? passwordSafe
			: format === 'stickypasswordxml'
			? stickyPassword
			: format === 'clipperzhtml'
			? clipperz
			: format === 'passworddepot17xml'
			? passwordDepot
			: safeInCloud;
		await writeFile(input, contents, { mode: 0o600 });
		const compare = async (executable: string, profile: string, session: string) => {
			await spawnCli(executable, profile, ['import', format!, input, '--session', session]);
			const listed = JSON.parse(
				await spawnCli(executable, profile, [
					'list',
					'items',
					'--search',
					prefix,
					'--session',
					session,
				]),
			) as Record<string, unknown>[];
			const folders = JSON.parse(
				await spawnCli(executable, profile, ['list', 'folders', '--search', prefix, '--session', session]),
			) as Record<string, unknown>[];
			const normalized = listed.map(item => ({
				name: item.name,
				type: item.type,
				favorite: item.favorite,
				notes: typeof item.notes === 'string'
					? format === 'safeincloudxml'
						? item.notes
						: item.notes.replace(/\r?\n$/, '')
					: null,
				folder: folders.find(folder => folder.id === item.folderId)?.name ?? null,
				fields: [...((item.fields ?? []) as Record<string, unknown>[])].sort((a, b) =>
					String(a.name).localeCompare(String(b.name))
				),
				login: item.login && typeof item.login === 'object'
					? {
						username: (item.login as Record<string, unknown>).username ?? null,
						password: (item.login as Record<string, unknown>).password ?? null,
						totp: (item.login as Record<string, unknown>).totp ?? null,
						uris: ((item.login as Record<string, unknown>).uris as Record<string, unknown>[] ?? []).map(uri => ({
							uri: uri.uri ?? null,
							match: uri.match ?? null,
						})),
					}
					: null,
				card: item.card ?? null,
				secureNote: item.secureNote ?? null,
			})).sort((a, b) => String(a.name).localeCompare(String(b.name)));
			return {
				normalized,
				ids: listed.map(item => String(item.id)),
				folderIds: folders.map(folder => String(folder.id)),
			};
		};
		const ownResult = await compare(ownExecutable, own, ownSession);
		for (const id of ownResult.ids) {
			await spawnCli(ownExecutable, own, ['delete', 'item', id, '--permanent', '--session', ownSession]);
		}
		for (const id of ownResult.folderIds) {
			await spawnCli(ownExecutable, own, ['delete', 'folder', id, '--session', ownSession]);
		}
		const referenceResult = await compare(official, referenceDirectory, referenceSession);
		expect(ownResult.normalized).toEqual(referenceResult.normalized);
	} finally {
		proxy?.stop(true);
		userKey.fill(0);
		await rm(directory, { recursive: true, force: true });
	}
}, 180000);
