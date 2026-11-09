#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runDirect } from '../runtime.mjs';

const sdkName = '@kjanat/vaultwarden';
const cliName = '@kjanat/vaultwarden-cli';

export function runConsumerSmoke(runtime, consumer, expectedSdkVersion, cli) {
	consumer = resolve(consumer);
	execFileSync(runtime, [fileURLToPath(import.meta.url)], {
		cwd: consumer,
		stdio: 'inherit',
		env: { ...process.env, CONSUMER_DIRECTORY: consumer, EXPECTED_SDK_VERSION: expectedSdkVersion, EXPECTED_CLI: cli },
	});
}

function resolveInstallation(consumer, cli) {
	const requireFromConsumer = createRequire(resolve(consumer, 'package.json'));
	const installed = resolve(consumer, 'node_modules') + sep;
	const vw = resolve(consumer, 'node_modules/.bin/vw');
	const inside = path => {
		assert(path.startsWith(installed), `Package resolved outside the consumer installation: ${path}`);
		return path;
	};
	switch (cli) {
		case 'direct': {
			const cliPath = inside(requireFromConsumer.resolve(`${cliName}/package.json`));
			return { cliPath, sdkPath: inside(createRequire(cliPath).resolve(sdkName)), vw };
		}
		case 'optional': {
			const sdkPath = inside(requireFromConsumer.resolve(sdkName));
			const cliPath = inside(createRequire(sdkPath).resolve(`${cliName}/package.json`));
			assert.equal(createRequire(cliPath).resolve(sdkName), sdkPath, 'The optional CLI must use the installed SDK');
			return { cliPath, sdkPath, vw };
		}
		case 'omitted': {
			const sdkPath = inside(requireFromConsumer.resolve(sdkName));
			let cliPath;
			try {
				cliPath = createRequire(sdkPath).resolve(`${cliName}/package.json`);
			} catch (error) {
				if (error?.code !== 'MODULE_NOT_FOUND') throw error;
			}
			assert(!cliPath?.startsWith(installed), `${cliName} must be absent: ${cliPath}`);
			assert(!existsSync(vw), `vw must be absent: ${vw}`);
			return { sdkPath };
		}
		default:
			assert.fail(`Unknown CLI installation: ${cli}`);
	}
}

export async function smokeConsumer({ consumer, expectedSdkVersion, cli }) {
	const { cliPath, sdkPath, vw } = resolveInstallation(consumer, cli);
	const sdkUrl = pathToFileURL(sdkPath);
	const fixtures = new URL('../../apps/cli/test/fixtures/kdbx/', import.meta.url);
	const sdk = createRequire(sdkPath)(`${sdkName}/package.json`);
	const OriginalModule = WebAssembly.Module;
	let wasmCompilations = 0;
	WebAssembly.Module = new Proxy(OriginalModule, {
		construct(target, args) {
			wasmCompilations++;
			return Reflect.construct(target, args);
		},
	});
	try {
		const {
			SDK_VERSION,
			VaultwardenClient,
			decrypt,
			deriveMasterKey,
			encrypt,
			matchesUri,
			parseExternalCsv,
			parseKdbx,
			passwordHealth,
			passwordStrength,
			stretchKey,
		} = await import(sdkUrl.href);
		assert.equal(wasmCompilations, 0, 'SDK import must not compile WASM');

		assert.equal(SDK_VERSION, sdk.version);
		assert.equal(sdk.version, expectedSdkVersion);
		// Exercise both packed lookup tables, including PSL private rules and exceptions.
		for (
			const [stored, target, expected] of [
				['login.example.co.uk', 'example.co.uk', true],
				['login.city.kawasaki.jp', 'city.kawasaki.jp', true],
				['a.foo.kawasaki.jp', 'b.foo.kawasaki.jp', false],
				['alice.github.io', 'bob.github.io', false],
			]
		) {
			assert.equal(await matchesUri({ uri: `https://${stored}` }, `https://${target}`), expected);
		}
		const htmlImport = parseExternalCsv(
			'lastpasscsv',
			'<!doctype html><html><body><pre>url,username,password,extra,name,grouping,fav\nhttps://example.com,alice,secret,&lt;notes&gt;,Tea &amp; Coffee,Personal,1</pre></body></html>',
		);
		assert.equal(htmlImport.items[0].name, 'Tea & Coffee');
		assert.equal(htmlImport.items[0].notes, '<notes>');
		assert.equal(htmlImport.items[0].login.password, 'secret');
		if (cliPath) {
			const cliManifest = JSON.parse(await readFile(cliPath, 'utf8'));
			for (const [command, expected] of [['--version', cliManifest.version], ['sdk-version', sdk.version]]) {
				const output = execFileSync(process.execPath, [vw, command], { cwd: consumer, encoding: 'utf8' });
				assert.equal(output.trim(), expected);
			}
		}

		const password = '67t9b5g67$%Dh89n';
		// Exercise the packaged WASM asset under every consumer runtime, with no network.
		assert.equal(passwordStrength('password'), 0);
		const scorerCompilations = wasmCompilations;
		assert(scorerCompilations > 0, 'The first score must initialize WASM');
		assert.equal(passwordStrength('VeryStrong123@#'), 4);
		assert.equal(passwordStrength('asdfjkhkjwer!', 'ASDFJKHKJWER@example.test'), 1);
		assert.equal(passwordStrength('🔑'.repeat(100) + 'NeverScored'), passwordStrength('🔑'.repeat(100)));
		const health = await passwordHealth([
			{ id: 'score-fixture', type: 1, name: 'Score fixture', login: { password: 'password' } },
		], { checkExposed: false });
		assert.equal(health[0].passwordStrength, 0);
		assert.equal(health[0].exposed, false);
		assert.equal(wasmCompilations, scorerCompilations, 'Repeated scores reuse the component');
		WebAssembly.Module = OriginalModule;
		for (
			const [kdf, expected] of [
				[{ type: 0, iterations: 10000 }, '1f4f68e29647b15ac250acd1118184518aa745a7fe95021b27c5402a16c3564b'],
				[
					{ type: 1, iterations: 4, memory: 32, parallelism: 2 },
					'cff0e1b1a213a34c626ab3afe00911f01493ed2ff6968db83ee183f23335e1f2',
				],
			]
		) {
			const master = await deriveMasterKey(password, '  TEST_KEY ', kdf);
			assert.equal(master.toString('hex'), expected);
			const key = stretchKey(master);
			const ciphertext = encrypt(Buffer.from('runtime fixture'), key);
			assert.equal(decrypt(ciphertext, key).toString(), 'runtime fixture');
			assert.throws(() => decrypt(ciphertext, Buffer.alloc(64, 8)), /authentication/);
			master.fill(0);
			key.fill(0);
		}

		for (
			const [fixture, keyFile] of [
				['aes3', undefined],
				['aes4', 'keyfile-v2.bin'],
				['argon2d', 'keyfile-raw.bin'],
				['argon2id', undefined],
			]
		) {
			const document = await parseKdbx(await readFile(new URL(`${fixture}.kdbx`, fixtures)), {
				password: fixture === 'argon2d' ? undefined : 'synthetic-database-password',
				keyFile: keyFile ? await readFile(new URL(keyFile, fixtures)) : undefined,
			});
			assert.equal(document.items.length, 2);
			const root = document.items.find(item => item.name === 'KDBX compatibility root');
			assert.equal(root?.notes, 'exact\tnotes\nsecond line');
			assert.equal(root?.login.password, '  synthetic-secret  ');
		}

		// Exercise actual HTTP and fetch under each runtime with an isolated protocol fixture.
		const requests = [];
		let fixtureError;
		const server = createServer(async (request, response) => {
			try {
				requests.push(request.url);
				const chunks = [];
				for await (const chunk of request) chunks.push(chunk);
				const body = Buffer.concat(chunks).toString();
				let data;
				switch (request.url) {
					case '/identity/accounts/prelogin':
						assert.equal(JSON.parse(body).email, 'fixture@example.test');
						data = { kdf: 0, kdfIterations: 10000 };
						break;
					case '/identity/connect/token':
						assert.equal(new URLSearchParams(body).get('grant_type'), 'password');
						assert.equal(new URLSearchParams(body).get('password'), 'synthetic-password-hash');
						data = {
							access_token: 'synthetic-access',
							refresh_token: 'synthetic-refresh',
							expires_in: 3600,
							key: 'synthetic-key',
						};
						break;
					case '/api/sync?excludeDomains=false':
						assert.equal(request.headers.authorization, 'Bearer synthetic-access');
						data = { profile: { id: 'runtime-fixture' }, ciphers: [] };
						break;
					default:
						throw new Error(`Unexpected fixture request: ${request.url}`);
				}
				response.writeHead(200, { 'Content-Type': 'application/json' });
				response.end(JSON.stringify(data));
			} catch (error) {
				fixtureError = error;
				response.writeHead(500);
				response.end('{}');
			}
		});
		await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
		try {
			const client = new VaultwardenClient(`http://127.0.0.1:${server.address().port}`);
			assert.deepEqual(await client.prelogin(' Fixture@Example.Test '), { type: 0, iterations: 10000 });
			const login = await client.login('fixture@example.test', 'synthetic-password-hash');
			assert.equal(login.encryptedUserKey, 'synthetic-key');
			assert.deepEqual(await client.sync(login.accessToken), { profile: { id: 'runtime-fixture' }, ciphers: [] });
			assert.equal(fixtureError, undefined);
			assert.deepEqual(requests, [
				'/identity/accounts/prelogin',
				'/identity/connect/token',
				'/api/sync?excludeDomains=false',
			]);
		} finally {
			await new Promise(resolve => server.close(resolve));
		}
		console.log(
			`Installed packages verified: ${process.versions.bun ? 'Bun' : 'Node'} ${
				process.versions.bun ?? process.version
			} / ${process.arch}; CLI ${cli}; password-strength WASM, crypto, KDBX workers, login and sync.`,
		);
	} finally {
		WebAssembly.Module = OriginalModule;
	}
}

if (import.meta.main) await runDirect(['release', 'smoke'], import.meta.url, { smokeConsumer });
