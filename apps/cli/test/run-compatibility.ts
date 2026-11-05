#!/usr/bin/env bun
import { randomUUID } from 'node:crypto';
import { appendFile, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';
import { loopbackPorts, startMailpit } from '#test/fixtures/mailpit';
import { assertStableVersion, resolveCompatibilityTarget, type CompatibilityTargets } from '#test/compatibility-plan';
import { runDirect } from '../../../tools/runtime.mjs';

export interface CompatibilityOptions {
	version?: string;
	image?: string;
	reference?: string;
	referenceVersion?: string;
	protocolOnly?: boolean;
	smtp?: boolean;
	sso?: boolean;
	testCase?: string;
	importFormat?: string;
	importShard?: string;
	skipImports?: boolean;
	listFiltersOnly?: boolean;
	policyRedactionOnly?: boolean;
	focusedImport?: boolean;
}

export async function runCompatibility(options: CompatibilityOptions = {}) {
	const {
		servers: compatibilityTargets,
		referenceIncompatibilities,
	} = await Bun
		.file(
			new URL('./fixtures/compatibility-targets.json', import.meta.url),
		).json() as CompatibilityTargets;

	const version = options.version ?? '1.37.4';
	if (process.platform === 'win32') throw new Error('The managed compatibility runner requires POSIX process groups.');
	const { image } = resolveCompatibilityTarget({ servers: compatibilityTargets }, version, options.image);
	const reference = options.reference;
	let expectedReferenceVersion = options.referenceVersion;
	if (expectedReferenceVersion !== undefined) assertStableVersion(expectedReferenceVersion);
	const protocolOnly = options.protocolOnly ?? false;
	const smtpEnabled = options.smtp ?? false;
	const ssoEnabled = options.sso ?? false;
	if ((ssoEnabled || smtpEnabled) && process.platform !== 'linux') {
		throw new Error('The SMTP and SSO fixtures require Linux host networking.');
	}
	let compareReference = !protocolOnly && !smtpEnabled && !ssoEnabled;
	if (compareReference && (!reference || !isAbsolute(reference) || !(await stat(reference)).isFile())) {
		throw new Error(
			'--reference must name an absolute path to the independent bw executable; use --protocol-only to run without it.',
		);
	}
	if (!Bun.which('envctl')) throw new Error('Compatibility runner requires envctl for Docker output redaction.');
	for (const command of ['docker', 'node', 'ssh-keygen']) {
		if (!Bun.which(command)) throw new Error(`Compatibility runner requires ${command}.`);
	}
	const directory = await mkdtemp(join(tmpdir(), 'vw-compat-run-'));
	const name = `vw-compat-${randomUUID()}`;
	let mailpit: Awaited<ReturnType<typeof startMailpit>> | undefined;
	let mailpitFailed = false;
	let mailApi: string | undefined;
	let mailSmtpPort: number | undefined;
	let oidc: ReturnType<typeof Bun.spawn> | undefined;
	let oidcUrl: string | undefined, hostServer: string | undefined;
	const oidcControl = randomUUID();
	let interrupted = false;
	const cancellation = new AbortController();
	const running = new Set<ChildProcess>();
	const stopTests = () => {
		for (const child of running) {
			if (child.pid) {
				try {
					process.kill(-child.pid, 'SIGTERM');
				} catch { /* The owned process group has already exited. */ }
			}
		}
	};
	const interrupt = () => {
		interrupted = true;
		cancellation.abort();
		stopTests();
	};
	process.on('SIGINT', interrupt);
	process.on('SIGTERM', interrupt);

	async function redact(output: string): Promise<string> {
		const safe = Bun.spawn(['envctl', 'redact'], {
			stdin: Buffer.from(output),
			stdout: 'pipe',
			stderr: 'pipe',
		});
		const [code, stdout] = await Promise.all([
			safe.exited,
			new Response(safe.stdout).text(),
			new Response(safe.stderr).text(),
		]);
		if (code !== 0) throw new Error(`envctl redaction failed (exit ${code}); Mailpit output was withheld.`);
		return stdout;
	}

	/** Docker output reaches the caller only after envctl; neither raw stream is displayed or saved. */
	async function docker(args: string[]): Promise<{ code: number; output: string }> {
		const child = Bun.spawn(['docker', ...args], { stdout: 'pipe', stderr: 'pipe' });
		const safe = Bun.spawn(['envctl', 'redact'], { stdin: 'pipe', stdout: 'pipe', stderr: 'pipe' });
		const stdout = new Response(safe.stdout).text(), stderr = new Response(safe.stderr).text();
		await Promise.all([
			child.stdout.pipeTo(
				new WritableStream({
					write(chunk) {
						safe.stdin.write(chunk);
					},
				}),
			),
			child.stderr.pipeTo(
				new WritableStream({
					write(chunk) {
						safe.stdin.write(chunk);
					},
				}),
			),
		]);
		safe.stdin.end();
		const [code, redacted, redactorCode, redactorError] = await Promise.all([
			child.exited,
			stdout,
			safe.exited,
			stderr,
		]);
		if (redactorCode !== 0) {
			throw new Error(`envctl redaction failed (exit ${redactorCode}); Docker output was withheld. ${redactorError}`);
		}
		return { code, output: redacted };
	}
	let exitCode: number | undefined;
	try {
		if (compareReference) {
			const referenceVersion = Bun.spawn([reference!, '--version'], {
				env: { PATH: process.env.PATH, BITWARDENCLI_APPDATA_DIR: directory },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 30000,
			});
			const [code, stdout] = await Promise.all([
				referenceVersion.exited,
				new Response(referenceVersion.stdout).text(),
				new Response(referenceVersion.stderr).text(),
			]);
			if (code !== 0) throw new Error('Could not read the reference CLI version.');
			const actual = stdout.trim();
			assertStableVersion(actual);
			if (expectedReferenceVersion !== undefined && actual !== expectedReferenceVersion) {
				throw new Error(`Reference executable must be bw ${expectedReferenceVersion}; got ${actual}.`);
			}
			expectedReferenceVersion = actual;
		}
		const node = Bun.spawn(['node', '--version'], { env: { PATH: process.env.PATH }, stdout: 'pipe', stderr: 'pipe' });
		const [nodeCode, nodeVersion] = await Promise.all([
			node.exited,
			new Response(node.stdout).text(),
			new Response(node.stderr).text(),
		]);
		if (nodeCode !== 0 || !/^v\d+\.\d+\.\d+$/.test(nodeVersion.trim())) {
			throw new Error('Could not identify Node executable.');
		}
		console.log(`Vaultwarden ${version}: ${image}`);
		console.log(`Node ${nodeVersion.trim()}; Bun ${Bun.version}`);
		console.log(
			ssoEnabled
				? 'SSO suite: synthetic OIDC provider and CLI login.'
				: smtpEnabled
				? 'SMTP suite: library and CLI login; no reference CLI required.'
				: compareReference
				? `Reference: ${reference} (${expectedReferenceVersion})`
				: 'Protocol-only suite: CLI against Vaultwarden; independent bw comparison disabled.',
		);
		if (smtpEnabled) {
			mailpit = await startMailpit({ signal: cancellation.signal, redact });
			mailApi = mailpit.apiUrl;
			mailSmtpPort = mailpit.smtpPort;
			const fixture = mailpit;
			void fixture.exited.then(() => {
				if (!fixture.stopping && !interrupted) {
					mailpitFailed = true;
					stopTests();
				}
			});
			console.log(`SMTP receiver: Mailpit pid ${mailpit.pid}; capture-only on loopback.`);
		}
		if (ssoEnabled) {
			oidc = Bun.spawn(['bun', new URL('./fixtures/oidc-provider.ts', import.meta.url).pathname], {
				env: { PATH: process.env.PATH, VW_OIDC_CONTROL: oidcControl },
				stdout: 'pipe',
				stderr: 'inherit',
			});
			const reader = (oidc.stdout as ReadableStream<Uint8Array>).getReader();
			const first = await reader.read();
			oidcUrl = new TextDecoder().decode(first.value).trim();
			reader.releaseLock();
			if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(oidcUrl)) throw new Error('OIDC fixture did not start.');
		}
		if (ssoEnabled || smtpEnabled) {
			const [port] = await loopbackPorts(1);
			hostServer = `http://127.0.0.1:${port}`;
		}
		const started = await docker([
			'run',
			'-d',
			'--name',
			name,
			...(hostServer
				? [
					'--network',
					'host',
					'-e',
					'ROCKET_ADDRESS=127.0.0.1',
					'-e',
					`ROCKET_PORT=${new URL(hostServer).port}`,
					'-e',
					`DOMAIN=${hostServer}`,
					...(ssoEnabled
						? [
							'-e',
							'SSO_ENABLED=true',
							'-e',
							'SSO_ONLY=true',
							'-e',
							'SSO_CLIENT_ID=fixture-client',
							'-e',
							'SSO_CLIENT_SECRET=synthetic-oidc-secret',
							'-e',
							`SSO_AUTHORITY=${oidcUrl}`,
						]
						: []),
				]
				: ['-p', '127.0.0.1::80']),
			'-e',
			'I_REALLY_WANT_VOLATILE_STORAGE=true',
			'-e',
			'SIGNUPS_ALLOWED=true',
			'-e',
			'SIGNUPS_VERIFY=false',
			'-e',
			'LOGIN_RATELIMIT_MAX_BURST=10000',
			'-e',
			'UNAUTHENTICATED_RATELIMIT_MAX_BURST=10000',
			...(smtpEnabled
				? [
					'-e',
					'SMTP_HOST=127.0.0.1',
					'-e',
					`SMTP_PORT=${mailSmtpPort}`,
					'-e',
					'SMTP_SECURITY=off',
					'-e',
					'SMTP_FROM=no-reply@example.com',
				]
				: []),
			image,
		]);
		if (started.code !== 0) throw new Error(`Could not start fixture server: ${started.output}`);
		console.log(`Fixture container: ${name}`);
		let server = hostServer;
		if (!server) {
			const port = await docker(['port', name, '80/tcp']);
			const address = port.output.trim();
			if (port.code !== 0 || !/^127\.0\.0\.1:\d+$/.test(address)) {
				throw new Error('Could not discover disposable loopback port.');
			}
			server = `http://${address}`;
		}
		const deadline = Date.now() + 60000;
		let ready = false;
		while (Date.now() < deadline && !interrupted) {
			try {
				const response = await fetch(`${server}/alive`, { signal: AbortSignal.timeout(1000) });
				if (response.ok) {
					ready = true;
					break;
				}
			} catch { /* The known container is still starting. */ }
			await Bun.sleep(200);
		}
		if (!ready) throw new Error('Disposable Vaultwarden did not become healthy.');
		if (interrupted) throw new Error('Compatibility run interrupted.');
		const actualVersion = await fetch(`${server}/api/version`, { signal: AbortSignal.timeout(5000) });
		if (!actualVersion.ok || await actualVersion.json() !== version) {
			throw new Error(`Disposable image does not report the planned Vaultwarden version ${version}.`);
		}
		if (compareReference) {
			const expected = referenceIncompatibilities.find(entry =>
				entry.server === version
				&& entry.referenceCliVersion === expectedReferenceVersion
			);
			const probe = spawn('bun', ['test', 'test/reference-authentication-live.test.ts'], {
				detached: true,
				cwd: new URL('..', import.meta.url).pathname,
				env: {
					PATH: process.env.PATH,
					VW_TEST_SERVER: server,
					VW_TEST_BW: reference,
					VW_TEST_REFERENCE_DIRECTORY: directory,
					VW_TEST_REFERENCE_FAILURE: expected?.error,
				},
				stdio: 'inherit',
			});
			running.add(probe);
			const code = await new Promise<number>((resolve, reject) => {
				probe.once('error', reject);
				probe.once('exit', code => resolve(code ?? 130));
			}).finally(() => running.delete(probe));
			if (code !== 0) throw new Error('Reference authentication tests failed.');
			compareReference = expected === undefined;
			const summary = `Vaultwarden ${version} / bw ${expectedReferenceVersion}: ${
				compareReference
					? 'PBKDF2 and Argon2id login passed; running comparisons.'
					: `Expected reference login failures (${
						expected!.error
					}); continuing Vaultwarden protocol tests without reference comparisons.`
			}`;
			console.log(summary);
			if (process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY, `${summary}\n`);
		}
		const cwd = new URL('..', import.meta.url).pathname;
		const env = {
			PATH: process.env.PATH,
			VOLTA_HOME: process.env.VOLTA_HOME,
			VW_TEST_SERVER: server,
			VW_TEST_VERSION: version,
			VW_TEST_BW: compareReference ? reference : undefined,
			VW_TEST_BW_VERSION: compareReference ? expectedReferenceVersion : undefined,
			VW_TEST_IMPORT_FORMAT: options.importFormat,
			VW_TEST_IMPORT_SHARD: undefined as string | undefined,
			VW_TEST_SKIP_IMPORTS: undefined as string | undefined,
			VW_TEST_LIST_FILTERS_ONLY: options.listFiltersOnly ? '1' : undefined,
			VW_TEST_POLICY_REDACTION_ONLY: options.policyRedactionOnly ? '1' : undefined,
			VW_TEST_FOCUSED_IMPORT: options.focusedImport ? '1' : undefined,
			VW_TEST_MAILPIT: mailApi,
			VW_TEST_OIDC: oidcUrl,
			VW_OIDC_CONTROL: ssoEnabled ? oidcControl : undefined,
		};
		const testArgs = (files: string[]) => {
			const args = ['bun', 'test', ...files];
			if (options.testCase) args.push('--test-name-pattern', options.testCase);
			return args;
		};
		const shardImportMatrix = compareReference && !options.focusedImport && !ssoEnabled
			&& !smtpEnabled
			&& !options.testCase && !options.importFormat && !options.importShard
			&& !options.skipImports;
		const runs: { files: string[]; shard?: string; skipImports?: boolean }[] = options.importShard
			? [{ files: ['test/challenge-live.test.ts'], shard: options.importShard }]
			: options.skipImports
			? [{ files: ['test/challenge-live.test.ts'], skipImports: true }]
			: shardImportMatrix
			? [
				{ files: ['test/live.test.ts', 'test/backup-integrity-live.test.ts'] },
				...Array.from({ length: 8 }, (_, index) => ({ files: ['test/challenge-live.test.ts'], shard: `${index}/8` })),
				{ files: ['test/challenge-live.test.ts'], skipImports: true },
			]
			: [{
				files: options.focusedImport
					? ['test/import-live.test.ts']
					: ssoEnabled
					? ['test/sso-live.test.ts']
					: smtpEnabled
					? ['test/email-live.test.ts']
					: ['test/live.test.ts', 'test/challenge-live.test.ts', 'test/backup-integrity-live.test.ts'],
			}];
		const runOne = async (run: { files: string[]; shard?: string; skipImports?: boolean }): Promise<number> => {
			if (runs.length > 1) {
				console.log(
					run.shard ? `Compatibility import shard ${run.shard}` : run.skipImports
						? 'Compatibility REST and authentication checks'
						: 'Compatibility KDF and vault checks',
				);
			}
			mailpit?.assertRunning();
			const args = testArgs(run.files);
			const childEnv = {
				...env,
				VW_TEST_IMPORT_SHARD: run.shard ?? options.importShard,
				VW_TEST_SKIP_IMPORTS: run.skipImports || options.skipImports ? '1' : undefined,
			};
			const child = spawn(args[0]!, args.slice(1), { detached: true, cwd, env: childEnv, stdio: 'inherit' });
			running.add(child);
			return await new Promise<number>(resolve => {
				child.once('error', error => {
					console.error(`Could not start compatibility test process: ${error.message}`);
					resolve(1);
				});
				child.once('exit', code => resolve(code ?? 130));
			}).finally(() => {
				running.delete(child);
			});
		};
		const reportFailure = async () => {
			if (!interrupted) {
				const logs = await docker(['logs', '--tail', '80', name]);
				console.error(logs.output);
				if (mailpit) console.error(await mailpit.diagnostics());
			}
		};
		if (shardImportMatrix) {
			// Check authentication and REST setup before the long KDF and import comparisons.
			exitCode = await runOne(runs.at(-1)!);
			if (exitCode === 0 && !interrupted) exitCode = await runOne(runs[0]!);
			if (exitCode === 0 && !interrupted) {
				let nextShard = 1;
				let failed = false;
				const workers = Array.from({ length: Math.min(4, runs.length - 2) }, async () => {
					while (!failed && !interrupted && nextShard < runs.length - 1) {
						const run = runs[nextShard++]!;
						const code = await runOne(run);
						if (code !== 0 && !failed) {
							failed = true;
							exitCode = code;
							stopTests();
						}
					}
				});
				await Promise.all(workers);
			}
			if (exitCode !== 0) await reportFailure();
		} else {
			for (const run of runs) {
				exitCode = await runOne(run);
				if (exitCode !== 0) {
					await reportFailure();
					break;
				}
			}
		}
	} finally {
		stopTests();
		await mailpit?.stop();
		if (oidc) {
			oidc.kill('SIGTERM');
			await oidc.exited;
		}
		const removed = await docker(['rm', '-f', name]);
		if (removed.code !== 0 && !removed.output.includes('No such container')) {
			exitCode = 1;
			console.error(`Fixture cleanup failed: ${removed.output}`);
		} else console.log(`Removed fixture container: ${name}`);
		await rm(directory, { recursive: true, force: true });
		process.off('SIGINT', interrupt);
		process.off('SIGTERM', interrupt);
	}
	return interrupted ? 130 : mailpitFailed ? 1 : exitCode ?? 1;
}

if (import.meta.main) await runDirect(['compat', 'run'], import.meta.url, { runCompatibility });
