import { expect, test } from 'bun:test';
import { stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRepoCLI } from './repo.ts';
import { repoRoot } from './runtime.mjs';

const entrypoints = [
	'tools/repo.ts',
	'tools/bundle-size.ts',
	'tools/release/pack.ts',
	'tools/release/preview.ts',
	'tools/release/verify.ts',
	'tools/release/smoke.mjs',
	'tools/release/draft.ts',
	'tools/release/download.ts',
	'tools/release/validate.ts',
	'tools/release/verify-attestations.ts',
	'tools/release/publish.ts',
	'packages/vaultwarden/wasm/build.ts',
	'apps/cli/test/plan-compatibility.ts',
	'apps/cli/test/run-compatibility.ts',
	'experiments/dependency-size/build.mjs',
	'experiments/dependency-size/probe.mjs',
	'experiments/dependency-size/wasm.mjs',
	'experiments/dependency-size/parity.mjs',
	'experiments/dependency-size/verify-recorded.mjs',
	'experiments/wasip2/build.mjs',
	'experiments/wasip2/optimize.mjs',
	'experiments/wasip2/benchmark.mjs',
	'experiments/wasip2/benchmark-worker.mjs',
	'experiments/wasip2/verify.mjs',
	'experiments/wasip2/verify-sdk.mjs',
];

test('help exposes task groups and explicit tool options without starting work', async () => {
	const app = createRepoCLI();
	const root = await app.execute(['--help']);
	expect(root.exitCode).toBe(0);
	for (const group of ['experiment', 'wasm', 'release', 'compat']) expect(root.stdout.join('')).toContain(group);
	const build = await app.execute(['experiment', 'sizes', 'build', '--help']);
	expect(build.exitCode).toBe(0);
	for (const option of ['--wasm-opt', '--cargo-home', '--js-only']) expect(build.stdout.join('')).toContain(option);
	const compat = await app.execute(['compat', 'run', '--help']);
	expect(compat.stdout.join('')).toContain('--reference-version');
	expect(compat.stdout.join('')).not.toContain('VW_TEST_');
});

test('invalid arguments fail before running builds, downloads or containers', async () => {
	for (
		const args of [
			['release', 'pack', 'unknown'],
			['release', 'verify', '--runtime', 'deno'],
			['experiment', 'sizes', 'build', '--wasm-oot', 'bad'],
			['experiment', 'wasip2', 'verify-sdk', '--optimization', 'fast'],
			['compat', 'run', '--server-version', 'latest'],
			['compat', 'plan', '--mode', 'latest'],
			['compat', 'run', '--smtp', '--sso'],
			['compat', 'run', '--import-shard', '8/8'],
		]
	) {
		const result = await createRepoCLI().execute(args);
		expect(result.exitCode).not.toBe(0);
	}
});

test('commands pass validated options to operations and honor runtime selection', async () => {
	const calls: unknown[] = [];
	const app = createRepoCLI({
		[new URL('../apps/cli/test/plan-compatibility.ts', import.meta.url).href]: {
			planCompatibilityMatrix: (mode: string) => {
				calls.push(mode);
			},
		},
		[new URL('./release/verify.ts', import.meta.url).href]: {
			verifyRelease: (runtime: string, metadata?: string) => calls.push([runtime, metadata]),
		},
		[new URL('./release/smoke.mjs', import.meta.url).href]: {
			smokeConsumer: (options: unknown) => calls.push(options),
		},
		[new URL('../experiments/wasip2/verify-sdk.mjs', import.meta.url).href]: {
			verifySdk: (options: unknown) => calls.push(options),
		},
		[new URL('../experiments/dependency-size/probe.mjs', import.meta.url).href]: {
			probeJavaScript: () => calls.push('JavaScript only'),
		},
	});
	expect((await app.execute(['release', 'verify', '--runtime', 'both'])).exitCode).toBe(0);
	expect(calls.splice(0)).toEqual([['node', undefined], ['bun', undefined]]);
	for (const cli of ['direct', 'optional', 'omitted']) {
		const smoke = await app.execute(['release', 'smoke', '--consumer', repoRoot, '--expected-sdk-version', '0.1.3'], {
			env: { EXPECTED_CLI: cli },
		});
		expect(smoke.exitCode).toBe(0);
		expect(calls.splice(0)).toEqual([{ consumer: resolve(repoRoot), expectedSdkVersion: '0.1.3', cli }]);
	}
	for (const cli of [[], ['--cli', 'global']]) {
		const smoke = await app.execute([
			'release',
			'smoke',
			'--consumer',
			repoRoot,
			'--expected-sdk-version',
			'0.1.3',
			...cli,
		]);
		expect(smoke.exitCode).not.toBe(0);
		expect(calls).toEqual([]);
	}
	expect(
		(await app.execute([
			'experiment',
			'wasip2',
			'verify-sdk',
			'--variant',
			'baseline',
			'--mode',
			'minified',
			'--optimization',
			'Os',
		])).exitCode,
	).toBe(0);
	expect(calls.splice(0)).toEqual([{ variant: 'baseline', mode: 'minified', optimization: 'Os' }]);
	expect((await app.execute(['experiment', 'sizes', 'build', '--js-only', '--runtime', 'bun'])).exitCode).toBe(0);
	expect(calls.splice(0)).toEqual(['JavaScript only']);
	expect((await app.execute(['compat', 'plan'])).exitCode).toBe(0);
	expect((await app.execute(['compat', 'plan', '--mode', 'pr'])).exitCode).toBe(0);
	expect(calls).toEqual(['full', 'pr']);
});

test('release verification treats empty preview metadata as absent and validates supplied paths', async () => {
	const calls: unknown[] = [];
	const app = createRepoCLI({
		[new URL('./release/verify.ts', import.meta.url).href]: {
			verifyRelease: (runtime: string, metadata?: string) => calls.push([runtime, metadata]),
		},
	});
	for (const metadata of [undefined, '', resolve(repoRoot, 'package.json')]) {
		const result = await app.execute(['release', 'verify'], {
			env: { RUNTIME: 'node', PREVIEW_METADATA: metadata },
		});
		expect(result.exitCode).toBe(0);
		expect(calls.splice(0)).toEqual([['node', metadata || undefined]]);
	}
	for (const metadata of [resolve(repoRoot, 'missing-preview.json'), repoRoot]) {
		const result = await app.execute(['release', 'verify', '--preview-metadata', metadata]);
		expect(result.exitCode).not.toBe(0);
		expect(calls).toEqual([]);
	}
});

test('entrypoint imports do not run operations or change the working directory', async () => {
	const cwd = process.cwd();
	const exitCode = process.exitCode;
	for (const entrypoint of entrypoints) {
		await import(pathToFileURL(resolve(repoRoot, entrypoint)).href);
		expect(process.cwd()).toBe(cwd);
		expect(process.exitCode).toBe(exitCode);
	}
});

test('entrypoints are executable and show help from outside the checkout', async () => {
	for (const entrypoint of entrypoints) {
		const path = resolve(repoRoot, entrypoint);
		expect((await stat(path)).mode & 0o111).not.toBe(0);
		expect((await Bun.file(path).text()).startsWith('#!/usr/bin/env bun\n')).toBe(true);
		const child = Bun.spawn([path, '--help'], { cwd: tmpdir(), stdout: 'pipe', stderr: 'pipe' });
		const [code, stdout, stderr] = await Promise.all([
			child.exited,
			new Response(child.stdout).text(),
			new Response(child.stderr).text(),
		]);
		expect({ entrypoint, code, stderr }).toEqual({ entrypoint, code: 0, stderr: '' });
		expect(stdout).toContain('Usage:');
	}
}, 30000);

test('Node can execute the same guarded entrypoint and reject invalid options', async () => {
	const child = Bun.spawn(['node', resolve(repoRoot, 'experiments/wasip2/verify-sdk.mjs'), '--variant', 'invalid'], {
		cwd: tmpdir(),
		stdout: 'pipe',
		stderr: 'pipe',
	});
	const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
	expect(code).not.toBe(0);
	expect(stderr).toContain('variant');
});

test('a direct Node invocation reaches the operation instead of awaiting its own import', async () => {
	const child = Bun.spawn([
		'node',
		resolve(repoRoot, 'experiments/wasip2/verify.mjs'),
		'--distribution',
		'nonexistent-test-distribution',
	], {
		cwd: tmpdir(),
		stdout: 'pipe',
		stderr: 'pipe',
	});
	const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text()]);
	expect(code).toBe(1);
	expect(stderr).toContain('Cannot find module');
	expect(stderr).not.toContain('unsettled top-level await');
});
