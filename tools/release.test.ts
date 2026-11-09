import { expect, test } from 'bun:test';
import { execFileSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { checksum, parseRelease, verifyChecksums, type ReleaseMetadata } from './release/metadata.ts';
import { publicationNeeded } from './release/publish.ts';
import { smokeConsumer } from './release/smoke.mjs';
import { repoRoot } from './runtime.mjs';

const sha = 'a'.repeat(40);
const metadata: ReleaseMetadata = {
	tag: 'v0.1.3',
	version: '0.1.3',
	sha,
	run: 123,
	packages: ['vaultwarden', 'cli'],
	prerelease: false,
};

test('release metadata rejects mismatched versions, packages, source and workflow IDs', () => {
	expect(parseRelease(JSON.stringify(metadata))).toEqual(metadata);
	for (
		const patch of [
			{ version: '0.1.2' },
			{ packages: ['cli'] },
			{ sha: '../main' },
			{ run: 0 },
			{ run: 1.5 },
			{ prerelease: true },
		]
	) {
		expect(() => parseRelease(JSON.stringify({ ...metadata, ...patch }))).toThrow();
	}
	expect(parseRelease(JSON.stringify({ ...metadata, tag: 'v0.1.3+build-x', version: '0.1.3+build-x' })).prerelease)
		.toBe(false);
});

test('npm publication requires E404 or identical existing archive integrity', () => {
	expect(publicationNeeded(0, '"sha512-same"', 'sha512-same')).toBe(false);
	expect(publicationNeeded(0, '["sha512-same"]', 'sha512-same')).toBe(false);
	expect(publicationNeeded(1, '{"error":{"code":"E404"}}', 'sha512-same')).toBe(true);
	for (
		const [status, output] of [
			[0, '"sha512-different"'],
			[0, '[]'],
			[1, '{"error":{"code":"E401"}}'],
			[null, '{"error":{"code":"E404"}}'],
		] as const
	) {
		expect(() => publicationNeeded(status, output, 'sha512-same')).toThrow();
	}
});

async function fixture() {
	const root = await mkdtemp(resolve(tmpdir(), 'vw-release-cli-'));
	for (
		const directory of [
			'tools',
			'tools/release',
			'artifacts',
			'tested',
			'bin',
			'packages/vaultwarden',
			'apps/cli',
			'archive/package',
		]
	) {
		await mkdir(resolve(root, directory), { recursive: true });
	}
	for (
		const file of [
			'tools/repo.ts',
			'tools/runtime.mjs',
			...['metadata', 'draft', 'download', 'validate', 'verify-attestations', 'publish'].map(name =>
				`tools/release/${name}.ts`
			),
		]
	) {
		await cp(resolve(repoRoot, file), resolve(root, file));
	}
	await writeFile(resolve(root, 'package.json'), '{"type":"module"}');
	await symlink(resolve(repoRoot, 'node_modules'), resolve(root, 'node_modules'));
	for (
		const [id, directory, name] of [
			['vaultwarden', 'packages/vaultwarden', '@kjanat/vaultwarden'],
			['cli', 'apps/cli', '@kjanat/vaultwarden-cli'],
		]
	) {
		const manifest = JSON.stringify({ name, version: metadata.version, publishConfig: { access: 'public' } });
		await writeFile(resolve(root, directory!, 'package.json'), manifest);
		await writeFile(resolve(root, 'archive/package/package.json'), manifest);
		execFileSync('tar', ['-czf', resolve(root, 'artifacts', `${id}.tgz`), '-C', resolve(root, 'archive'), 'package']);
		await writeFile(
			resolve(root, 'artifacts', `${id}.tgz.sha256`),
			`${await checksum(resolve(root, 'artifacts'), `${id}.tgz`)}  ${id}.tgz\n`,
		);
		await cp(resolve(root, 'artifacts', `${id}.tgz`), resolve(root, 'tested', `${id}.tgz`));
	}
	// These executables record the real subprocess arguments; none contacts GitHub or npm.
	await writeFile(
		resolve(root, 'bin/fake-tool'),
		`#!/usr/bin/env bun
import { appendFileSync } from 'node:fs';
import { basename } from 'node:path';
const command = basename(process.argv[1]);
const args = process.argv.slice(2);
appendFileSync(process.env.CALLS, JSON.stringify([command, ...args]) + '\\n');
if (command === 'git' && args[0] === 'rev-parse') console.log('${sha}');
if (command === 'gh' && args[0] === 'release' && args[1] === 'list') console.log('[]');
if (command === 'gh' && args[0] === 'release' && args[1] === 'view') console.log('{"isDraft":true}');
if (command === 'gh' && args[0] === 'run' && args[1] === 'view') console.log('{"workflowName":"Release","conclusion":"success"}');
if (command === 'npm' && args.includes('view')) { console.log('{"error":{"code":"E404"}}'); process.exit(1); }
`,
		{ mode: 0o755 },
	);
	for (const tool of ['git', 'gh', 'npm']) await cp(resolve(root, 'bin/fake-tool'), resolve(root, 'bin', tool));
	const callsFile = resolve(root, 'calls.jsonl');
	await writeFile(callsFile, '');
	const env = {
		...process.env,
		PATH: `${resolve(root, 'bin')}:${process.env.PATH}`,
		CALLS: callsFile,
		TAG: metadata.tag,
		GITHUB_REF: `refs/tags/${metadata.tag}`,
		GITHUB_RUN_ID: String(metadata.run),
		GITHUB_OUTPUT: resolve(root, 'output'),
		GITHUB_STEP_SUMMARY: resolve(root, 'summary'),
		GH_REPO: 'example/repository',
		RELEASE: JSON.stringify(metadata),
		RELEASE_PACKAGE: undefined,
		RUNNER_TEMP: root,
	};
	return {
		root,
		async execute(args: string[], overrides: Record<string, string> = {}) {
			const child = Bun.spawn([process.execPath, resolve(root, 'tools/repo.ts'), 'release', ...args], {
				cwd: root,
				env: { ...env, ...overrides },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 20000,
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			return { code, stdout, stderr };
		},
		async calls(): Promise<string[][]> {
			return (await readFile(callsFile, 'utf8')).trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
		},
		cleanup: () => rm(root, { recursive: true, force: true }),
	};
}

test('release commands consume workflow env and retain draft, provenance and publication gates', async () => {
	const f = await fixture();
	try {
		for (
			const args of [
				['draft', 'prepare'],
				['draft', 'stage'],
				['verify-attestations'],
				['draft', 'attach'],
				['download'],
				['validate'],
			]
		) {
			const result = await f.execute(args);
			expect({ args, code: result.code, stderr: result.stderr }).toEqual({ args, code: 0, stderr: '' });
		}
		const published = await f.execute(['publish'], { RELEASE_PACKAGE: 'cli' });
		expect(published.code).toBe(0);
		const calls = await f.calls();
		const attestations = calls.filter(args => args[1] === 'attestation');
		expect(attestations).toHaveLength(4);
		for (const args of attestations) {
			expect(args).toContain('example/repository/.github/workflows/release.yml');
			expect(args).toContain(`refs/tags/${metadata.tag}`);
			expect(args).toContain(sha);
			expect(args).toContain('--deny-self-hosted-runners');
		}
		expect(calls.find(args => args[1] === 'release' && args[2] === 'create')).toContain('--draft');
		expect(calls.find(args => args[1] === 'release' && args[2] === 'upload')).toEqual([
			'gh',
			'release',
			'upload',
			metadata.tag,
			'vaultwarden.tgz',
			'cli.tgz',
			'SHA256SUMS',
			'release.json',
			'--clobber',
		]);
		const publish = calls.find(args => args[0] === 'npm' && args.includes('publish'))!;
		expect(publish).toContain('--provenance');
		expect(publish).toContain('--ignore-scripts');
		expect(publish.slice(-2)).toEqual(['--tag', 'latest']);
		expect((await readFile(resolve(f.root, 'output'), 'utf8')).trim().split('\n')).toHaveLength(2);
	} finally {
		await f.cleanup();
	}
}, 30000);

test('tampered assets or changed tested archives stop release mutations', async () => {
	const f = await fixture();
	try {
		expect((await f.execute(['draft', 'stage'])).code).toBe(0);
		await writeFile(resolve(f.root, 'tested/cli.tgz'), 'different tested bytes');
		const publish = await f.execute(['publish'], { RELEASE_PACKAGE: 'cli' });
		expect(publish.code).not.toBe(0);
		expect(publish.stderr).toContain('differs from tested build');
		await writeFile(resolve(f.root, 'artifacts/vaultwarden.tgz'), 'tampered release');
		const attach = await f.execute(['draft', 'attach']);
		expect(attach.code).not.toBe(0);
		expect(attach.stderr).toContain('Checksum mismatch');
		expect((await f.calls()).some(args => args[0] === 'npm' || args.includes('upload'))).toBe(false);
		await expect(verifyChecksums(resolve(f.root, 'artifacts'), 'SHA256SUMS', ['missing.tgz'])).rejects.toThrow(
			'Missing checksum',
		);
	} finally {
		await f.cleanup();
	}
}, 30000);

test('consumer smoke resolves each CLI installation inside the consumer before importing the SDK', async () => {
	const sdk = 'consumer/node_modules/@kjanat/vaultwarden';
	const cli = 'consumer/node_modules/@kjanat/vaultwarden-cli';
	const ancestor = { 'node_modules/@kjanat/vaultwarden': sdk, 'node_modules/@kjanat/vaultwarden-cli': cli };
	const outside = 'Package resolved outside the consumer installation';
	const cases: [string, Record<string, string>, string, boolean?][] = [
		['direct', ancestor, outside],
		['optional', ancestor, outside],
		['omitted', ancestor, outside],
		['direct', { [sdk]: sdk, [cli]: cli }, `Imported ${sdk}`],
		['optional', { [sdk]: sdk }, 'Cannot find module'],
		[
			'optional',
			{ [sdk]: sdk, [cli]: cli, [`${cli}/node_modules/@kjanat/vaultwarden`]: sdk },
			'must use the installed SDK',
		],
		['optional', { [sdk]: sdk, [cli]: cli }, `Imported ${sdk}`],
		['omitted', { [sdk]: sdk, [cli]: cli }, '@kjanat/vaultwarden-cli must be absent'],
		['omitted', { [sdk]: sdk }, 'vw must be absent', true],
		['omitted', { [sdk]: sdk, 'node_modules/@kjanat/vaultwarden-cli': cli }, `Imported ${sdk}`],
		['omitted', { [sdk]: sdk }, `Imported ${sdk}`],
		['global', { [sdk]: sdk }, 'Unknown CLI installation: global'],
	];
	for (const [installation, layout, error, vw] of cases) {
		const root = await mkdtemp(resolve(tmpdir(), 'vw-consumer-isolation-'));
		try {
			const consumer = resolve(root, 'consumer');
			await mkdir(resolve(consumer, 'node_modules/.bin'), { recursive: true });
			await writeFile(resolve(consumer, 'package.json'), '{"private":true}');
			if (vw) await writeFile(resolve(consumer, 'node_modules/.bin/vw'), '');
			for (const [directory, name] of Object.entries(layout)) {
				await mkdir(resolve(root, directory), { recursive: true });
				await writeFile(
					resolve(root, directory, 'package.json'),
					JSON.stringify({ name: name.replace(/^.*node_modules\//, ''), main: 'index.mjs' }),
				);
				await writeFile(
					resolve(root, directory, 'index.mjs'),
					`throw new Error(${JSON.stringify(`Imported ${directory}`)});`,
				);
			}
			await expect(smokeConsumer({ consumer, expectedSdkVersion: '0.1.3', cli: installation }), installation)
				.rejects.toThrow(error);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	}
});
