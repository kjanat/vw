#!/usr/bin/env bun
import { cli, command, group, arg, flag } from '@kjanat/dreamcli';
import { createAdapter } from '@kjanat/dreamcli/runtime';
import { execFileSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { resolve } from 'node:path';
import { repoRoot, resolveWasmOpt } from './runtime.mjs';
import { releaseTagPattern } from './release/metadata.ts';

const wasmOptFlag = () =>
	flag.string({ nonEmpty: true })
		.describe('Binaryen 133 executable; defaults to the mise pin, then PATH');
const cargoHomeFlag = () => flag.path({ type: 'directory' }).describe('Cargo registry/cache directory');
const runtimeFlag = () =>
	flag.enum(['node', 'bun', 'both']).env('RUNTIME').default('both').describe('JavaScript runtime(s)');
const measurementRuntimeFlag = () =>
	flag.enum(['node', 'bun']).default('node')
		.describe('Runtime/compressor for size measurements; original results use Node');
const runtimes = (runtime: 'node' | 'bun' | 'both'): ('node' | 'bun')[] =>
	runtime === 'both' ? ['node', 'bun'] : [runtime];
function runScript(runtime: string, script: string, args: string[] = []) {
	execFileSync(runtime, [resolve(repoRoot, script), ...args], { cwd: repoRoot, stdio: 'inherit' });
}

export function createRepoCLI(direct: Record<string, unknown> = {}) {
	// A directly executed module is still evaluating its main guard. Reuse its
	// exported operation instead of awaiting an import of that same module.
	async function load<T>(path: string, importer: () => Promise<T>): Promise<T> {
		const supplied = direct[new URL(path, import.meta.url).href];
		return supplied === undefined ? importer() : supplied as T;
	}
	const sizes = group('sizes').description('Compare HTML parser and public suffix implementations')
		.command(
			command('build').description('Build and measure the JavaScript and WASIp2 candidates')
				.flag('wasm-opt', wasmOptFlag()).flag('cargo-home', cargoHomeFlag())
				.flag('runtime', measurementRuntimeFlag())
				.flag('js-only', flag.boolean().describe('Measure JavaScript candidates without Rust or Binaryen'))
				.action(async ({ flags }) => {
					if (flags.runtime !== (process.versions.bun ? 'bun' : 'node')) {
						const args = ['--runtime', flags.runtime];
						if (flags['js-only']) args.push('--js-only');
						if (flags['wasm-opt']) args.push('--wasm-opt', resolveWasmOpt(flags['wasm-opt']));
						if (flags['cargo-home']) args.push('--cargo-home', resolve(flags['cargo-home']));
						runScript(flags.runtime, 'experiments/dependency-size/build.mjs', args);
						return;
					}
					if (flags['js-only']) {
						return (await load(
							'../experiments/dependency-size/probe.mjs',
							() => import('../experiments/dependency-size/probe.mjs'),
						)).probeJavaScript();
					}
					await (await load(
						'../experiments/dependency-size/build.mjs',
						() => import('../experiments/dependency-size/build.mjs'),
					)).buildDependencySize({
						wasmOpt: resolveWasmOpt(flags['wasm-opt']),
						cargoHome: flags['cargo-home'] ? resolve(flags['cargo-home']) : undefined,
					});
				}),
		)
		.command(
			command('wasm').description('Transpile, optimize and measure already-built components')
				.flag('wasm-opt', wasmOptFlag())
				.flag('runtime', measurementRuntimeFlag())
				.action(async ({ flags }) => {
					if (flags.runtime !== (process.versions.bun ? 'bun' : 'node')) {
						runScript(flags.runtime, 'experiments/dependency-size/wasm.mjs', [
							'--runtime',
							flags.runtime,
							'--wasm-opt',
							resolveWasmOpt(flags['wasm-opt']),
						]);
						return;
					}
					return (
						(await load(
							'../experiments/dependency-size/wasm.mjs',
							() => import('../experiments/dependency-size/wasm.mjs'),
						))
							.measureWasm({ wasmOpt: resolveWasmOpt(flags['wasm-opt']) })
					);
				}),
		)
		.command(
			command('test').description('Run compatibility cases and compare recorded findings')
				.flag('runtime', runtimeFlag())
				.action(async ({ flags }) => {
					for (const runtime of runtimes(flags.runtime)) runScript(runtime, 'experiments/dependency-size/parity.mjs');
					await (await load(
						'../experiments/dependency-size/verify-recorded.mjs',
						() => import('../experiments/dependency-size/verify-recorded.mjs'),
					))
						.verifyRecorded(runtimes(flags.runtime));
				}),
		)
		.command(
			command('parity').description('Run the corpus in the current process runtime')
				.action(async () =>
					(await load(
						'../experiments/dependency-size/parity.mjs',
						() => import('../experiments/dependency-size/parity.mjs'),
					)).checkParity()
				),
		)
		.command(
			command('verify-recorded').description('Compare fresh Node/Bun reports with recorded results')
				.action(async () =>
					(await load(
						'../experiments/dependency-size/verify-recorded.mjs',
						() => import('../experiments/dependency-size/verify-recorded.mjs'),
					)).verifyRecorded()
				),
		);

	const wasip2 = group('wasip2').description('Compare password-scoring WASM implementations')
		.command(
			command('build').description('Build the baseline and WASIp2 scorers')
				.action(async () =>
					(await load('../experiments/wasip2/build.mjs', () => import('../experiments/wasip2/build.mjs')))
						.buildScorers()
				),
		)
		.command(
			command('optimize').description('Compare Binaryen optimization profiles')
				.flag('wasm-opt', wasmOptFlag())
				.action(async ({ flags }) =>
					(await load('../experiments/wasip2/optimize.mjs', () => import('../experiments/wasip2/optimize.mjs')))
						.optimizeScorers({ wasmOpt: resolveWasmOpt(flags['wasm-opt']) })
				),
		)
		.command(
			command('benchmark').description('Benchmark import, cold scoring and warm scoring')
				.action(async () =>
					(await load('../experiments/wasip2/benchmark.mjs', () => import('../experiments/wasip2/benchmark.mjs')))
						.benchmarkScorers()
				),
		)
		.command(
			command('benchmark-worker').description('Measure a single scorer in the current runtime')
				.flag('variant', flag.enum(['baseline', 'p2']).required())
				.action(async ({ flags }) =>
					(await load(
						'../experiments/wasip2/benchmark-worker.mjs',
						() => import('../experiments/wasip2/benchmark-worker.mjs'),
					))
						.benchmarkWorker(flags.variant)
				),
		)
		.command(
			command('verify').description('Check scorer parity and lazy initialization in this runtime')
				.flag(
					'distribution',
					flag.string({ nonEmpty: true }).default('dist').describe('Directory relative to the experiment'),
				)
				.action(async ({ flags }) =>
					(await load('../experiments/wasip2/verify.mjs', () => import('../experiments/wasip2/verify.mjs')))
						.verifyScorers(flags.distribution)
				),
		)
		.command(
			command('test').description('Verify scorers with Node and Bun')
				.flag('runtime', runtimeFlag())
				.flag('distribution', flag.string({ nonEmpty: true }).default('dist'))
				.action(({ flags }) => {
					for (const runtime of runtimes(flags.runtime)) {
						runScript(runtime, 'experiments/wasip2/verify.mjs', ['--distribution', flags.distribution]);
					}
				}),
		)
		.command(
			command('verify-sdk').description('Test an alternate scorer through packed SDK and CLI installations')
				.flag('variant', flag.enum(['baseline', 'p2']).default('p2'))
				.flag('mode', flag.enum(['default', 'minified', 'minified-no-maps']).default('default'))
				.flag('optimization', flag.enum(['none', 'Os', 'Oz', 'Oz-converge']).default('none'))
				.action(async ({ flags }) =>
					(await load('../experiments/wasip2/verify-sdk.mjs', () => import('../experiments/wasip2/verify-sdk.mjs')))
						.verifySdk(flags)
				),
		);

	const tagFlag = () => flag.string({ pattern: releaseTagPattern }).env('TAG').required();
	const releaseFlag = () => flag.string({ nonEmpty: true }).env('RELEASE').required();
	const outputFlag = () => flag.path({ type: 'file', mustExist: false }).env('GITHUB_OUTPUT');
	const release = group('release').description('Pack, verify and publish tested release archives')
		.command(
			group('draft').description('Prepare, stage and attach GitHub draft releases')
				.command(
					command('prepare').description('Check the release source and create a GitHub draft')
						.flag('tag', tagFlag())
						.flag('ref', flag.string({ nonEmpty: true }).env('GITHUB_REF').required())
						.flag('run-id', flag.string({ pattern: /^[1-9]\d*$/ }).env('GITHUB_RUN_ID').required())
						.flag('output', outputFlag())
						.action(async ({ flags }) => {
							await (await load('./release/draft.ts', () => import('./release/draft.ts')))
								.prepareDraft({ tag: flags.tag, ref: flags.ref, runId: flags['run-id'], output: flags.output });
						}),
				)
				.command(
					command('stage').description('Verify tested archives and write release assets and checksums')
						.flag('release', releaseFlag())
						.action(async ({ flags }) => {
							await (await load('./release/draft.ts', () => import('./release/draft.ts')))
								.stageDraft(flags.release);
						}),
				)
				.command(
					command('attach').description('Attach staged assets to an existing GitHub draft')
						.flag('release', releaseFlag())
						.flag('summary', flag.path({ type: 'file', mustExist: false }).env('GITHUB_STEP_SUMMARY'))
						.action(async ({ flags }) => {
							await (await load('./release/draft.ts', () => import('./release/draft.ts')))
								.attachDraft(flags.release, flags.summary);
						}),
				),
		)
		.command(
			command('verify-attestations').description('Verify provenance for every release asset against this checkout')
				.flag('tag', tagFlag())
				.flag('repository', flag.string({ pattern: /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/ }).env('GH_REPO').required())
				.action(async ({ flags }) => {
					(await load(
						'./release/verify-attestations.ts',
						() => import('./release/verify-attestations.ts'),
					))
						.verifyAttestations(flags.tag, flags.repository);
				}),
		)
		.command(
			command('download').description('Download release assets or a selected package with its checksums')
				.flag('tag', tagFlag())
				.flag('package', flag.enum(['vaultwarden', 'cli']).env('RELEASE_PACKAGE'))
				.action(async ({ flags }) => {
					(await load('./release/download.ts', () => import('./release/download.ts')))
						.downloadRelease(flags.tag, flags.package);
				}),
		)
		.command(
			command('validate').description('Verify release checksums, source and successful build workflow')
				.flag('tag', tagFlag())
				.flag('output', outputFlag())
				.action(async ({ flags }) => {
					await (await load('./release/validate.ts', () => import('./release/validate.ts')))
						.validateRelease(flags.tag, flags.output);
				}),
		)
		.command(
			command('publish').description('Publish the approved, byte-identical archive with npm provenance')
				.arg('package', arg.enum(['vaultwarden', 'cli']).env('RELEASE_PACKAGE'))
				.flag('release', releaseFlag())
				.flag('temporary', flag.path({ type: 'directory' }).env('RUNNER_TEMP').required())
				.action(async ({ args, flags }) => {
					await (await load('./release/publish.ts', () => import('./release/publish.ts')))
						.publishRelease({ packageId: args.package, metadata: flags.release, temporary: flags.temporary });
				}),
		)
		.command(
			command('pack').description('Pack a public workspace and write its SHA-256 checksum')
				.arg('package', arg.enum(['vaultwarden', 'cli']).env('RELEASE_PACKAGE'))
				.action(async ({ args }) =>
					(await load('./release/pack.ts', () => import('./release/pack.ts'))).packRelease(
						args.package,
					)
				),
		)
		.command(
			command('smoke').description('Check packages installed in an isolated consumer directory')
				.flag('consumer', flag.path({ type: 'directory' }).env('CONSUMER_DIRECTORY').required())
				.flag('expected-sdk-version', flag.string({ nonEmpty: true }).env('EXPECTED_SDK_VERSION').required())
				.action(async ({ flags }) => {
					await (await load('./release/smoke.mjs', () => import('./release/smoke.mjs')))
						.smokeConsumer({ consumer: resolve(flags.consumer), expectedSdkVersion: flags['expected-sdk-version'] });
				}),
		)
		.command(
			command('verify').description('Verify isolated installations of archives or published previews')
				.flag('runtime', runtimeFlag())
				.flag(
					'preview-metadata',
					flag.custom((raw: unknown) => {
						// GitHub Actions supplies an empty value for archive-only verification.
						if (raw === '') return undefined;
						if (typeof raw !== 'string' || !statSync(raw, { throwIfNoEntry: false })?.isFile()) {
							throw new Error('Preview publication metadata must name an existing file.');
						}
						return raw;
					}).env('PREVIEW_METADATA').describe('Preview publication metadata'),
				)
				.action(async ({ flags }) => {
					const metadata = flags['preview-metadata'] ? resolve(flags['preview-metadata']) : undefined;
					for (const runtime of runtimes(flags.runtime)) {
						await (await load('./release/verify.ts', () => import('./release/verify.ts')))
							.verifyRelease(runtime, metadata);
					}
				}),
		)
		.command(
			command('preview').description('Download preview archives and verify their published hashes')
				.flag(
					'metadata',
					flag.path({ type: 'file' }).env('PREVIEW_METADATA').default(resolve(repoRoot, 'artifacts/preview.json')),
				)
				.action(async ({ flags }) =>
					(await load('./release/preview.ts', () => import('./release/preview.ts'))).fetchPreview(
						resolve(flags.metadata),
					)
				),
		);

	return cli('vw-repo').description('Builds, experiments and release tooling for the vw repository')
		.builtins({ json: 'off', quiet: 'off' })
		.command(group('experiment').description('Reproducible implementation comparisons').command(sizes).command(wasip2))
		.command(
			group('wasm').description('Production password-scoring component')
				.command(
					command('build').description('Build and optimize the SDK WASIp2 scorer')
						.flag('wasm-opt', wasmOptFlag())
						.action(async ({ flags }) =>
							(await load(
								'../packages/vaultwarden/wasm/build.ts',
								() => import('../packages/vaultwarden/wasm/build.ts'),
							))
								.buildPasswordStrength({ wasmOpt: resolveWasmOpt(flags['wasm-opt']) })
						),
				),
		)
		.command(
			group('bundle').description('Measure installed SDK bundles including all runtime assets')
				.command(
					command('compare').description('Compare two SDK tarballs with identical Node/esbuild settings')
						.flag('baseline', flag.path({ type: 'file' }).required())
						.flag('candidate', flag.path({ type: 'file' }).required())
						.flag('output', flag.path({ type: 'file', mustExist: false }))
						.action(async ({ flags }) => {
							const args = ['--baseline', resolve(flags.baseline), '--candidate', resolve(flags.candidate)];
							if (flags.output) args.push('--output', resolve(flags.output));
							if (process.versions.bun) {
								runScript('node', 'tools/bundle-size.ts', args);
								return;
							}
							await (await load('./bundle-size.ts', () => import('./bundle-size.ts'))).compareBundles({
								baseline: resolve(flags.baseline),
								candidate: resolve(flags.candidate),
								output: flags.output ? resolve(flags.output) : undefined,
							});
						}),
				),
		)
		.command(release)
		.command(
			group('compat').description('Disposable Vaultwarden compatibility runs')
				.command(
					command('plan').description('Discover supported server and CLI releases and print the CI matrices')
						.flag(
							'mode',
							flag.enum(['full', 'pr']).env('COMPATIBILITY_MODE').default('full').describe(
								'Full cross-product or newest server/CLI edges',
							),
						)
						.action(async ({ flags }) => {
							await (await load(
								'../apps/cli/test/plan-compatibility.ts',
								() => import('../apps/cli/test/plan-compatibility.ts'),
							)).planCompatibilityMatrix(flags.mode);
						}),
				)
				.command(
					command('run').description('Run the managed compatibility suite in disposable containers')
						.flag('server-version', flag.string({ pattern: /^\d+\.\d+\.\d+$/ }).env('SERVER_VERSION').default('1.37.4'))
						.flag(
							'image',
							flag.string({ nonEmpty: true }).env('SERVER_IMAGE').describe('Immutable Vaultwarden image override'),
						)
						.flag(
							'reference',
							flag.path({ type: 'file' }).env('REFERENCE_CLI').describe('Independent Bitwarden CLI executable'),
						)
						.flag('reference-version', flag.string({ pattern: /^\d+\.\d+\.\d+$/ }).env('REFERENCE_VERSION'))
						.flag(
							'protocol-only',
							flag.boolean().env('COMPATIBILITY_PROTOCOL_ONLY').describe('Run without reference CLI comparisons'),
						)
						.flag(
							'smtp',
							flag.boolean().env('COMPATIBILITY_SMTP').describe('Exercise delivered email codes with Mailpit'),
						)
						.flag('sso', flag.boolean().env('COMPATIBILITY_SSO').describe('Exercise OIDC SSO'))
						.flag('case', flag.string({ nonEmpty: true }).env('COMPATIBILITY_CASE').describe('Test name pattern'))
						.flag('import-format', flag.string({ nonEmpty: true }).env('COMPATIBILITY_IMPORT_FORMAT'))
						.flag('import-shard', flag.string({ pattern: /^\d+\/[1-9]\d*$/ }).env('COMPATIBILITY_IMPORT_SHARD'))
						.flag('skip-imports', flag.boolean().env('COMPATIBILITY_SKIP_IMPORTS'))
						.flag('focused-import', flag.boolean().env('COMPATIBILITY_FOCUSED_IMPORT'))
						.flag('list-filters-only', flag.boolean().env('COMPATIBILITY_LIST_FILTERS_ONLY'))
						.flag('policy-redaction-only', flag.boolean().env('COMPATIBILITY_POLICY_REDACTION_ONLY'))
						.derive(({ flags }) => {
							if (flags.smtp && flags.sso) throw new Error('--smtp and --sso are mutually exclusive');
							if (flags['import-shard']) {
								const [index, count] = flags['import-shard'].split('/').map(Number);
								if (index! >= count!) throw new Error('--import-shard index must be smaller than its count');
							}
							return {};
						})
						.action(async ({ flags, out }) => {
							execFileSync('bun', ['run', 'build'], { cwd: repoRoot, stdio: 'inherit' });
							const code = await (await load(
								'../apps/cli/test/run-compatibility.ts',
								() => import('../apps/cli/test/run-compatibility.ts'),
							)).runCompatibility({
								version: flags['server-version'],
								image: flags.image,
								reference: flags.reference ? resolve(flags.reference) : undefined,
								referenceVersion: flags['reference-version'],
								protocolOnly: flags['protocol-only'],
								smtp: flags.smtp,
								sso: flags.sso,
								testCase: flags.case,
								importFormat: flags['import-format'],
								importShard: flags['import-shard'],
								skipImports: flags['skip-imports'],
								focusedImport: flags['focused-import'],
								listFiltersOnly: flags['list-filters-only'],
								policyRedactionOnly: flags['policy-redaction-only'],
							});
							out.setExitCode(code);
						}),
				),
		)
		.completions();
}

export async function runRepo(prefix: string[] = [], direct: Record<string, unknown> = {}) {
	const adapter = createAdapter();
	await createRepoCLI(direct).run({
		adapter: { ...adapter, argv: [...adapter.argv.slice(0, 2), ...prefix, ...adapter.argv.slice(2)] },
	});
}

if (import.meta.main) await runRepo();
