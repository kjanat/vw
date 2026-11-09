#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
	cpSync,
	mkdirSync,
	mkdtempSync,
	readdirSync,
	readFileSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';
import { runConsumerSmoke } from '../../tools/release/smoke.mjs';

export async function verifySdk({ variant = 'p2', mode = 'default', optimization = 'none' } = {}) {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		const root = dirname(fileURLToPath(import.meta.url));
		const repo = resolve(root, '../..');
		assert(['baseline', 'p2'].includes(variant));
		assert(['default', 'minified', 'minified-no-maps'].includes(mode));
		assert(['none', 'Os', 'Oz', 'Oz-converge'].includes(optimization));
		const distribution = optimization === 'none' ? 'dist' : `dist/wasm-opt/${optimization}`;
		const source = join(repo, 'packages/vaultwarden');
		mkdirSync(join(root, '.cache'), { recursive: true });
		const work = mkdtempSync(join(root, '.cache/sdk-'));
		const sdk = join(work, 'packages/vaultwarden');
		cpSync(join(repo, 'package.json'), join(work, 'package.json'));
		cpSync(join(repo, 'bun.lock'), join(work, 'bun.lock'));
		cpSync(source, sdk, {
			recursive: true,
			filter: path =>
				!relative(source, path).split('/').some(part =>
					['node_modules', 'dist', 'target', 'vendor', '.cache', '.turbo'].includes(part)
				),
		});
		symlinkSync(join(source, 'node_modules'), join(sdk, 'node_modules'), 'dir');
		if (mode === 'minified-no-maps') {
			const tsconfigPath = join(sdk, 'tsconfig.json');
			const tsconfig = JSON.parse(readFileSync(tsconfigPath));
			tsconfig.compilerOptions.declarationMap = false;
			tsconfig.compilerOptions.sourceMap = false;
			writeFileSync(tsconfigPath, JSON.stringify(tsconfig, null, 2) + '\n');
		}
		cpSync(join(root, distribution, variant), join(sdk, 'src/generated-backend'), { recursive: true });
		writeFileSync(
			join(sdk, 'src/password-strength.ts'),
			"export { score as passwordScore } from './generated-backend/index.mjs';\n",
		);
		writeFileSync(
			join(sdk, 'tsdown.config.ts'),
			`import { defineConfig } from 'tsdown';
		export default defineConfig({
		  entry: ['src/index.ts', 'src/kdbx-worker.ts'], platform: 'node', dts: true, exports: true,
		  ${mode !== 'default' ? 'minify: true,' : ''}
		  ${mode === 'minified-no-maps' ? 'sourcemap: false,' : ''}
		  deps: { alwaysBundle: ['kdbxweb'], onlyBundle: ['kdbxweb'] },
		  copy: ['src/generated-backend/*.br', 'wasm/THIRD_PARTY_NOTICES.txt'],
		});
		`,
		);
		const run = (command, args, cwd, env = process.env) => execFileSync(command, args, { cwd, env, stdio: 'inherit' });
		run(join(source, 'node_modules/.bin/tsdown'), [], sdk);
		run('bun', ['test', 'test/reports.test.ts'], sdk);
		const archive = join(work, 'sdk.tgz');
		run('bun', ['pm', 'pack', '--ignore-scripts', '--filename', archive], sdk);
		const sdkManifest = JSON.parse(readFileSync(join(source, 'package.json')));
		const cliManifest = JSON.parse(readFileSync(join(repo, 'apps/cli/package.json')));

		// Pack the existing CLI; it consumes the alternate SDK through the public package API.
		const cliArchive = join(work, 'cli.tgz');
		run('bun', ['pm', 'pack', '--ignore-scripts', '--filename', cliArchive], join(repo, 'apps/cli'));
		let packageBytes;
		for (const runtime of ['node', 'bun']) {
			const consumer = join(work, runtime);
			mkdirSync(consumer);
			writeFileSync(
				join(consumer, 'package.json'),
				JSON.stringify({
					private: true,
					type: 'module',
					dependencies: {
						[sdkManifest.name]: `file:${archive}`,
						[cliManifest.name]: `file:${cliArchive}`,
					},
					overrides: { [sdkManifest.name]: `file:${archive}`, [cliManifest.name]: `file:${cliArchive}` },
				}),
			);
			run('bun', ['install', '--ignore-scripts'], consumer);
			runConsumerSmoke(runtime, consumer, sdkManifest.version, 'direct');
			const installed = join(consumer, 'node_modules', sdkManifest.name);
			const sizes = { js: 0, maps: 0, declarations: 0, wasm: 0, other: 0 };
			for (const file of readdirSync(installed, { recursive: true })) {
				const stat = statSync(join(installed, file));
				if (!stat.isFile()) continue;
				const category = file.endsWith('.map')
					? 'maps'
					: file.endsWith('.d.mts')
					? 'declarations'
					: file.endsWith('.mjs')
					? 'js'
					: file.endsWith('.wasm.br')
					? 'wasm'
					: 'other';
				sizes[category] += stat.size;
			}
			assert(sizes.declarations > 0, 'Installed SDK must retain its TypeScript declarations');
			if (mode === 'minified-no-maps') assert.equal(sizes.maps, 0);
			if (packageBytes) assert.deepEqual(sizes, packageBytes);
			packageBytes = sizes;
		}
		writeFileSync(
			join(
				root,
				`results/sdk-${variant}${mode === 'default' ? '' : `-${mode}`}${
					optimization === 'none' ? '' : `-wasm-opt-${optimization}`
				}.json`,
			),
			JSON.stringify(
				{
					variant,
					mode,
					optimization,
					archive,
					packedBytes: readFileSync(archive).length,
					unpackedBytes: Object.values(packageBytes).reduce((sum, size) => sum + size, 0),
					packageBytes,
					node: true,
					bun: true,
					reportTests: 9,
				},
				null,
				2,
			) + '\n',
		);
		console.log(`${variant} SDK integration verified (${mode}, wasm-opt ${optimization}): ${work}`);
	});
}

if (import.meta.main) await runDirect(['experiment', 'wasip2', 'verify-sdk'], import.meta.url, { verifySdk });
