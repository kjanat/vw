#!/usr/bin/env bun
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { gzipSync, brotliCompressSync, constants } from 'node:zlib';
import { build, version as esbuildVersion } from 'esbuild';
import { repoRoot, runDirect } from './runtime.mjs';

const sizes = (bytes: Uint8Array) => ({
	minified: bytes.length,
	gzip: gzipSync(bytes, { level: 9 }).length,
	brotli: brotliCompressSync(bytes, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }).length,
});

export async function compareBundles(options: { baseline: string; candidate: string; output?: string }) {
	await mkdir(join(repoRoot, '.cache'), { recursive: true });
	const work = await mkdtemp(join(repoRoot, '.cache/bundle-size-'));
	async function measure(name: string, archive: string) {
		const cwd = join(work, name);
		await mkdir(cwd);
		await writeFile(
			join(cwd, 'package.json'),
			JSON.stringify({
				private: true,
				type: 'module',
				dependencies: { '@kjanat/vaultwarden': `file:${archive}` },
			}),
		);
		execFileSync('bun', ['install', '--ignore-scripts', '--omit=optional'], {
			cwd,
			stdio: ['ignore', 'ignore', 'inherit'],
		});
		const sdk = join(cwd, 'node_modules/@kjanat/vaultwarden');
		const bundle = async (source: string, filename: string) => {
			const result = await build({
				stdin: { contents: source, resolveDir: cwd, sourcefile: filename },
				bundle: true,
				minify: true,
				platform: 'node',
				format: 'esm',
				target: 'node24.8',
				mainFields: ['module', 'main'],
				write: false,
				logLevel: 'silent',
			});
			return sizes(result.outputFiles[0]!.contents);
		};
		const allExports = await bundle("export * from '@kjanat/vaultwarden';", 'all-exports.mjs');
		const cryptoOnly = await bundle("export {encrypt,decrypt} from '@kjanat/vaultwarden';", 'crypto-only.mjs');
		const worker = await bundle(`import ${JSON.stringify(join(sdk, 'dist/kdbx-worker.mjs'))};`, 'worker.mjs');
		const sidecars = [];
		for (const file of (await readdir(join(sdk, 'dist'), { recursive: true })).sort()) {
			if (!file.endsWith('.br')) continue;
			const bytes = await readFile(join(sdk, 'dist', file));
			sidecars.push({ file, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex') });
		}
		const sidecarBytes = sidecars.reduce((sum, file) => sum + file.bytes, 0);
		return {
			archiveSha256: createHash('sha256').update(await readFile(archive)).digest('hex'),
			allExports,
			cryptoOnly,
			worker,
			sidecars,
			sidecarBytes,
			// Workers are separate runtime entrypoints; compressed binary/data files are counted at shipped size.
			totalGzip: allExports.gzip + worker.gzip + sidecarBytes,
			totalBrotli: allExports.brotli + worker.brotli + sidecarBytes,
		};
	}
	const baseline = await measure('baseline', options.baseline);
	const candidate = await measure('candidate', options.candidate);
	const report = {
		method:
			'All SDK exports and KDBX worker bundled separately; includes every shipped Brotli sidecar. Not a Bundlephobia measurement.',
		node: process.version,
		esbuild: esbuildVersion,
		baseline,
		candidate,
		saved: {
			javascriptGzip: baseline.allExports.gzip - candidate.allExports.gzip,
			totalGzip: baseline.totalGzip - candidate.totalGzip,
			totalBrotli: baseline.totalBrotli - candidate.totalBrotli,
		},
	};
	const json = JSON.stringify(report, null, 2) + '\n';
	if (options.output) {
		await mkdir(dirname(options.output), { recursive: true });
		await writeFile(options.output, json);
	}
	console.log(json);
	return report;
}

if (import.meta.main) await runDirect(['bundle', 'compare'], import.meta.url, { compareBundles });
