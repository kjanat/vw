#!/usr/bin/env bun
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { cases } from './cases.mjs';
import { runDirect, inDirectory } from '../../tools/runtime.mjs';

export async function verifyScorers(distribution = 'dist') {
	return inDirectory(fileURLToPath(new URL('.', import.meta.url)), async () => {
		const { score: reference } = await import('./dist/baseline/index.mjs');
		const { score: baseline } = await import(new URL(`./${distribution}/baseline/index.mjs`, import.meta.url));
		const originalModule = WebAssembly.Module;
		let compilations = 0;
		WebAssembly.Module = new Proxy(originalModule, {
			construct(target, args) {
				compilations++;
				return Reflect.construct(target, args);
			},
		});
		const { createScorer, score: p2 } = await import(new URL(`./${distribution}/p2/index.mjs`, import.meta.url));
		assert.equal(compilations, 0, 'import must not compile WASM');
		assert.equal(p2('password'), 0);
		const initializedCompilations = compilations;
		assert(initializedCompilations > 0);
		assert.equal(p2('VeryStrong123@#'), 4);
		assert.equal(compilations, initializedCompilations, 'repeated calls reuse the instance');
		WebAssembly.Module = originalModule;

		const calls = {};
		const isolated = createScorer(name => calls[name] = (calls[name] ?? 0) + 1);
		for (const { password, context } of cases) {
			assert.equal(baseline(password, context), reference(password, context));
			assert.equal(p2(password, context), baseline(password, context));
			assert.equal(isolated(password, context), baseline(password, context));
		}
		for (
			const [password, expected] of [
				['password', 0],
				['password11', 1],
				['Weakpass2', 2],
				['GoodPass3!', 3],
				['VeryStrong123@#', 4],
			]
		) {
			assert.equal(p2(password), expected);
		}
		assert.equal(p2('asdfjkhkjwer!', ['asdfjkhkjwer']), 1);
		assert.equal(p2('asdfjkhkjwer!'), 4);
		assert.equal(p2('🔑'.repeat(100) + 'NeverScored'), p2('🔑'.repeat(100)));
		assert(calls['clock.wall'] > 0);
		assert(calls['clock.monotonic'] > 0);
		assert(calls['random.hashSeed'] > 0);
		assert(
			Object.keys(calls).every(name =>
				['clock.wall', 'clock.monotonic', 'random.hashSeed', 'environment.empty'].includes(name)
			),
		);
		console.log(
			JSON.stringify(
				{ runtime: process.versions.bun ? 'bun' : 'node', distribution, cases: cases.length, matches: true, calls },
				null,
				2,
			),
		);
	});
}

if (import.meta.main) await runDirect(['experiment', 'wasip2', 'verify'], import.meta.url, { verifyScorers });
