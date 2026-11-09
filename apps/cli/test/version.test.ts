import { fileURLToPath } from 'node:url';
import { test, expect } from 'bun:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SDK_VERSION } from '@kjanat/vaultwarden';
import { CLI_PACKAGE, checkForUpdates } from '#version-commands';

test('CLI version and SDK version identify their own package manifests before login', async () => {
	const directory = await mkdtemp(join(tmpdir(), 'vw-version-'));
	const sdk = await Bun.file(new URL('../../../packages/vaultwarden/package.json', import.meta.url)).json();
	try {
		for (const [command, expected] of [['--version', CLI_PACKAGE.version], ['sdk-version', sdk.version]] as const) {
			const child = Bun.spawn(['node', fileURLToPath(import.meta.resolve('#main')), command], {
				env: { PATH: process.env.PATH, VW_APPDATA_DIR: directory },
				stdout: 'pipe',
				stderr: 'pipe',
			});
			const [code, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			expect(code).toBe(0);
			expect(stdout).toContain(expected);
			expect(stderr).toBe('');
		}
		expect(SDK_VERSION).toBe(sdk.version);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
});
test('private builds report their unpublished update channel without making a network request', async () => {
	let calls = 0;
	const transport = (async () => {
		calls++;
		throw new Error('Must not request.');
	}) as unknown as typeof fetch;
	expect(await checkForUpdates({ name: '@example/private', version: '1.2.3', private: true }, transport))
		.toEqual({ name: '@example/private', current: '1.2.3', status: 'private' });
	expect(calls).toBe(0);
});
test('published updates use the independent package registry path without vault credentials or redirects', async () => {
	const transport = (async (url: unknown, init: RequestInit) => {
		expect(String(url)).toBe('https://registry.npmjs.org/%40example%2Fcli/latest');
		expect(init.redirect).toBe('error');
		expect(init.headers).toEqual({ Accept: 'application/json' });
		expect(init.signal).toBeInstanceOf(AbortSignal);
		return Response.json({ version: '1.3.0' });
	}) as unknown as typeof fetch;
	expect(await checkForUpdates({ name: '@example/cli', version: '1.2.3' }, transport))
		.toEqual({ name: '@example/cli', current: '1.2.3', latest: '1.3.0', status: 'available' });
});
test('update precedence handles numeric prereleases, stable versions, build metadata and development versions ahead of releases', async () => {
	for (
		const [current, latest, expected] of [
			['1.2.3', '1.2.3', 'current'],
			['2.0.0', '1.9.99', 'ahead'],
			['1.2.3+build.1', '1.2.3+build.2', 'current'],
			['1.2.3-rc.2', '1.2.3-rc.10', 'available'],
			['1.2.3-rc.10', '1.2.3-rc.2', 'ahead'],
			['1.2.3-rc.2', '1.2.3', 'available'],
			['1.2.3', '1.2.3-rc.2', 'ahead'],
			['1.2.3-1', '1.2.3-alpha', 'available'],
			['1.2.3-alpha', '1.2.3-alpha.1', 'available'],
			['1.2.3-beta', '1.2.3-alpha', 'ahead'],
		] as const
	) {
		const transport = (async () => Response.json({ version: latest })) as unknown as typeof fetch;
		expect((await checkForUpdates({ name: 'example', version: current }, transport)).status).toBe(expected);
	}
});
test('unpublished packages and update-channel failures remain distinct and never echo server data', async () => {
	const metadata = { name: 'example', version: '1.2.3' };
	const absent = (async () => new Response(null, { status: 404 })) as unknown as typeof fetch;
	expect((await checkForUpdates(metadata, absent)).status).toBe('unpublished');
	for (const status of [401, 429, 500]) {
		const transport =
			(async () => Response.json({ message: 'synthetic secret' }, { status })) as unknown as typeof fetch;
		await expect(checkForUpdates(metadata, transport)).rejects.toThrow(`HTTP ${status}`);
	}
	for (const version of [null, 'secret-invalid-version', '1.2.3-01', '1.2.3+bad\nterminal']) {
		const transport = (async () => Response.json({ version })) as unknown as typeof fetch;
		try {
			await checkForUpdates(metadata, transport);
			throw new Error('Expected rejection.');
		} catch (error) {
			expect(String(error)).toContain('Invalid');
			expect(String(error)).not.toContain('secret-invalid-version');
		}
	}
	const disconnected = (async () => {
		throw new Error('synthetic secret');
	}) as unknown as typeof fetch;
	await expect(checkForUpdates(metadata, disconnected)).rejects.toThrow('Could not check');
});
