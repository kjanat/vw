import { fileURLToPath } from 'node:url';
import { expect, test } from 'bun:test';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { dataDirectory, openSession, sealSession, withStore, type State } from '#store';

// Resolve launchers such as Volta so signals reach Node itself, not a forwarding shim.
const runtime = Bun.spawnSync(['node', '-p', 'process.execPath'], {
	env: { PATH: process.env.PATH },
	stdout: 'pipe',
	stderr: 'pipe',
});
if (runtime.exitCode !== 0) throw new Error('Could not resolve the Node executable for interruption tests.');
const nodeExecutable = runtime.stdout.toString().trim();

test('profile directory uses its VW override or the XDG config directory', () => {
	const names = ['VW_APPDATA_DIR', 'XDG_CONFIG_HOME'] as const;
	const previous = Object.fromEntries(names.map(name => [name, process.env[name]]));
	try {
		process.env.XDG_CONFIG_HOME = '/synthetic/xdg';
		delete process.env.VW_APPDATA_DIR;
		process.env.VW_APPDATA_DIR = '/synthetic/vw-profile';
		expect(dataDirectory()).toBe('/synthetic/vw-profile');

		delete process.env.VW_APPDATA_DIR;
		expect(dataDirectory()).toBe(join('/synthetic/xdg', 'vaultwarden-cli'));
	} finally {
		for (const name of names) {
			if (previous[name] === undefined) delete process.env[name];
			else process.env[name] = previous[name];
		}
	}
});

test('session wrapping requires the token, and lock invalidates old tokens', () => {
	const state = { version: 1, deviceId: 'device', account: {} } as State;
	const key = Buffer.alloc(64, 7);
	const token = sealSession(state, key);
	expect(openSession(state, token)).toEqual(key);
	expect(() => openSession(state, Buffer.alloc(32, 8).toString('base64'))).toThrow('Invalid session');
	delete state.session;
	expect(() => openSession(state, token)).toThrow('locked');
});
test('state writes are private and atomic, concurrent commands fail safely', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-store-'));
	try {
		await withStore(dir, async (state, save) => {
			state.server = 'https://example.com';
			await save();
			await expect(withStore(dir, async () => {})).rejects.toThrow(
				'Another vw command',
			);
		});
		expect((await stat(dir)).mode & 0o777).toBe(0o700);
		expect((await stat(join(dir, 'state.json'))).mode & 0o777).toBe(0o600);
		expect(
			JSON.parse(await readFile(join(dir, 'state.json'), 'utf8')).server,
		).toBe('https://example.com');
		await withStore(dir, async (state) => {
			expect(state.server).toBe('https://example.com');
		});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});
test('state directories cannot be symlinks', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-symlink-'));
	try {
		await symlink(dir, join(dir, 'link'));
		await expect(withStore(join(dir, 'link'), async () => {})).rejects.toThrow(
			'owned directory',
		);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('malformed state is left intact without a destructive reset or racing backup', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-invalid-state-'));
	try {
		const original = '{invalid synthetic state';
		await writeFile(join(dir, 'state.json'), original, { mode: 0o600 });
		let entered = false;
		await expect(withStore(dir, async (_state, save) => {
			entered = true;
			await save();
		})).rejects.toThrow('Could not read CLI state');
		expect(entered).toBe(false);
		expect(await readFile(join(dir, 'state.json'), 'utf8')).toBe(original);
		expect(await readdir(dir)).toEqual(['state.json']);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

async function interruptStoreOwner(directory: string, signal: 'SIGINT' | 'SIGTERM' | 'SIGKILL'): Promise<void> {
	const module = import.meta.resolve('#store');
	const code = `import { withStore } from ${JSON.stringify(module)};
await withStore(process.argv[1], async () => {
 console.log('holding-store-lock');
 await new Promise(() => { setInterval(() => {}, 1000); });
});`;
	const child = Bun.spawn([nodeExecutable, '--input-type=module', '--eval', code, directory], {
		env: { PATH: process.env.PATH },
		stdout: 'pipe',
		stderr: 'pipe',
		timeout: 5000,
		killSignal: 'SIGKILL',
	});
	try {
		const reader = child.stdout.getReader();
		const ready = await reader.read();
		reader.releaseLock();
		expect(new TextDecoder().decode(ready.value)).toContain('holding-store-lock');
		await expect(withStore(directory, async () => {})).rejects.toThrow('Another vw command');
		child.kill(signal);
		await child.exited;
	} finally {
		if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
		await child.exited;
		await new Response(child.stderr).text();
	}
}

for (const signal of ['SIGINT', 'SIGTERM', 'SIGKILL'] as const) {
	test(`CLI lock and logout recover after a store owner exits through ${signal}`, async () => {
		const dir = await mkdtemp(join(tmpdir(), 'vw-store-interrupt-'));
		try {
			for (const command of ['lock', 'logout']) {
				await withStore(dir, async (state, save) => {
					state.account = {} as NonNullable<State['account']>;
					await save();
				});
				await interruptStoreOwner(dir, signal);
				const child = Bun.spawn([nodeExecutable, fileURLToPath(import.meta.resolve('#main')), command], {
					env: { PATH: process.env.PATH, VW_APPDATA_DIR: dir },
					stdout: 'pipe',
					stderr: 'pipe',
				});
				const [code, stdout, stderr] = await Promise.all([
					child.exited,
					new Response(child.stdout).text(),
					new Response(child.stderr).text(),
				]);
				if (code) throw new Error(`Interrupted-store ${command} failed: ${stderr}`);
				expect(stdout).toContain(command === 'lock' ? 'Your vault is locked.' : 'You have logged out.');
			}
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	}, 10000);
}

for (const boundary of ['detach', 'delete'] as const) {
	test(`store recovers when killed immediately after lock release ${boundary}`, async () => {
		const dir = await mkdtemp(join(tmpdir(), 'vw-store-release-'));
		try {
			const module = import.meta.resolve('#store');
			const code = `import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
const directory = process.argv[1];
const lock = join(directory, '.lock');
const stop = (boundary) => {
 console.log(boundary);
 process.kill(process.pid, 'SIGKILL');
};
const unlink = fs.unlink;
fs.unlink = async (path) => {
 await unlink(path);
 if (String(path).startsWith(lock + '/owner-')) stop('owner-deleted');
};
const rename = fs.rename;
fs.rename = async (from, to) => {
 await rename(from, to);
 if (from === lock && ${JSON.stringify(boundary)} === 'detach') stop('lock-detached');
};
const rm = fs.rm;
fs.rm = async (path, options) => {
 await rm(path, options);
 if (String(path).startsWith(lock + '-') && ${JSON.stringify(boundary)} === 'delete') stop('lock-deleted');
};
syncBuiltinESMExports();
const { withStore } = await import(${JSON.stringify(module)});
await withStore(directory, async (state, save) => {
 state.server = 'https://saved-before-release.example';
 await save();
});
throw new Error('Release interruption was not injected.');`;
			const child = Bun.spawn([nodeExecutable, '--input-type=module', '--eval', code, dir], {
				env: { PATH: process.env.PATH },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 5000,
				killSignal: 'SIGKILL',
			});
			const [, stdout, stderr] = await Promise.all([
				child.exited,
				new Response(child.stdout).text(),
				new Response(child.stderr).text(),
			]);
			expect(stderr).toBe('');
			expect(child.signalCode).toBe('SIGKILL');
			expect(stdout).toMatch(/owner-deleted|lock-detached|lock-deleted/);
			const next = Bun.spawn([
				nodeExecutable,
				'--input-type=module',
				'--eval',
				`
import { withStore } from ${JSON.stringify(module)};
await withStore(process.argv[1], async (state, save) => {
 if (state.server !== 'https://saved-before-release.example') throw new Error('Saved state was lost.');
 state.lastSync = 'recovered';
 await save();
});`,
				dir,
			], {
				env: { PATH: process.env.PATH },
				stdout: 'pipe',
				stderr: 'pipe',
				timeout: 5000,
				killSignal: 'SIGKILL',
			});
			const [exitCode, output, error] = await Promise.all([
				next.exited,
				new Response(next.stdout).text(),
				new Response(next.stderr).text(),
			]);
			expect(error).toBe('');
			expect(output).toBe('');
			expect(exitCode).toBe(0);
			expect(stdout.trim()).toBe(boundary === 'detach' ? 'lock-detached' : 'lock-deleted');
			await withStore(dir, async state => expect(state.lastSync).toBe('recovered'));
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
}

test('concurrent stale-lock recovery never admits two active store writers', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-store-recovery-race-'));
	try {
		await interruptStoreOwner(dir, 'SIGKILL');
		let active = 0, maximum = 0;
		const results = await Promise.allSettled(Array.from({ length: 8 }, () =>
			withStore(dir, async () => {
				maximum = Math.max(maximum, ++active);
				try {
					await new Promise(resolve => setTimeout(resolve, 50));
				} finally {
					active--;
				}
			})));
		expect(results.some(result => result.status === 'fulfilled')).toBe(true);
		expect(maximum).toBe(1);
		await withStore(dir, async () => {});
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}, 10000);

for (const boundary of ['takeover', 'detach', 'delete'] as const) {
	test(`stale-lock recovery survives SIGKILL after ${boundary}`, async () => {
		const dir = await mkdtemp(join(tmpdir(), 'vw-store-reclaim-'));
		const module = import.meta.resolve('#store');
		try {
			await withStore(dir, async (state, save) => {
				state.server = 'https://saved.example';
				await save();
			});
			await interruptStoreOwner(dir, 'SIGKILL');
			// Repeated interruption also verifies recovery of a dead reclaimer's token.
			for (let attempt = 0; attempt < (boundary === 'takeover' ? 2 : 1); attempt++) {
				const code = `import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
const lock = process.argv[1] + '/.lock';
const stop = () => { console.log('interrupted-${boundary}'); process.kill(process.pid, 'SIGKILL'); };
const rename = fs.rename;
fs.rename = async (from, to) => {
 await rename(from, to);
 if (${JSON.stringify(boundary)} === 'takeover' && String(to).startsWith(lock + '/recovery-')) stop();
 if (${JSON.stringify(boundary)} === 'detach' && from === lock) stop();
};
const rm = fs.rm;
fs.rm = async (path, options) => {
 await rm(path, options);
 if (${JSON.stringify(boundary)} === 'delete' && String(path).endsWith('.retired')) stop();
};
syncBuiltinESMExports();
const { withStore } = await import(${JSON.stringify(module)});
await withStore(process.argv[1], async () => { throw new Error('Recovery was not interrupted.'); });`;
				const child = Bun.spawn([nodeExecutable, '--input-type=module', '--eval', code, dir], {
					env: { PATH: process.env.PATH },
					stdout: 'pipe',
					stderr: 'pipe',
					timeout: 5000,
					killSignal: 'SIGKILL',
				});
				const [, stdout, stderr] = await Promise.all([
					child.exited,
					new Response(child.stdout).text(),
					new Response(child.stderr).text(),
				]);
				expect(stderr).toBe('');
				expect(stdout.trim()).toBe(`interrupted-${boundary}`);
				expect(child.signalCode).toBe('SIGKILL');
			}
			const next = Bun.spawn([
				nodeExecutable,
				'--input-type=module',
				'--eval',
				`
import { withStore } from ${JSON.stringify(module)};
await withStore(process.argv[1], async (state, save) => {
 if (state.server !== 'https://saved.example') throw new Error('Saved state was lost.');
 state.lastSync = 'recovered'; await save();
});`,
				dir,
			], { env: { PATH: process.env.PATH }, stdout: 'pipe', stderr: 'pipe', timeout: 5000, killSignal: 'SIGKILL' });
			const [exitCode, stderr] = await Promise.all([
				next.exited,
				new Response(next.stderr).text(),
				new Response(next.stdout).text(),
			]);
			expect(stderr).toBe('');
			expect(exitCode).toBe(0);
			await withStore(dir, async state => expect(state.lastSync).toBe('recovered'));
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	}, 10000);
}

test('legacy locks without verifiable owners are not stolen', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-store-legacy-lock-'));
	try {
		await mkdir(join(dir, '.lock'));
		let ran = false;
		await expect(withStore(dir, async () => {
			ran = true;
		})).rejects.toThrow('no verifiable owner');
		expect(ran).toBe(false);
		expect((await stat(join(dir, '.lock'))).isDirectory()).toBe(true);
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
});

test('contending store commands do not lose completed writes across lock handovers', async () => {
	const dir = await mkdtemp(join(tmpdir(), 'vw-store-handovers-'));
	// A state sync can hold the lock longer than a fixed spin budget on a loaded runner.
	const deadline = Date.now() + 15_000;
	try {
		await Promise.all(Array.from({ length: 6 }, async () => {
			for (let saved = 0; saved < 3;) {
				if (Date.now() >= deadline) throw new Error('Store handover failed to make progress.');
				let entered = false;
				try {
					await withStore(dir, async (state, save) => {
						entered = true;
						state.lastSync = String(Number(state.lastSync ?? 0) + 1);
						await save();
					});
					saved++;
				} catch (error) {
					if (entered) throw error;
					await new Promise(resolve => setTimeout(resolve, 5));
				}
			}
		}));
		await withStore(dir, async state => expect(state.lastSync).toBe('18'));
	} finally {
		await rm(dir, { recursive: true, force: true });
	}
}, 20000);
