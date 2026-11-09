import { test } from 'bun:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cleanupAll, cleanupDiagnostic, readOidcUrl, terminate } from '#test/fixtures/lifecycle';

const hanging = "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);";

function oidc(source: string) {
	return Bun.spawn([process.execPath, '-e', source], { stdin: 'ignore', stdout: 'pipe', stderr: 'ignore' });
}

test('owned test groups escalate to SIGKILL within the shutdown deadline', async () => {
	const child = spawn(process.execPath, ['-e', `${hanging} console.log('ready');`], {
		detached: true,
		stdio: ['ignore', 'pipe', 'ignore'],
	});
	const exited = new Promise<void>(resolve => child.once('exit', () => resolve()));
	try {
		await new Promise<void>(resolve => child.stdout!.once('data', () => resolve()));
		assert.ok(child.pid);
		const pid = child.pid;
		const start = performance.now();
		await terminate(exited, signal => process.kill(-pid, signal), 30, true);
		assert.equal(child.signalCode, 'SIGKILL');
		assert.ok(performance.now() - start < 2000);
		assert.throws(() => process.kill(-pid, 0));
	} finally {
		if (child.pid && child.signalCode === null) process.kill(-child.pid, 'SIGKILL');
		await exited;
	}
});

test('OIDC shutdown escalates when SIGTERM is ignored', async () => {
	const child = oidc(`${hanging} console.log('http://127.0.0.1:12345');`);
	try {
		assert.equal(await readOidcUrl(child, new AbortController().signal), 'http://127.0.0.1:12345');
		const start = performance.now();
		await terminate(child.exited, signal => child.kill(signal), 30);
		assert.equal(child.signalCode, 'SIGKILL');
		assert.ok(performance.now() - start < 2000);
	} finally {
		child.kill('SIGKILL');
		await child.exited;
	}
});

test('OIDC startup has a deadline when no URL is printed', async () => {
	const child = oidc(hanging);
	const start = performance.now();
	try {
		await assert.rejects(readOidcUrl(child, new AbortController().signal, 200), /timed out/);
	} finally {
		await terminate(child.exited, signal => child.kill(signal), 30);
	}
	assert.ok(performance.now() - start < 2000);
	assert.throws(() => process.kill(child.pid, 0));
});

test('OIDC startup responds to cancellation and early exit', async () => {
	const child = oidc(hanging);
	const controller = new AbortController();
	const starting = readOidcUrl(child, controller.signal);
	controller.abort();
	try {
		await assert.rejects(starting, /cancelled/);
	} finally {
		await terminate(child.exited, signal => child.kill(signal), 30);
	}
	const early = oidc('process.exit(17)');
	await assert.rejects(readOidcUrl(early, new AbortController().signal), /exit 17|valid URL/);
	await early.exited;
});

test('cleanup attempts every resource and preserves the primary failure', async () => {
	const primary = new Error('primary test failure');
	const cleanupError = new Error('synthetic-secret');
	const attempted: string[] = [];
	let failures: Awaited<ReturnType<typeof cleanupAll>> = [];
	await assert.rejects(async () => {
		try {
			throw primary;
		} finally {
			failures = await cleanupAll(Object.fromEntries(
				['tests', 'Mailpit', 'OIDC', 'Docker', 'directory', 'listeners'].map(name => [name, async () => {
					attempted.push(name);
					if (name === 'Mailpit' || name === 'Docker') throw cleanupError;
				}]),
			));
		}
	}, error => error === primary);
	assert.deepEqual(attempted, ['tests', 'Mailpit', 'OIDC', 'Docker', 'directory', 'listeners']);
	assert.deepEqual(failures.map(failure => failure.name), ['Mailpit', 'Docker']);
	assert.ok(failures.every(failure => failure.error === cleanupError));
});

test('cleanup diagnostics are redacted and redactor failures withhold raw errors', async () => {
	const failure = new Error('synthetic-secret');
	assert.equal(
		await cleanupDiagnostic(failure, async output => output.replaceAll('synthetic-secret', '<redacted>')),
		'Error: <redacted>',
	);
	assert.equal(
		await cleanupDiagnostic(failure, async () => {
			throw failure;
		}),
		'diagnostics unavailable: redaction failed; output withheld.',
	);
});

test('group escalation still kills descendants after the leader exits on SIGTERM', async () => {
	const source = `
		const { spawn } = require('node:child_process');
		spawn(process.execPath, ['-e', ${
			JSON.stringify(`${hanging} console.log('ready');`)
		}], { stdio: ['ignore', 'inherit', 'ignore'] });
	`;
	const child = spawn(process.execPath, ['-e', source], { detached: true, stdio: ['ignore', 'pipe', 'ignore'] });
	const exited = new Promise<void>(resolve => child.once('exit', () => resolve()));
	const closed = new Promise<void>(resolve => child.stdout!.once('close', () => resolve()));
	assert.ok(child.pid);
	const pid = child.pid;
	try {
		await new Promise<void>(resolve => child.stdout!.once('data', () => resolve()));
		await terminate(exited, signal => process.kill(-pid, signal), 50, true);
		assert.equal(child.signalCode, 'SIGTERM');
		// The descendant inherits stdout; closing it proves the descendant was also killed.
		await closed;
	} finally {
		try {
			process.kill(-pid, 'SIGKILL');
		} catch { /* Already stopped. */ }
		await exited;
	}
});
