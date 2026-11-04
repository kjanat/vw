import { expect, test } from 'bun:test';
import { createServer, createConnection } from 'node:net';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { loopbackPorts, startMailpit, type MailpitOptions } from '#test/fixtures/mailpit';

const redact = async (text: string) => text.replaceAll('synthetic-secret', '<redacted>');

async function fakeMailpit(
	mode: 'exit' | 'hang' | 'ready',
	run: (options: MailpitOptions, pid: () => Promise<number>) => Promise<void>,
) {
	const directory = await mkdtemp(join(tmpdir(), 'vw-mailpit-test-'));
	const pidFile = join(directory, 'pid');
	const script = join(directory, 'fixture.ts');
	await Bun.write(
		script,
		`
		await Bun.write(${JSON.stringify(pidFile)}, String(process.pid));
		console.error('fixture diagnostic: synthetic-secret');
		${mode === 'exit' ? 'process.exit(17);' : "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000);"}
		${
			mode === 'ready'
				? `
			const port = flag => Number(Bun.argv[Bun.argv.indexOf(flag) + 1].split(':').at(-1));
			Bun.serve({ hostname: '127.0.0.1', port: port('--listen'), fetch: () => new Response('ready') });
			Bun.listen({ hostname: '127.0.0.1', port: port('--smtp'), socket: {
				open(socket) { socket.write('220 fixture ready\\r\\n'); }, data() {},
			} });
		`
				: ''
		}
	`,
	);
	try {
		await run(
			{ command: [process.execPath, script], redact, shutdownTimeoutMs: 30 },
			async () => Number(await Bun.file(pidFile).text()),
		);
	} finally {
		await rm(directory, { recursive: true, force: true });
	}
}

function expectStopped(pid: number) {
	expect(() => process.kill(pid, 0)).toThrow();
}

test('Mailpit reports a missing executable before starting the fixture', async () => {
	await expect(startMailpit({ command: ['/nonexistent/vw-mailpit'], redact })).rejects.toThrow('executable not found');
});

test('Mailpit startup errors include the exit status and redacted diagnostics', async () => {
	await fakeMailpit('exit', async (options, pid) => {
		let failure: unknown;
		try {
			await startMailpit(options);
		} catch (error) {
			failure = error;
		}
		expect(String(failure)).toContain('exit 17');
		expect(String(failure)).toContain('fixture diagnostic: <redacted>');
		expect(String(failure)).not.toContain('synthetic-secret');
		expectStopped(await pid());
	});
});

test('Mailpit readiness times out and forcibly stops an unresponsive process', async () => {
	await fakeMailpit('hang', async (options, pid) => {
		await expect(startMailpit({ ...options, startupTimeoutMs: 300 })).rejects.toThrow('Mailpit startup failed');
		expectStopped(await pid());
	});
});

test('cancelling Mailpit startup stops the process and reports the cancellation', async () => {
	await fakeMailpit('hang', async (options, pid) => {
		const controller = new AbortController();
		const starting = startMailpit({ ...options, signal: controller.signal });
		// Wait for the process to start so this exercises cleanup, not pre-start rejection.
		for (let attempt = 0; attempt < 100; attempt++) {
			try {
				await pid();
				break;
			} catch {
				await Bun.sleep(10);
			}
		}
		controller.abort(new Error('cancelled by test'));
		await expect(starting).rejects.toThrow('cancelled by test');
		expectStopped(await pid());
	});
});

test('cancellation after readiness forcibly stops a process that ignores SIGTERM', async () => {
	await fakeMailpit('ready', async (options, pid) => {
		const controller = new AbortController();
		const fixture = await startMailpit({ ...options, signal: controller.signal });
		try {
			controller.abort();
			await fixture.exited;
			expectStopped(await pid());
		} finally {
			await fixture.stop();
		}
	});
});

test.skipIf(!Bun.which('mailpit'))(
	'Mailpit reports an occupied SMTP port and cleans up its HTTP listener',
	async () => {
		const server = createServer();
		await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
		const port = (server.address() as { port: number }).port;
		const [apiPort] = await loopbackPorts(1);
		try {
			await expect(startMailpit({ smtpPort: port, apiPort, redact })).rejects.toThrow('address already in use');
			await expect(fetch(`http://127.0.0.1:${apiPort}/readyz`)).rejects.toThrow();
		} finally {
			await new Promise<void>(resolve => server.close(() => resolve()));
		}
	},
);

async function deliver(port: number) {
	const socket = createConnection({ host: '127.0.0.1', port, signal: AbortSignal.timeout(3000) });
	const reader = createInterface({ input: socket, crlfDelay: Infinity });
	const lines = reader[Symbol.asyncIterator]();
	const response = async (code: number) => {
		let line: IteratorResult<string>;
		do {
			line = await lines.next();
			expect(line.done).toBe(false);
			expect(line.value.startsWith(String(code))).toBe(true);
		} while (line.value[3] === '-');
	};
	const send = async (command: string, code: number) => {
		socket.write(`${command}\r\n`);
		await response(code);
	};
	try {
		await response(220);
		await send('EHLO localhost', 250);
		await send('MAIL FROM:<fixture@example.com>', 250);
		await send('RCPT TO:<recipient@example.com>', 250);
		await send('DATA', 354);
		await send(
			'From: fixture@example.com\r\nTo: recipient@example.com\r\nSubject: fixture\r\n\r\nVerification code: 123456\r\n.',
			250,
		);
		await send('QUIT', 221);
	} finally {
		reader.close();
		socket.destroy();
	}
}

test.skipIf(!Bun.which('mailpit'))(
	'parallel Mailpit processes capture isolated SMTP messages and stop on cancellation',
	async () => {
		const first = new AbortController(), second = new AbortController();
		const fixtures: Awaited<ReturnType<typeof startMailpit>>[] = [];
		try {
			const started = await Promise.allSettled([
				startMailpit({ redact, signal: first.signal }),
				startMailpit({ redact, signal: second.signal }),
			]);
			for (const result of started) if (result.status === 'fulfilled') fixtures.push(result.value);
			for (const result of started) if (result.status === 'rejected') throw result.reason;
			expect(new Set(fixtures.flatMap(f => [f.smtpPort, Number(new URL(f.apiUrl).port)])).size).toBe(4);
			await deliver(fixtures[0]!.smtpPort);
			const messages = await Promise.all(
				fixtures.map(async f => (await (await fetch(`${f.apiUrl}/api/v1/messages`)).json()).messages),
			);
			expect(messages[0]).toHaveLength(1);
			expect(messages[1]).toHaveLength(0);
			const message = await (await fetch(`${fixtures[0]!.apiUrl}/api/v1/message/${messages[0][0].ID}`)).json();
			expect(message.Text).toContain('123456');
			first.abort();
			await fixtures[0]!.exited;
			expect(() => fixtures[0]!.assertRunning()).toThrow('exited unexpectedly');
		} finally {
			await Promise.all(fixtures.map(f => f.stop()));
			for (const fixture of fixtures) expectStopped(fixture.pid);
		}
	},
);
