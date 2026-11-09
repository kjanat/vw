import { terminate } from '#test/fixtures/lifecycle';
import { createConnection, createServer } from 'node:net';

/** Hold all reservations until every port has been selected, so none can be selected twice. */
export async function loopbackPorts(count: number): Promise<number[]> {
	const servers = [] as ReturnType<typeof createServer>[];
	try {
		const ports: number[] = [];
		for (let index = 0; index < count; index++) {
			const server = createServer();
			servers.push(server);
			await new Promise<void>((resolve, reject) => {
				server.once('error', reject);
				server.listen(0, '127.0.0.1', resolve);
			});
			const address = server.address();
			if (!address || typeof address === 'string') throw new Error('Could not reserve a loopback port.');
			ports.push(address.port);
		}
		return ports;
	} finally {
		await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
	}
}

function smtpReady(port: number, signal: AbortSignal): Promise<boolean> {
	return new Promise(resolve => {
		const socket = createConnection({ host: '127.0.0.1', port, signal });
		let greeting = '';
		const finish = (ready: boolean) => {
			socket.destroy();
			resolve(ready);
		};
		socket.setTimeout(500, () => finish(false));
		socket.on('error', () => finish(false));
		socket.on('end', () => finish(false));
		socket.on('data', chunk => {
			greeting += chunk.toString();
			if (greeting.includes('\n')) finish(greeting.startsWith('220'));
		});
	});
}

export interface MailpitOptions {
	signal?: AbortSignal;
	redact: (output: string) => Promise<string>;
	command?: string[];
	smtpPort?: number;
	apiPort?: number;
	startupTimeoutMs?: number;
	shutdownTimeoutMs?: number;
}

/** A foreground fixture with no inherited MP_* settings, relay, or persistent database. */
export async function startMailpit(options: MailpitOptions) {
	options.signal?.throwIfAborted();
	const command = options.command ?? [Bun.which('mailpit') ?? 'mailpit'];
	if (!Bun.which(command[0]!)) {
		throw new Error('Mailpit executable not found; run mise install github:axllent/mailpit.');
	}
	const [smtpPort, apiPort] = await loopbackPorts(2);
	const smtp = options.smtpPort ?? smtpPort!;
	const apiUrl = `http://127.0.0.1:${options.apiPort ?? apiPort}`;
	const child = Bun.spawn([
		...command,
		'--smtp',
		`127.0.0.1:${smtp}`,
		'--listen',
		new URL(apiUrl).host,
		'--disable-version-check',
	], {
		env: { PATH: process.env.PATH },
		stdin: 'ignore',
		stdout: 'pipe',
		stderr: 'pipe',
	});
	let output = '';
	const capture = async (stream: ReadableStream<Uint8Array>) => {
		const decoder = new TextDecoder();
		for await (const chunk of stream) output = (output + decoder.decode(chunk, { stream: true })).slice(-8192);
		output = (output + decoder.decode()).slice(-8192);
	};
	const streams = Promise.all([capture(child.stdout), capture(child.stderr)]);
	let stopping = false;
	let shutdown: Promise<void> | undefined;
	const abort = (): void => {
		void fixture.stop();
	};
	const fixture = {
		apiUrl,
		smtpPort: smtp,
		pid: child.pid,
		exited: child.exited,
		get stopping() {
			return stopping;
		},
		async diagnostics(): Promise<string> {
			try {
				return await options.redact(output);
			} catch {
				// Redactor errors can contain raw input too. Never print them or replace the primary failure.
				return 'Mailpit diagnostics unavailable: redaction failed; output withheld.';
			}
		},
		assertRunning() {
			if (child.exitCode !== null || child.signalCode !== null) {
				throw new Error(`Mailpit exited unexpectedly (exit ${child.exitCode}, signal ${child.signalCode}).`);
			}
		},
		stop(): Promise<void> {
			return shutdown ??= (async () => {
				stopping = true;
				options.signal?.removeEventListener('abort', abort);
				if (child.exitCode === null && child.signalCode === null) {
					await terminate(child.exited, signal => child.kill(signal), options.shutdownTimeoutMs);
				}
				await child.exited;
				await streams;
			})();
		},
	};
	options.signal?.addEventListener('abort', abort, { once: true });
	try {
		const signal = AbortSignal.any([
			AbortSignal.timeout(options.startupTimeoutMs ?? 10000),
			...(options.signal ? [options.signal] : []),
		]);
		while (true) {
			signal.throwIfAborted();
			fixture.assertRunning();
			try {
				const response = await fetch(`${apiUrl}/readyz`, {
					signal: AbortSignal.any([signal, AbortSignal.timeout(500)]),
				});
				await response.body?.cancel();
				if (response.ok && await smtpReady(smtp, signal)) {
					signal.throwIfAborted();
					fixture.assertRunning();
					return fixture;
				}
			} catch { /* Retry while the owned process is starting; the deadline and exit checks are outside this catch. */ }
			await Bun.sleep(25);
		}
	} catch (error) {
		await fixture.stop();
		throw new Error(
			`Mailpit startup failed: ${error instanceof Error ? error.message : String(error)}\n${await fixture
				.diagnostics()}`,
			{ cause: error },
		);
	}
}
