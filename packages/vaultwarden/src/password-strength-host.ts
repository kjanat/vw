import { randomBytes } from 'node:crypto';
import { hrtime } from 'node:process';
import type { ImportObject } from './generated/password-strength.js';

/** Only the capabilities used by this scorer; unused WASI operations fail closed. */
export function createScoringHost(onCall?: (name: string) => void): ImportObject {
	const call =
		<Args extends unknown[], Result>(name: string, fn: (...args: Args) => Result) => (...args: Args): Result => {
			onCall?.(name);
			return fn(...args);
		};
	const deny = (name: string) =>
		call(name, (): never => {
			throw new Error(`Unexpected WASI operation in password scorer: ${name}`);
		});
	class Pollable {
		block() {
			return deny('poll.block')();
		}
	}
	class InputStream {}
	class OutputStream {
		checkWrite() {
			return deny('stream.checkWrite')();
		}
		write() {
			return deny('stream.write')();
		}
		blockingFlush() {
			return deny('stream.blockingFlush')();
		}
		subscribe() {
			return deny('stream.subscribe')();
		}
	}
	class IoError {}
	class TerminalInput {}
	class TerminalOutput {}
	const imports: ImportObject = {
		'wasi:clocks/monotonic-clock@0.2.12': {
			now: call('clock.monotonic', () => hrtime.bigint()),
			subscribeDuration: deny('clock.subscribeDuration'),
		},
		'wasi:clocks/wall-clock@0.2.12': {
			now: call('clock.wall', () => {
				const milliseconds = Date.now();
				const seconds = Math.floor(milliseconds / 1000);
				return { seconds: BigInt(seconds), nanoseconds: (milliseconds - seconds * 1000) * 1_000_000 };
			}),
		},
		'wasi:random/insecure-seed@0.2.12': {
			insecureSeed: call('random.hashSeed', (): [bigint, bigint] => {
				const bytes = randomBytes(16);
				return [bytes.readBigUInt64LE(0), bytes.readBigUInt64LE(8)];
			}),
		},
		'wasi:cli/environment@0.2.12': { getEnvironment: call('environment.empty', () => []) },
		'wasi:cli/exit@0.2.12': { exit: deny('exit'), exitWithCode: deny('exitWithCode') },
		'wasi:cli/stdin@0.2.12': { getStdin: deny('stdin') },
		'wasi:cli/stdout@0.2.12': { getStdout: deny('stdout') },
		'wasi:cli/stderr@0.2.12': { getStderr: deny('stderr') },
		'wasi:cli/terminal-input@0.2.12': { TerminalInput },
		'wasi:cli/terminal-output@0.2.12': { TerminalOutput },
		'wasi:cli/terminal-stdin@0.2.12': { getTerminalStdin: deny('terminal.stdin') },
		'wasi:cli/terminal-stdout@0.2.12': { getTerminalStdout: deny('terminal.stdout') },
		'wasi:cli/terminal-stderr@0.2.12': { getTerminalStderr: deny('terminal.stderr') },
		'wasi:io/error@0.2.12': { Error: IoError },
		'wasi:io/poll@0.2.12': { Pollable, poll: deny('poll') },
		'wasi:io/streams@0.2.12': { InputStream, OutputStream },
	};
	// Jco 1.40 types use versioned keys; its JS instantiator uses unversioned keys.
	// Keep both aliases while checking the host against the generated WIT types.
	return Object.assign(
		imports,
		Object.fromEntries(
			Object.entries(imports).map(([name, value]) => [name.replace(/@[^@]+$/, ''), value]),
		),
	);
}
