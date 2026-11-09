/** Shared Mailpit policy: allow two seconds for SIGTERM, then force termination. */
export async function terminate(
	exited: Promise<unknown>,
	kill: (signal: 'SIGTERM' | 'SIGKILL') => void,
	timeoutMs = 2000,
	group = false,
): Promise<void> {
	kill('SIGTERM');
	let timer: ReturnType<typeof setTimeout> | undefined;
	try {
		const deadline = new Promise<false>(resolve => {
			timer = setTimeout(() => resolve(false), timeoutMs);
		});
		// A group leader can exit while descendants still ignore SIGTERM.
		const stopped = group ? await deadline : await Promise.race([exited.then(() => true), deadline]);
		if (!stopped) kill('SIGKILL');
	} finally {
		clearTimeout(timer);
	}
	await exited;
}

/** Attempt every resource, retaining failures for separate, redacted reporting. */
export async function cleanupAll(steps: Record<string, () => unknown | Promise<unknown>>) {
	const failures: { name: string; error: unknown }[] = [];
	for (const [name, cleanup] of Object.entries(steps)) {
		try {
			await cleanup();
		} catch (error) {
			failures.push({ name, error });
		}
	}
	return failures;
}

export async function cleanupDiagnostic(error: unknown, redact: (output: string) => Promise<string>): Promise<string> {
	try {
		return await redact(String(error));
	} catch {
		// Redactor failures can contain the raw input. Withhold both errors.
		return 'diagnostics unavailable: redaction failed; output withheld.';
	}
}

export async function readOidcUrl(
	child: { stdout: ReadableStream<Uint8Array>; exited: Promise<number> },
	signal: AbortSignal,
	timeoutMs = 10000,
): Promise<string> {
	const reader = child.stdout.getReader();
	let timer: ReturnType<typeof setTimeout> | undefined;
	let abort: (() => void) | undefined;
	try {
		const cancelled = new Promise<never>((_, reject) => {
			abort = () => reject(new Error('OIDC startup cancelled.'));
			signal.addEventListener('abort', abort, { once: true });
			if (signal.aborted) abort();
			timer = setTimeout(() => reject(new Error('OIDC startup timed out.')), timeoutMs);
		});
		const exited = child.exited.then(code => {
			throw new Error(`OIDC fixture exited during startup (exit ${code}).`);
		});
		const decoder = new TextDecoder();
		let output = '';
		while (true) {
			const chunk = await Promise.race([reader.read(), cancelled, exited]);
			output += decoder.decode(chunk.value, { stream: !chunk.done });
			if (output.includes('\n') || chunk.done) {
				const url = output.trim();
				if (!/^http:\/\/127\.0\.0\.1:\d+$/.test(url)) throw new Error('OIDC fixture did not print a valid URL.');
				return url;
			}
			if (output.length > 1024) throw new Error('OIDC fixture URL exceeded the startup output limit.');
		}
	} finally {
		clearTimeout(timer);
		if (abort) signal.removeEventListener('abort', abort);
		await reader.cancel();
		reader.releaseLock();
	}
}
