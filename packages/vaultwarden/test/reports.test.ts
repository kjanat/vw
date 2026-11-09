import { test, expect } from 'bun:test';
import { PasswordExposureClient, passwordHealth, passwordStrength } from '#reports';
import type { VaultItem } from '#models';

const suffix = '1E4C9B93F3F0682250B6CF8331B7EE68FD8';
const padded = `${suffix}:123\r\n00000000000000000000000000000000000:0\r\n`;
const login = (id: string, password: string, username = ''): VaultItem => ({
	id,
	type: 1,
	name: `Item ${id}`,
	login: { password, username },
});

test('password-health scoring uses username tokens, no global brand words, and a Unicode scalar cap', () => {
	for (
		const [password, score] of [
			['password', 0],
			['password11', 1],
			['Weakpass2', 2],
			['GoodPass3!', 3],
			['VeryStrong123@#', 4],
		] as const
	) {
		expect(passwordStrength(password)).toBe(score);
	}
	expect(passwordStrength('asdfjkhkjwer!')).toBe(4);
	expect(passwordStrength('asdfjkhkjwer!', 'asdfjkhkjwer@example.com')).toBe(1);
	expect(passwordStrength('asdfjkhkjwer!', 'ASDFJKHKJWER')).toBe(1);
	expect(passwordStrength('bitwarden')).toBeGreaterThan(0);
	expect(passwordStrength('🔑'.repeat(100) + 'NeverScored')).toBe(passwordStrength('🔑'.repeat(100)));
});
test('WASM scoring handles empty and Unicode inputs without retaining previous username context', () => {
	expect(passwordStrength('')).toBe(0);
	expect(passwordStrength('asdfjkhkjwer!', 'asdfjkhkjwer@example.com')).toBe(1);
	expect(passwordStrength('asdfjkhkjwer!')).toBe(4);
	expect(passwordStrength('asdfjkhkjwer!', 'unrelated@example.com')).toBe(4);
	expect(passwordStrength('𐰊𐰂𐰄𐰀𐰁')).toBe(1);
	expect(passwordStrength('!QASW@#EDFR$%TGHY^&UJKI*(OL')).toBe(4);
});
test('offline reports include archived and organization logins, exclude trash, non-logins and empty passwords, and count exact reuse', async () => {
	const items = [
		login('a', 'private-secret-token'),
		{ ...login('b', 'private-secret-token'), archivedDate: '2026-01-01' },
		{ ...login('c', 'Private-secret-token'), organizationId: 'org' },
		{ ...login('d', 'private-secret-token'), deletedDate: '2026-01-01' },
		login('e', ''),
		{ id: 'f', type: 2, name: 'Note', login: { password: 'private-secret-token' } },
	];
	let startedWith = -1;
	const rows = await passwordHealth(items, {
		checkExposed: false,
		onStart: count => startedWith = count,
		exposure: new PasswordExposureClient({
			fetch: (async () => {
				throw new Error('must not request');
			}) as unknown as typeof fetch,
		}),
	});
	expect(startedWith).toBe(3);
	expect(rows.map(row => row.id)).toEqual(['a', 'b', 'c']);
	expect(rows.map(row => row.reuseCount)).toEqual([2, 2, null]);
	expect(rows.every(row => !row.exposed && row.exposedCount === null && row.exposedError === null)).toBe(true);
	expect(JSON.stringify(rows)).not.toContain('private-secret-token');
	expect(JSON.stringify(rows)).not.toContain('username');
});
test('range requests send only five SHA1 characters, ask for padding, and never include credentials', async () => {
	let calls = 0;
	const client = new PasswordExposureClient({
		baseUrl: 'https://mirror.example/prefix',
		fetch: (async (url: unknown, init?: RequestInit) => {
			calls++;
			expect(url).toBe('https://mirror.example/prefix/range/5BAA6');
			expect(init!.redirect).toBe('error');
			expect(init!.credentials).toBe('omit');
			const headers = new Headers(init!.headers);
			expect(headers.get('Add-Padding')).toBe('true');
			expect(headers.has('Authorization')).toBe(false);
			expect(init!.body).toBeUndefined();
			expect(String(url)).not.toContain(suffix);
			return new Response(padded.toLowerCase());
		}) as unknown as typeof fetch,
	});
	expect(await client.count('password')).toBe(123);
	expect(calls).toBe(1);
});
test('reports coalesce repeated-password lookups and distinguish failures from zero matches', async () => {
	const requested: string[] = [];
	const client = new PasswordExposureClient({
		fetch: (async (url: unknown) => {
			requested.push(String(url));
			return String(url).endsWith('5BAA6')
				? new Response(padded)
				: new Response('private service error', { status: 503 });
		}) as unknown as typeof fetch,
	});
	const rows = await passwordHealth([login('a', 'password'), login('b', 'password'), login('c', 'different')], {
		exposure: client,
	});
	expect(requested).toHaveLength(2);
	expect(rows[0]).toMatchObject({ exposed: true, exposedCount: 123, reuseCount: 2, exposedError: null });
	expect(rows[1]).toMatchObject({ exposed: true, exposedCount: 123 });
	expect(rows[2]).toMatchObject({
		exposed: false,
		exposedCount: null,
		exposedError: 'Password exposure request failed (HTTP 503).',
	});
	expect(JSON.stringify(rows)).not.toContain('private service error');
});
test('malformed HTTP 200 exposure rows follow the pinned SDK and count as zero', async () => {
	for (
		const body of ['', '<html>unavailable</html>', `${suffix}:not-a-count`, `${suffix}:4294967296`, `${suffix}:-1`]
	) {
		const client = new PasswordExposureClient({ fetch: (async () => new Response(body)) as unknown as typeof fetch });
		expect(await client.count('password')).toBe(0);
	}
	const client = new PasswordExposureClient({
		fetch: (async () => new Response('00000000000000000000000000000000000:0')) as unknown as typeof fetch,
	});
	expect(await client.count('password')).toBe(0);
	const empty = new PasswordExposureClient({ fetch: (async () => new Response(null)) as unknown as typeof fetch });
	expect(await empty.count('password')).toBe(0);
	const duplicate = new PasswordExposureClient({
		fetch: (async () => new Response(`${suffix}:invalid\n${suffix}:12`)) as unknown as typeof fetch,
	});
	expect(await duplicate.count('password')).toBe(0);
	expect(() => new PasswordExposureClient({ baseUrl: 'http://remote.example' })).toThrow('HTTPS');
});

test('malformed successful exposure bodies do not produce a local error field', async () => {
	const client = new PasswordExposureClient({ fetch: (async () => new Response('')) as unknown as typeof fetch });
	expect(await passwordHealth([login('a', 'password')], { exposure: client })).toMatchObject([{
		exposed: false,
		exposedCount: null,
		exposedError: null,
	}]);
});
test('exposure requests obey a shared concurrency limit and release slots after failures', async () => {
	let active = 0, peak = 0, calls = 0;
	const release: (() => void)[] = [];
	const client = new PasswordExposureClient({
		maxConcurrent: 2,
		fetch: (async () => {
			active++;
			const call = ++calls;
			peak = Math.max(peak, active);
			await new Promise<void>(resolve => release.push(resolve));
			active--;
			return new Response(padded, { status: call === 1 ? 503 : 200 });
		}) as unknown as typeof fetch,
	});
	const requests = Array.from({ length: 5 }, (_, i) => client.count(`Synthetic-${i}`).catch(() => -1));
	for (let i = 0; i < 10 && calls < 5; i++) {
		await Bun.sleep(0);
		for (const resolve of release.splice(0)) resolve();
	}
	expect(await Promise.all(requests)).toContain(-1);
	expect(calls).toBe(5);
	expect(peak).toBe(2);
});
test('timeouts release a request slot, and oversized bodies are canceled', async () => {
	const client = new PasswordExposureClient({
		timeoutMs: 10,
		maxConcurrent: 1,
		fetch: (async (_url: unknown, init?: RequestInit) => {
			return new Promise<Response>((_resolve, reject) =>
				init!.signal!.addEventListener('abort', () => reject(new Error('private URL in transport error')))
			);
		}) as unknown as typeof fetch,
	});
	await expect(client.count('password')).rejects.toThrow('failed or timed out');
	await expect(client.count('password')).rejects.toThrow('failed or timed out');
	let canceled = false;
	const large = new PasswordExposureClient({
		fetch: (async () =>
			new Response(
				new ReadableStream({
					start(controller) {
						controller.enqueue(new Uint8Array(4 * 1024 * 1024 + 1));
					},
					cancel() {
						canceled = true;
					},
				}),
			)) as unknown as typeof fetch,
	});
	await expect(large.count('password')).rejects.toThrow('size limit');
	expect(canceled).toBe(true);
});
