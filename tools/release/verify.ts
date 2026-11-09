#!/usr/bin/env bun
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runDirect, inDirectory, repoRoot } from '../runtime.mjs';
import { runConsumerSmoke } from './smoke.mjs';

export function publishedOptionalDependency(metadataUrl: string, repositoryUrl: string) {
	const repo = repositoryUrl.match(/github\.com[:/](?<owner>[^/]+)\/(?<name>[^/.]+)/);
	assert(repo?.groups, `Cannot read GitHub repo from ${repositoryUrl}`);
	const prefix = `/${repo.groups.owner}/${repo.groups.name}`;
	const url = new URL(metadataUrl);
	// Compact preview metadata omits owner/repo. The packed manifest uses the long URL.
	if (url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)) return url.href;
	url.pathname = `${prefix}${url.pathname}`;
	return url.href;
}

export async function verifyRelease(runtime: 'node' | 'bun', previewMetadataPath?: string) {
	return inDirectory(repoRoot, async () => {
		assert(runtime === 'node' || runtime === 'bun', 'Choose node or bun');
		const workspaces = { vaultwarden: 'packages/vaultwarden', cli: 'apps/cli' } as const;
		const metadata = previewMetadataPath
			? JSON.parse(await readFile(previewMetadataPath, 'utf8')) as { packages: { name: string; url: string }[] }
			: undefined;
		const load = async (packageId: keyof typeof workspaces) => {
			const manifest = JSON.parse(await readFile(resolve(workspaces[packageId], 'package.json'), 'utf8')) as {
				name: string;
				version: string;
				repository?: { url?: string };
			};
			if (!metadata) return { ...manifest, source: `file:${resolve('artifacts', `${packageId}.tgz`)}` };
			const published = metadata.packages.find(pkg => pkg.name === manifest.name);
			assert(published, `Missing publication metadata for ${manifest.name}`);
			return { ...manifest, source: published.url };
		};
		const sdk = await load('vaultwarden');
		const cli = await load('cli');
		const consumers = [
			{ label: 'sdk', dependency: sdk, cli: 'optional', options: [] },
			{ label: 'sdk-only', dependency: sdk, cli: 'omitted', options: ['--omit=optional'] },
			{ label: 'cli', dependency: cli, cli: 'direct', options: [] },
		] as const;
		const consumerRoot = resolve('.cache');
		await mkdir(consumerRoot, { recursive: true });
		for (const { label, dependency, cli: installation, options } of consumers) {
			const consumer = await mkdtemp(resolve(consumerRoot, `vw-${label}-consumer-`));
			await writeFile(
				resolve(consumer, 'package.json'),
				JSON.stringify({
					private: true,
					type: 'module',
					dependencies: { [dependency.name]: dependency.source },
					// Same-version registry packages can otherwise satisfy the dependencies between
					// the SDK and CLI independently of the archives. Test the packed packages everywhere.
					...(!metadata ? { overrides: { [sdk.name]: sdk.source, [cli.name]: cli.source } } : {}),
				}),
			);
			execFileSync('bun', ['install', '--ignore-scripts', ...options], { cwd: consumer, stdio: 'inherit' });
			if (dependency === sdk) {
				const installed = JSON.parse(
					await readFile(resolve(consumer, 'node_modules', sdk.name, 'package.json'), 'utf8'),
				) as { optionalDependencies?: Record<string, string> };
				const repository = sdk.repository?.url;
				assert(repository, `Missing repository for ${sdk.name}`);
				assert.deepEqual(installed.optionalDependencies, {
					[cli.name]: metadata ? publishedOptionalDependency(cli.source, repository) : cli.version,
				});
			}
			runConsumerSmoke(runtime, consumer, sdk.version, installation);
		}
	});
}

if (import.meta.main) await runDirect(['release', 'verify'], import.meta.url, { verifyRelease });
