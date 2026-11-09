import { ApiError, field, type JsonObject, object, text, VaultwardenClient } from '#client';
import { vaultwardenCapabilities, vaultwardenVersionAtLeast } from '#capabilities';
import {
	decrypt,
	decryptAttachment,
	decryptSharedKey,
	encrypt,
	encryptAttachment,
	encryptedAttachmentSize,
	encryptSharedKey,
} from '#crypto';
import { fingerprintWords } from '#fingerprint';
import { DeviceApprovalService } from '#device-approval';
import { encryptItem } from '#item-codec';
import type { EditVaultItem, ItemFilter, VaultFolder, VaultItem } from '#models';
import { passwordHealth, type PasswordHealthOptions, type PasswordHealthRow } from '#reports';
import { applicableOrganizationPolicies } from '#policy';
import { findNamedObject, MultipleResultsError, searchItemsBasic, VaultObjectNotFoundError } from '#search';
import { SendService } from '#sends';
import {
	type ExportFormat,
	exportVault,
	type ImportFormat,
	type ImportResult,
	importVault,
	type TransferOptions,
} from '#transfer';
import { filterItemsByUrl, type UriMatchOptions } from '#uri-match';
import { decryptOwnedItem } from '#vault';
import { randomBytes } from 'node:crypto';

const normalizedId = (id: string) => text(id).toLowerCase();
const idPath = (id: string) => encodeURIComponent(normalizedId(id));
const maxBitwardenAttachmentBytes = 500 * 1024 * 1024;
export function assertAttachmentSize(plaintextSize: number, vaultwarden: boolean): void {
	if (!Number.isSafeInteger(plaintextSize) || plaintextSize < 0) throw new Error('Invalid attachment size.');
	if (vaultwarden) {
		if (encryptedAttachmentSize(plaintextSize) > vaultwardenCapabilities.fileUploads.maximumEncryptedBytes) {
			throw new Error('Attachment exceeds the supported Vaultwarden size.');
		}
	} else if (plaintextSize > maxBitwardenAttachmentBytes) {
		throw new Error('Attachment exceeds Bitwarden’s 500 MiB per-file limit.');
	}
}
function sameId(value: unknown, id: string): boolean {
	return typeof value === 'string' && normalizedId(value) === normalizedId(id);
}
function sameOptionalId(value: unknown, id: unknown): boolean {
	return value == null || id == null ? value == null && id == null : typeof id === 'string' && sameId(value, id);
}
function array(value: unknown): JsonObject[] {
	if (!Array.isArray(value)) throw new Error('Missing vault objects. Sync first.');
	return value.map(object);
}
function matchesId(value: unknown, filter: string): boolean {
	return filter === 'null' ? value == null : filter === 'notnull' ? value != null : value === filter;
}
function policyData(value: unknown): JsonObject {
	if (typeof value === 'string') {
		try {
			return object(JSON.parse(value));
		} catch {
			return {};
		}
	}
	return object(value);
}
/** Operates on an encrypted snapshot. No storage or terminal dependencies. Caller owns key lifetime. */
export class VaultService {
	constructor(
		readonly client: VaultwardenClient,
		readonly accessToken: string,
		readonly snapshot: JsonObject,
		private readonly userKey: Uint8Array,
	) {}
	async fingerprint(user = 'me'): Promise<string> {
		const profile = object(this.snapshot.profile);
		const id = user.toLowerCase() === 'me' ? text(profile.id) : user;
		if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
			throw new Error('A user ID or me is required for fingerprint verification.');
		}
		let value: unknown;
		if (user.toLowerCase() === 'me') {
			const pair = profile.accountKeys ? object(object(profile.accountKeys).publicKeyEncryptionKeyPair ?? {}) : {};
			value = profile.publicKey ?? pair.publicKey;
			if (!value) throw new Error('No public key available for the active user.');
		} else {
			try {
				value = (await this.client.api(this.accessToken, 'GET', `/users/${idPath(id)}/public-key`)).publicKey;
			} catch {
				throw new VaultObjectNotFoundError('Fingerprint not found.');
			}
		}
		const encoded = text(value), bytes = Buffer.from(encoded, 'base64');
		if (!bytes.length || bytes.toString('base64') !== encoded) throw new Error('Invalid user public key.');
		return fingerprintWords(id, bytes).join('-');
	}
	async listItemsForUrl(url: string, filter: ItemFilter = {}, options: UriMatchOptions = {}): Promise<VaultItem[]> {
		const domains = object(this.snapshot.domains ?? {});
		const groups = Array.isArray(domains.equivalentDomains)
			? domains.equivalentDomains.filter((value): value is string[] =>
				Array.isArray(value) && value.every(part => typeof part === 'string')
			)
			: [];
		for (const value of array(domains.globalEquivalentDomains ?? [])) {
			if (!value.excluded && Array.isArray(value.domains)) {
				groups.push(value.domains.filter((part): part is string => typeof part === 'string'));
			}
		}
		const policy = applicableOrganizationPolicies(this.snapshot, 16)[0]?.policy;
		const policyMatch = policy ? policyData(policy.data).uriMatchDetection : undefined;
		const defaultMatch = typeof policyMatch === 'number' && policyMatch >= 0 && policyMatch <= 5
			? policyMatch as UriMatchOptions['defaultMatch']
			: options.defaultMatch;
		return filterItemsByUrl(await this.listItems(filter), url, {
			...options,
			defaultMatch,
			equivalentDomains: options.equivalentDomains ?? groups,
		});
	}
	async findItem(query: string, predicate: (item: VaultItem) => boolean = () => true): Promise<VaultItem> {
		if (!query.trim()) throw new VaultObjectNotFoundError('Item not found.');
		const byGuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(query);
		const exact = array(this.snapshot.ciphers).find(item =>
			typeof item.id === 'string' && item.id.toLowerCase() === query.toLowerCase()
		);
		const activeCiphers = array(this.snapshot.ciphers).filter(item => !item.deletedDate && !item.archivedDate);
		const candidates = exact
			? [await this.decryptItem(exact)]
			: byGuid
			? []
			: searchItemsBasic(await Promise.all(activeCiphers.map(item => this.decryptItem(item))), query);
		if (candidates.length === 1 && this.isRestrictedItem(candidates[0]!)) {
			throw new Error('Access to this item type is restricted by organizational policy.');
		}
		const visible = candidates.filter(item => !this.isRestrictedItem(item));
		if (candidates.length > 1 && visible.length === 0) {
			throw new Error('Access to this item type is restricted by organizational policy.');
		}
		const matches = visible.filter(predicate);
		if (matches.length !== 1) {
			if (matches.length > 1) throw new MultipleResultsError(matches.map(item => text(item.id)));
			throw new VaultObjectNotFoundError('Item not found.');
		}
		return matches[0]!;
	}
	async passwordHealth(options: PasswordHealthOptions = {}): Promise<PasswordHealthRow[]> {
		// Reports ignore premium archive filtering, but still honor item visibility policy.
		const items: VaultItem[] = [];
		for (const item of array(field(this.snapshot, 'ciphers'))) {
			if (this.isRestrictedItem(item as VaultItem)) continue;
			items.push(decryptOwnedItem(item, await this.ownerKey(item)) as VaultItem);
		}
		return passwordHealth(items, options);
	}
	get sends(): SendService {
		return new SendService(this.client, this.accessToken, this.snapshot, this.userKey);
	}
	get deviceApprovals(): DeviceApprovalService {
		return new DeviceApprovalService(
			this.client,
			this.accessToken,
			this.snapshot,
			organizationId => this.ownerKey({ organizationId }),
		);
	}
	exportVault(format: ExportFormat, options: TransferOptions = {}): Promise<Buffer> {
		return exportVault(
			this,
			{ user: this.userKey, organization: id => this.ownerKey({ organizationId: id }) },
			format,
			options,
		);
	}
	importVault(format: ImportFormat, input: Uint8Array | string, options: TransferOptions = {}): Promise<ImportResult> {
		return importVault(
			this,
			{ user: this.userKey, organization: id => this.ownerKey({ organizationId: id }) },
			format,
			input,
			options,
		);
	}
	/** Create an independent key-cache view over a refreshed encrypted snapshot. */
	withSnapshot(snapshot: JsonObject): VaultService {
		return new VaultService(this.client, this.accessToken, snapshot, this.userKey);
	}
	private readonly organizationKeys = new Map<string, Buffer>();
	private readonly pendingOrganizationKeys = new Map<string, Promise<Buffer>>();
	private keyGeneration = 0;
	dispose(): void {
		this.keyGeneration++;
		for (const key of this.organizationKeys.values()) key.fill(0);
		this.organizationKeys.clear();
		this.pendingOrganizationKeys.clear();
	}
	private async ownerKey(item: JsonObject): Promise<Uint8Array> {
		if (!item.organizationId) return this.userKey;
		const id = normalizedId(text(item.organizationId));
		const cached = this.organizationKeys.get(id);
		if (cached) return cached;
		const pending = this.pendingOrganizationKeys.get(id);
		if (pending) return pending;
		const request = this.decryptOrganizationKey(id, this.keyGeneration);
		this.pendingOrganizationKeys.set(id, request);
		try {
			return await request;
		} finally {
			if (this.pendingOrganizationKeys.get(id) === request) this.pendingOrganizationKeys.delete(id);
		}
	}
	private async decryptOrganizationKey(id: string, generation: number): Promise<Buffer> {
		const profile = object(field(this.snapshot, 'profile'));
		const organization = array(profile.organizations ?? []).find(org => sameId(org.id, id));
		if (!organization) throw new Error('Organization key is not available. Sync first.');
		const pair = profile.accountKeys ? object(object(profile.accountKeys).publicKeyEncryptionKeyPair ?? {}) : {};
		const wrappedPrivateKey = text(profile.privateKey ?? pair.wrappedPrivateKey);
		const privateKey = decrypt(wrappedPrivateKey, this.userKey);
		try {
			const key = await decryptSharedKey(text(organization.key), privateKey);
			if (generation !== this.keyGeneration) {
				key.fill(0);
				throw new Error('Organization key request was invalidated.');
			}
			if (key.length !== 64) {
				key.fill(0);
				throw new Error('Unsupported organization key length.');
			}
			this.organizationKeys.set(id, key);
			return key;
		} finally {
			privateKey.fill(0);
		}
	}
	listOrganizations(): JsonObject[] {
		return this.organizationRecords(false);
	}
	findOrganization(query: string): JsonObject {
		return findNamedObject(this.organizationRecords(true), query);
	}
	private organizationRecords(includeProviderOrganizations: boolean): JsonObject[] {
		const profile = object(field(this.snapshot, 'profile'));
		const source = profile.organizationsNew ?? profile.organizations ?? [];
		const organizations = structuredClone(array(source)).filter(org => org.status === 2);
		if (includeProviderOrganizations) {
			for (const providerOrganization of array(profile.providerOrganizations ?? [])) {
				const providerId = text(providerOrganization.id);
				if (providerId && !organizations.some(value => sameId(value.id, providerId))) {
					organizations.push({ ...providerOrganization, status: 2 });
				}
			}
		}
		return organizations.map(org => {
			delete org.key;
			return org;
		});
	}
	async findCollection(query: string): Promise<JsonObject> {
		return findNamedObject(await this.listCollections(), query);
	}
	async listCollections(): Promise<JsonObject[]> {
		const collections: JsonObject[] = [];
		for (const collection of array(field(this.snapshot, 'collections') ?? [])) {
			collections.push(await this.decodeCollection(collection));
		}
		return collections;
	}
	async listOrganizationCollections(organizationId: string): Promise<JsonObject[]> {
		const organization = this.cachedOrganization(organizationId);
		const response = await this.client.api(
			this.accessToken,
			'GET',
			organization.canViewAllCollections === true
				? `/organizations/${idPath(organizationId)}/collections`
				: '/collections',
		);
		const collections: JsonObject[] = [];
		for (const collection of array(response.data).filter(value => sameId(value.organizationId, organizationId))) {
			collections.push(await this.decodeCollection(collection));
		}
		return collections;
	}
	private async decodeCollection(collection: JsonObject): Promise<JsonObject> {
		return { ...collection, name: decrypt(text(collection.name), await this.ownerKey(collection)).toString('utf8') };
	}
	async getOrganizationCollection(organizationId: string, id: string): Promise<JsonObject> {
		this.cachedOrganization(organizationId);
		await this.ownerKey({ organizationId });
		const response = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/collections/${idPath(id)}/details`,
		);
		return this.decodeCollection({ ...response, organizationId });
	}
	async createCollection(organizationId: string, input: JsonObject): Promise<JsonObject> {
		return this.saveCollection(organizationId, undefined, input);
	}
	async editCollection(organizationId: string, id: string, input: JsonObject): Promise<JsonObject> {
		return this.saveCollection(organizationId, id, input);
	}
	private async saveCollection(organizationId: string, id: string | undefined, input: JsonObject): Promise<JsonObject> {
		if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('Collection name is required.');
		if (input.organizationId && !sameId(input.organizationId, organizationId)) {
			throw new Error('Collection organization does not match.');
		}
		const groupsOmitted = input.groups == null;
		const usersOmitted = input.users == null;
		const needsServerCheck = id ? groupsOmitted || usersOmitted : groupsOmitted;
		const vaultwarden = needsServerCheck ? await this.client.isVaultwardenServer() : false;
		const current = id && vaultwarden && (groupsOmitted || usersOmitted)
			? await this.getOrganizationCollection(normalizedId(organizationId), id)
			: undefined;
		if (
			id && vaultwarden
			&& (groupsOmitted && !Array.isArray(current?.groups) || usersOmitted && !Array.isArray(current?.users))
		) {
			throw new Error('Vaultwarden collection access details are incomplete; refusing to replace assignments.');
		}
		const body = {
			name: encrypt(Buffer.from(input.name), await this.ownerKey({ organizationId })),
			groups: input.groups ?? (vaultwarden ? current?.groups ?? [] : null),
			users: input.users ?? (id
				? vaultwarden ? current?.users ?? [] : null
				: this.defaultCollectionUsers(organizationId)),
			externalId: input.externalId ?? undefined,
		};
		if (body.groups !== null && !Array.isArray(body.groups) || body.users !== null && !Array.isArray(body.users)) {
			throw new Error('Collection users and groups must be arrays.');
		}
		const response = await this.client.api(
			this.accessToken,
			id ? 'PUT' : 'POST',
			`/organizations/${idPath(organizationId)}/collections${id ? `/${idPath(id)}` : ''}`,
			body,
		);
		return this.decodeCollection({ ...response, organizationId });
	}
	private defaultCollectionUsers(organizationId: string): JsonObject[] {
		const profile = object(field(this.snapshot, 'profile'));
		const organization = array(profile.organizations ?? []).find(value => sameId(value.id, organizationId));
		if (!organization || typeof organization.organizationUserId !== 'string' || !organization.organizationUserId) {
			throw new Error('Organization membership ID is not available. Sync first.');
		}
		return [{ id: organization.organizationUserId, readOnly: false, hidePasswords: false, manage: true }];
	}
	async deleteCollection(organizationId: string, id: string): Promise<void> {
		await this.client.api(
			this.accessToken,
			'DELETE',
			`/organizations/${idPath(organizationId)}/collections/${idPath(id)}`,
		);
	}
	async listOrganizationMembers(organizationId: string): Promise<JsonObject[]> {
		this.cachedOrganization(organizationId);
		return array(
			(await this.client.api(this.accessToken, 'GET', `/organizations/${idPath(organizationId)}/users`)).data,
		).map(user => ({
			object: 'org-member',
			id: user.id,
			email: user.email,
			name: user.name,
			status: user.status,
			type: user.type,
			twoFactorEnabled: user.twoFactorEnabled,
		}));
	}
	private cachedOrganization(id: string): JsonObject {
		const profile = object(this.snapshot.profile);
		const organization = array(profile.organizations ?? []).find(value => sameId(value.id, id));
		if (!organization) throw new Error('Organization not found.');
		return organization;
	}
	private async canWriteAnyCollection(organization: JsonObject): Promise<boolean> {
		const type = organization.type;
		const permissions = object(organization.permissions ?? {});
		return type === 4 && permissions.editAnyCollection === true
			|| (type === 0 || type === 1) && (
				organization.allowAdminAccessToAllCollectionItems === true
				|| await this.client.isVaultwardenServer()
			);
	}
	async confirmMember(organizationId: string, id: string): Promise<void> {
		const guid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
		if (!guid.test(id)) throw new Error(`\`${id}\` is not a GUID.`);
		if (!guid.test(organizationId)) throw new Error(`\`${organizationId}\` is not a GUID.`);
		const member = await this.client.api(
			this.accessToken,
			'GET',
			`/organizations/${idPath(organizationId)}/users/${idPath(id)}`,
		);
		if (member.status !== 1) {
			const statusMessage = member.status === 0
				? 'User must accept the invitation before they can be confirmed.'
				: member.status === 2
				? 'User is already confirmed.'
				: member.status === 3
				? 'User is revoked and cannot be confirmed.'
				: 'User is not in a valid state to be confirmed.';
			throw new Error(statusMessage);
		}
		const user = await this.client.api(this.accessToken, 'GET', `/users/${idPath(text(member.userId))}/public-key`);
		const organizationKey = await this.ownerKey({ organizationId });
		const key = await encryptSharedKey(organizationKey, text(user.publicKey));
		const defaultUserCollectionName = encrypt(Buffer.from('My Items', 'utf8'), organizationKey);
		await this.client.api(
			this.accessToken,
			'POST',
			`/organizations/${idPath(organizationId)}/users/${idPath(id)}/confirm`,
			{ key, defaultUserCollectionName },
		);
	}
	private async hasVaultwardenManagedCipherWriteAccess(cipher: JsonObject): Promise<boolean> {
		if (typeof cipher.organizationId !== 'string' || !(await this.client.isVaultwardenServer())) return false;
		const organizationId = cipher.organizationId;
		const collectionIds = Array.isArray(cipher.collectionIds) ? cipher.collectionIds : [];
		const collections = array(this.snapshot.collections ?? []);
		return collectionIds.some(id =>
			typeof id === 'string' && collections.some(collection =>
				sameId(collection.id, id)
				&& sameId(collection.organizationId, organizationId)
				&& collection.manage === true
			)
		);
	}
	private async validateTargetCollections(organizationId: string, collections: string[]): Promise<void> {
		if (!Array.isArray(collections)) {
			throw new Error('Expected an array of collection IDs.');
		}
		const organization = this.cachedOrganization(organizationId);
		if (collections.length === 0) {
			await this.assertCollectionlessOrganizationWriteAllowed(organizationId);
			return;
		}
		const canEditAllCiphers = await this.canWriteAnyCollection(organization);
		const cached = array(this.snapshot.collections ?? []);
		for (const id of collections) {
			const collection = cached.find(value =>
				typeof id === 'string' && sameId(value.id, id)
				&& sameId(value.organizationId, organizationId)
			);
			if (!collection || !canEditAllCiphers && collection.readOnly !== false) {
				throw new Error('You do not have permission to add items to this collection.');
			}
		}
	}
	private async assertCollectionlessOrganizationWriteAllowed(organizationId: string): Promise<void> {
		if (!(await this.client.isVaultwardenServer())) {
			throw new Error('You must provide at least one collection id for this item.');
		}
		const serverVersion = await this.client.serverVersion();
		if (
			!vaultwardenVersionAtLeast(
				serverVersion,
				vaultwardenCapabilities.collectionlessOrganizationItems.fullAccessRequiredFrom,
			)
		) return;

		const organization = this.cachedOrganization(organizationId);
		const permissions = object(organization.permissions ?? {});
		const confirmed = organization.status === 2;
		const fullAccess = organization.type === 0 || organization.type === 1
			|| organization.accessAll === true || permissions.editAnyCollection === true;
		if (!confirmed || !fullAccess) throw new ApiError(400);
	}
	/** Prevent Vaultwarden's bulk importer from silently dropping collectionless ciphers. */
	async assertOrganizationCollectionlessImportAllowed(organizationId: string): Promise<void> {
		if (!(await this.client.isVaultwardenServer())) return;
		// 1.36 treats Some([]) as an import permission; 1.37.4 requires a nonempty collection list.
		const serverVersion = await this.client.serverVersion();
		if (
			!vaultwardenVersionAtLeast(
				serverVersion,
				vaultwardenCapabilities.collectionlessOrganizationItems.fullAccessRequiredFrom,
			)
		) return;
		const organization = this.cachedOrganization(organizationId);
		const permissions = object(organization.permissions ?? {});
		const confirmed = organization.status === 2;
		const fullAccess = organization.type === 0 || organization.type === 1
			|| organization.accessAll === true || permissions.editAnyCollection === true;
		if (!confirmed || !fullAccess) throw new ApiError(400);
	}
	/** Match Vaultwarden 1.37.4's organization import collection permission checks before any server mutation. */
	async assertOrganizationImportCollectionsAllowed(
		organizationId: string,
		collectionIds: (string | undefined)[],
	): Promise<void> {
		if (!(await this.client.isVaultwardenServer())) return;
		const serverVersion = await this.client.serverVersion();
		if (
			!vaultwardenVersionAtLeast(
				serverVersion,
				vaultwardenCapabilities.organizationImportCollectionAccess.preflightRequiredFrom,
			)
		) return;

		const organization = this.cachedOrganization(organizationId);
		const type = organization.type;
		const permissions = object(organization.permissions ?? {});
		const confirmed = organization.status === 2;
		const fullAccess = type === 0 || type === 1 || organization.accessAll === true
			|| type === 4 && permissions.editAnyCollection === true;
		if (!confirmed) throw new ApiError(400);

		const cached = array(this.snapshot.collections ?? []);
		for (const id of collectionIds) {
			const existing = id && cached.find(collection =>
				sameId(collection.id, id)
				&& sameId(collection.organizationId, organizationId)
			);
			if (existing) {
				if (type !== 0 && type !== 1 && existing.readOnly !== false) throw new ApiError(400);
			} else if (type !== 0 && type !== 1 && !fullAccess) {
				throw new ApiError(400);
			}
		}
	}
	private async validateOrganizationCreateCollections(organizationId: string, collections: unknown): Promise<void> {
		if (!Array.isArray(collections) || collections.some(id => typeof id !== 'string' || !id)) {
			throw new Error('Expected an array of collection IDs.');
		}
		if (collections.length === 0) {
			await this.assertCollectionlessOrganizationWriteAllowed(organizationId);
			return;
		}
		await this.validateTargetCollections(organizationId, collections);
	}
	private async validateWritableCollections(
		organizationId: string,
		currentCollections: unknown,
		collections: string[],
	): Promise<void> {
		if (
			!Array.isArray(collections) || collections.some(id => typeof id !== 'string' || !id)
			|| currentCollections !== undefined
				&& (!Array.isArray(currentCollections)
					|| currentCollections.some(id => typeof id !== 'string' || !id))
		) {
			throw new Error('Expected an array of collection IDs.');
		}
		const current = new Set((currentCollections as string[] | undefined ?? []).map(id => normalizedId(id)));
		const desired = new Set(collections.map(normalizedId));
		const changed = [...new Set([...current, ...desired])].filter(id => current.has(id) !== desired.has(id));
		if (changed.length === 0) return;
		const organization = this.cachedOrganization(organizationId);
		const canEditAllCiphers = await this.canWriteAnyCollection(organization);
		const cached = array(this.snapshot.collections ?? []);
		for (const id of changed) {
			const collection = cached.find(value => sameId(value.id, id) && sameId(value.organizationId, organizationId));
			if (!collection || !canEditAllCiphers && collection.readOnly !== false) {
				throw new Error('You do not have permission to edit this collection.');
			}
		}
	}
	async editItemCollections(id: string, collections: string[]): Promise<VaultItem> {
		const wire = this.wire(id);
		if (!wire.organizationId) {
			throw new Error('Item does not belong to an organization. Consider moving it first.');
		}
		if (
			(wire.edit !== true || wire.viewPassword !== true)
			&& !(await this.hasVaultwardenManagedCipherWriteAccess(wire))
		) throw new Error('You do not have permission to edit this item');
		const org = text(wire.organizationId);
		// Vaultwarden permits collection management when any assigned collection grants manage access.
		await this.validateWritableCollections(org, wire.collectionIds, collections);
		const updatedWire = await this.client.api(this.accessToken, 'PUT', `/ciphers/${idPath(id)}/collections`, {
			collectionIds: collections,
		});
		return decryptOwnedItem(updatedWire, await this.ownerKey(updatedWire)) as VaultItem;
	}
	async moveItem(id: string, organizationId: string, collectionIds: string[]): Promise<VaultItem> {
		const cipherId = id.toLowerCase(), targetOrganizationId = organizationId.toLowerCase();
		let existing = this.wire(cipherId);
		if (existing.organizationId) throw new Error('Only personal items can be moved to an organization.');
		if (typeof existing.type === 'number') await this.client.assertCipherTypeSupported(existing.type);
		await this.validateTargetCollections(targetOrganizationId, collectionIds);
		if (!existing.key && Array.isArray(existing.attachments)) {
			const legacyAttachments = existing.attachments.map(object).filter(attachment => !attachment.key);
			if (legacyAttachments.length) {
				try {
					for (const attachment of legacyAttachments) {
						const attachmentId = text(attachment.id);
						const downloaded = await this.downloadAttachment(cipherId, attachmentId, false, true);
						try {
							await this.saveAttachment(cipherId, downloaded.fileName, downloaded.contents, false);
						} finally {
							downloaded.contents.fill(0);
						}
						await this.removeAttachment(cipherId, attachmentId, false);
					}
					const refreshed = await this.client.sync(this.accessToken);
					this.snapshot.ciphers = refreshed.ciphers;
					existing = this.wire(cipherId);
				} catch (error) {
					throw new Error(
						'Legacy attachment migration failed; the item was not shared. Sync and inspect its attachments before retrying.',
						{ cause: error },
					);
				}
			}
		}
		const owner = await this.ownerKey({ organizationId: targetOrganizationId });
		const key = existing.key ? decrypt(text(existing.key), this.userKey) : randomBytes(64);
		try {
			// For legacy items, generate a fresh item key; never wrap the user's account key for an organization.
			const cipher = existing.key
				? structuredClone(existing)
				: encryptItem(decryptOwnedItem(existing, this.userKey), key);
			cipher.organizationId = targetOrganizationId;
			cipher.key = encrypt(key, owner);
			cipher.encryptedFor = text(object(field(this.snapshot, 'profile')).id);
			cipher.lastKnownRevisionDate = text(existing.revisionDate);
			if (!existing.key && Array.isArray(existing.attachments)) {
				const attachments: JsonObject = {};
				for (const value of existing.attachments) {
					const attachment = object(value);
					if (!attachment.key) {
						throw new Error('Legacy attachment migration completed without an individual attachment key.');
					}
					const attachmentKey = decrypt(text(attachment.key), this.userKey);
					try {
						attachments[text(attachment.id)] = {
							fileName: encrypt(decrypt(text(attachment.fileName), this.userKey), key),
							key: encrypt(attachmentKey, key),
						};
					} finally {
						attachmentKey.fill(0);
					}
				}
				cipher.attachments2 = attachments;
			}
			delete cipher.attachments;
			delete cipher.id;
			delete cipher.revisionDate;
			const response = await this.client.api(this.accessToken, 'PUT', `/ciphers/${idPath(cipherId)}/share`, {
				cipher,
				collectionIds,
			});
			return decryptOwnedItem(response, owner) as VaultItem;
		} finally {
			key.fill(0);
		}
	}
	private wire(id: string): JsonObject {
		const found = array(field(this.snapshot, 'ciphers')).find(item => sameId(item.id, id));
		if (!found) throw new Error('Item not found. Sync and use its ID.');
		return found;
	}
	async listItems(filter: ItemFilter = {}): Promise<VaultItem[]> {
		const profile = object(this.snapshot.profile);
		const canArchive = profile.premium === true || profile.premiumPersonally === true
			|| profile.premiumFromOrganization === true
			|| filter.archived === true && await this.client.isVaultwardenServer();
		const archived = filter.archived === true && canArchive;
		const items = array(field(this.snapshot, 'ciphers')).filter(item => {
			if (this.isRestrictedItem(item as VaultItem)) return false;
			if (Boolean(item.deletedDate) !== Boolean(filter.trash)) return false;
			if (Boolean(item.archivedDate) !== archived) return false;
			const filters = [
				filter.folderId === undefined ? undefined : matchesId(item.folderId, filter.folderId),
				filter.organizationId === undefined ? undefined : matchesId(item.organizationId, filter.organizationId),
				filter.collectionId === undefined
					? undefined
					: filter.collectionId === 'null'
					? !Array.isArray(item.collectionIds) || item.collectionIds.length === 0
					: filter.collectionId === 'notnull'
					? Array.isArray(item.collectionIds) && item.collectionIds.length > 0
					: Array.isArray(item.collectionIds)
						&& item.collectionIds.some(id => id === filter.collectionId),
			].filter(value => value !== undefined);
			return !filters.length || filters.some(Boolean);
		});
		const decrypted: VaultItem[] = [];
		for (const item of items) decrypted.push(decryptOwnedItem(item, await this.ownerKey(item)) as VaultItem);
		return filter.search ? searchItemsBasic(decrypted, filter.search) : decrypted;
	}
	/** Whether an encrypted or decrypted cipher is hidden by an active item-type policy. */
	isRestrictedItem(item: { type?: unknown; organizationId?: unknown }): boolean {
		const organizations = array(object(this.snapshot.profile).organizations ?? []);
		const policies = applicableOrganizationPolicies(this.snapshot, 15).map(value => value.policy);
		if (!policies.length) return false;
		const restrictedTypes = (policy: JsonObject): number[] => {
			let data = policy.data;
			if (typeof data === 'string') {
				try {
					data = JSON.parse(data);
				} catch {
					data = undefined;
				}
			}
			return Array.isArray(data) ? data.filter((type): type is number => typeof type === 'number') : [3];
		};
		const allRestrictedTypes = new Set(policies.flatMap(restrictedTypes));
		if (typeof item.type !== 'number' || !allRestrictedTypes.has(item.type)) return false;
		const itemType = item.type;
		const allowedOrganizationIds = organizations.filter(organization => {
			const policy = policies.find(value => sameId(value.organizationId, text(organization.id)));
			return !policy || !restrictedTypes(policy).includes(itemType);
		}).map(organization => text(organization.id).toLowerCase());
		return typeof item.organizationId !== 'string'
			|| !allowedOrganizationIds.includes(item.organizationId.toLowerCase());
	}
	private personalOwnershipPolicyApplies(): boolean {
		return applicableOrganizationPolicies(this.snapshot, 5).length > 0;
	}
	async getItem(id: string): Promise<VaultItem> {
		const wire = this.wire(id);
		if (this.isRestrictedItem(wire as VaultItem)) {
			throw new Error('Access to this item type is restricted by organizational policy.');
		}
		return this.decryptItem(wire);
	}
	private async decryptItem(wire: JsonObject): Promise<VaultItem> {
		return decryptOwnedItem(wire, await this.ownerKey(wire)) as VaultItem;
	}
	canAccessTotp(id: string): boolean {
		if (this.hasPremiumAccess()) return true;
		const cipher = this.wire(id);
		return Boolean(cipher.organizationId) && cipher.organizationUseTotp === true;
	}
	/** Vaultwarden authorizes attachments by cipher access and does not apply Bitwarden's premium gate. */
	async canAccessAttachment(id: string): Promise<boolean> {
		return this.hasPremiumAccess() || Boolean(this.wire(id).organizationId) || await this.client.isVaultwardenServer();
	}
	private hasPremiumAccess(): boolean {
		const profile = object(this.snapshot.profile);
		return profile.premium === true || profile.premiumPersonally === true || profile.premiumFromOrganization === true;
	}
	/** Whether editing this archived item requires moving it back to the active vault. */
	async shouldUnarchiveBeforeEdit(id: string): Promise<boolean> {
		return Boolean(this.wire(id).archivedDate) && !this.hasPremiumAccess()
			&& !(await this.client.isVaultwardenServer());
	}
	listFolders(): VaultFolder[] {
		return array(field(this.snapshot, 'folders') ?? []).map(folder => ({
			...folder,
			name: decrypt(text(folder.name), this.userKey).toString('utf8'),
		}));
	}
	getFolder(id: string): VaultFolder {
		const folder = this.listFolders().find(folder => sameId(folder.id, id));
		if (!folder) throw new Error('Folder not found.');
		return folder;
	}
	findFolder(query: string): VaultFolder {
		return findNamedObject(this.listFolders(), query);
	}
	private async encodeItem(input: VaultItem, existing?: JsonObject): Promise<JsonObject> {
		if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('Item name is required.');
		if (!Number.isInteger(input.type) || ![1, 2, 3, 4, 5, 6, 7, 8].includes(input.type)) {
			throw new Error('Unsupported item type.');
		}
		const owner = await this.ownerKey(input);
		if (existing && !sameOptionalId(input.organizationId, existing.organizationId)) {
			throw new Error('Use move to change item ownership.');
		}
		let itemKey: Buffer | undefined;
		let previousItemKey: Buffer | undefined;
		let explicitItemKey: Buffer | undefined;
		try {
			// bw edit accepts a raw base64 item key. Serialized EncStrings are display data and are ignored.
			const requestedKey = input.key;
			if (requestedKey != null && !(typeof requestedKey === 'string' && /^\d+\./.test(requestedKey))) {
				if (
					typeof requestedKey !== 'string'
					|| !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(requestedKey)
				) {
					throw new Error('Invalid item key; expected a base64-encoded 512-bit key.');
				}
				explicitItemKey = Buffer.from(requestedKey, 'base64');
				if (explicitItemKey.length !== 64 || explicitItemKey.toString('base64') !== requestedKey) {
					explicitItemKey.fill(0);
					explicitItemKey = undefined;
					throw new Error('Invalid item key; expected a base64-encoded 512-bit key.');
				}
			}
			previousItemKey = existing?.key ? decrypt(text(existing.key), owner) : Buffer.from(owner);
			// Reuse the current key for ordinary edits so attachments and encrypted data remain readable.
			itemKey = explicitItemKey ?? (existing ? Buffer.from(previousItemKey) : randomBytes(64));
			const plain = { ...input };
			delete plain.key;
			if (existing?.attachments) plain.attachments = undefined; // Attachment metadata has its own endpoint.
			const encoded = encryptItem(plain, itemKey ?? owner);
			encoded.key = existing && !explicitItemKey && !existing.key ? null : encrypt(itemKey!, owner);
			if (existing && explicitItemKey && Array.isArray(existing.attachments)) {
				const attachments2: JsonObject = {};
				for (const value of existing.attachments) {
					const attachment = object(value);
					const attachmentId = text(attachment.id);
					const next: JsonObject = {
						fileName: encrypt(decrypt(text(attachment.fileName), previousItemKey!), itemKey!),
						lastKnownRevisionDate: existing.revisionDate ?? null,
					};
					const attachmentKey = attachment.key
						? decrypt(text(attachment.key), previousItemKey!)
						: Buffer.from(previousItemKey!);
					try {
						// Legacy attachment bytes use the old item key; wrap it as their per-file key.
						next.key = encrypt(attachmentKey, itemKey!);
					} finally {
						attachmentKey.fill(0);
					}
					attachments2[attachmentId] = next;
				}
				encoded.attachments2 = attachments2;
			}
			encoded.encryptedFor = text(object(field(this.snapshot, 'profile')).id);
			const revision = existing ? text(input.revisionDate ?? existing.revisionDate) : null;
			if (revision && !Number.isFinite(Date.parse(revision))) throw new Error('Invalid item revision date.');
			encoded.lastKnownRevisionDate = revision;
			delete encoded.revisionDate;
			delete encoded.id;
			delete encoded.deletedDate;
			return encoded;
		} finally {
			itemKey?.fill(0);
			previousItemKey?.fill(0);
			explicitItemKey?.fill(0);
		}
	}
	async createItem(input: VaultItem): Promise<VaultItem> {
		await this.client.assertCipherTypeSupported(input.type);
		if (this.isRestrictedItem(input)) {
			throw new Error('Creating this item type is restricted by organizational policy.');
		}
		if (input.organizationId) {
			await this.validateOrganizationCreateCollections(input.organizationId, input.collectionIds ?? []);
		}
		const encoded = await this.encodeItem(input);
		const wire = await this.client.api(
			this.accessToken,
			'POST',
			input.organizationId ? '/ciphers/create' : '/ciphers',
			input.organizationId ? { cipher: encoded, collectionIds: input.collectionIds ?? [] } : encoded,
		);
		return decryptOwnedItem(wire, await this.ownerKey(wire)) as VaultItem;
	}
	async editItem(id: string, input: EditVaultItem): Promise<VaultItem> {
		const cipherId = id.toLowerCase();
		const existing = this.wire(cipherId);
		await this.client.assertCipherTypeSupported(input.type);
		if (
			existing.edit !== true && !(await this.hasVaultwardenManagedCipherWriteAccess(existing))
		) throw new Error('You do not have permission to edit this item');
		if (existing.deletedDate) throw new Error('You may not edit a deleted item. Use the restore command first.');
		if (!existing.organizationId && this.personalOwnershipPolicyApplies()) {
			throw new Error(
				'An organization policy restricts editing this cipher. Please use the share command first before modifying it.',
			);
		}
		if (input.organizationId != null && !sameOptionalId(input.organizationId, existing.organizationId)) {
			throw new Error('Use move to change item ownership.');
		}
		const editable = decryptOwnedItem(existing, await this.ownerKey(existing)) as VaultItem;
		editable.type = input.type;
		if (input.key != null) editable.key = input.key;
		if (input.folderId !== undefined) editable.folderId = input.folderId;
		if (input.collectionIds !== undefined) editable.collectionIds = structuredClone(input.collectionIds);
		if (input.name !== undefined) editable.name = input.name;
		if (input.notes !== undefined) editable.notes = input.notes;
		if (input.favorite !== undefined) editable.favorite = input.favorite;
		if (input.reprompt !== undefined) editable.reprompt = input.reprompt;
		if (input.fields !== undefined) editable.fields = structuredClone(input.fields);
		const section = input.type === 1 ? 'login' : input.type === 2 ? 'secureNote' : input.type === 3
			? 'card'
			: input.type === 4
			? 'identity'
			: input.type === 5
			? 'sshKey'
			: input.type === 6
			? 'bankAccount'
			: input.type === 7
			? 'driversLicense'
			: 'passport';
		if (input[section] !== undefined) editable[section] = structuredClone(input[section]);
		if (input.passwordHistory !== undefined) editable.passwordHistory = structuredClone(input.passwordHistory);
		for (const date of ['creationDate', 'revisionDate', 'deletedDate', 'archivedDate'] as const) {
			if (input[date] !== undefined) (editable as JsonObject)[date] = input[date];
		}
		if (this.isRestrictedItem(editable)) {
			throw new Error('Editing this item type is restricted by organizational policy.');
		}
		if (existing.viewPassword === false) {
			const original = decryptOwnedItem(existing, await this.ownerKey(existing));
			const originalLogin = original.login == null ? undefined : object(original.login);
			const login = editable.login == null ? undefined : object(editable.login);
			if (originalLogin && login) {
				if (login.password == null && originalLogin.password != null) login.password = originalLogin.password;
				if (login.totp == null && originalLogin.totp != null) login.totp = originalLogin.totp;
				if (Array.isArray(login.fido2Credentials) && Array.isArray(originalLogin.fido2Credentials)) {
					const originalCredentials = new Map<string, JsonObject>();
					for (const value of originalLogin.fido2Credentials) {
						const credential = object(value);
						if (typeof credential.credentialId === 'string') {
							originalCredentials.set(credential.credentialId, credential);
						}
					}
					login.fido2Credentials = login.fido2Credentials.map(value => {
						const credential = object(value);
						const originalCredential = typeof credential.credentialId === 'string'
							? originalCredentials.get(credential.credentialId)
							: undefined;
						return credential.keyValue == null && originalCredential?.keyValue != null
							? { ...credential, keyValue: originalCredential.keyValue }
							: credential;
					});
				}
			}
			if (Array.isArray(editable.fields) && Array.isArray(original.fields)) {
				const originalFields = original.fields.map(object);
				const hiddenValues = new Map<unknown, unknown[]>();
				for (const field of originalFields) {
					if (field.type !== 1 || field.value == null) continue;
					const values = hiddenValues.get(field.name) ?? [];
					values.push(field.value);
					hiddenValues.set(field.name, values);
				}
				editable.fields = editable.fields.map(field => {
					const values = hiddenValues.get(field.name);
					return field.type === 1 && field.value == null && values?.length
						? { ...field, value: values.shift() }
						: field;
				});
			}
		}
		const wire = await this.client.api(
			this.accessToken,
			'PUT',
			`/ciphers/${idPath(cipherId)}`,
			await this.encodeItem(editable, existing),
		);
		return decryptOwnedItem(wire, await this.ownerKey(wire)) as VaultItem;
	}
	async deleteItem(id: string, permanent = false): Promise<void> {
		const cipherId = id.toLowerCase();
		const wire = this.wire(cipherId);
		const permissions = object(wire.permissions ?? {});
		if (
			permissions.delete !== true
			&& !(await this.hasVaultwardenManagedCipherWriteAccess(wire))
		) {
			throw new Error('You do not have permission to delete this item.');
		}
		if (this.isRestrictedItem(wire as VaultItem)) {
			throw new Error('Deleting this item type is restricted by organizational policy.');
		}
		await this.client.api(
			this.accessToken,
			permanent ? 'DELETE' : 'PUT',
			`/ciphers/${idPath(cipherId)}${permanent ? '' : '/delete'}`,
		);
	}
	async restoreItem(id: string): Promise<void> {
		const wire = this.wire(id);
		const archived = Boolean(wire.archivedDate && !wire.deletedDate);
		if (!archived && !wire.deletedDate) throw new Error('Cipher is not in trash.');
		if (wire.deletedDate) {
			const permissions = object(wire.permissions ?? {});
			if (
				permissions.restore !== true
				&& !(await this.hasVaultwardenManagedCipherWriteAccess(wire))
			) {
				throw new Error('You do not have permission to restore this item');
			}
		}
		await this.client.api(
			this.accessToken,
			'PUT',
			`/ciphers/${idPath(id)}/${archived ? 'unarchive' : 'restore'}`,
		);
	}
	async archiveItem(id: string): Promise<void> {
		const cipherId = id.toLowerCase();
		const wire = this.wire(cipherId);
		if (!this.hasPremiumAccess() && !(await this.client.isVaultwardenServer())) {
			throw new Error('Premium status is required to use this feature.');
		}
		if (wire.archivedDate && !wire.deletedDate) throw new Error('Item is already archived.');
		if (wire.deletedDate) {
			throw new Error('Item is in the trash, the item must be restored before archiving.');
		}
		await this.client.api(this.accessToken, 'PUT', `/ciphers/${idPath(cipherId)}/archive`);
	}
	private async itemKey(wire: JsonObject): Promise<Buffer> {
		const owner = await this.ownerKey(wire);
		return wire.key ? decrypt(text(wire.key), owner) : Buffer.from(owner);
	}
	async createAttachment(itemId: string, fileName: string, contents: Uint8Array): Promise<JsonObject> {
		return this.saveAttachment(itemId, fileName, contents, true);
	}
	private async saveAttachment(
		itemId: string,
		fileName: string,
		contents: Uint8Array,
		enforceEntitlement: boolean,
	): Promise<JsonObject> {
		if (!fileName || fileName.includes('\0')) throw new Error('Attachment file name is required.');
		const vaultwarden = contents.length > maxBitwardenAttachmentBytes
			? await this.client.isVaultwardenServer()
			: false;
		assertAttachmentSize(contents.length, vaultwarden);
		const item = this.wire(itemId);
		if (enforceEntitlement && !(await this.canAccessAttachment(itemId))) {
			throw new Error('Premium status is required to use this feature.');
		}
		const itemKey = await this.itemKey(item);
		const attachmentKey = randomBytes(64);
		try {
			const ciphertext = encryptAttachment(contents, attachmentKey);
			const response = await this.client.api(this.accessToken, 'POST', `/ciphers/${idPath(itemId)}/attachment/v2`, {
				fileName: encrypt(Buffer.from(fileName), itemKey),
				key: encrypt(attachmentKey, itemKey),
				fileSize: ciphertext.length,
			});
			const attachmentId = text(response.attachmentId);
			try {
				if (response.fileUploadType === 0) {
					const form = new FormData();
					form.set('data', new Blob([new Uint8Array(ciphertext)]), 'encrypted');
					await this.client.uploadAttachment(
						this.accessToken,
						normalizedId(itemId),
						normalizedId(attachmentId),
						form,
					);
				} else if (response.fileUploadType === 1) {
					await this.client.uploadAzureFile(
						text(response.url),
						ciphertext,
						async () =>
							text(
								(await this.client.api(
									this.accessToken,
									'GET',
									`/ciphers/${idPath(itemId)}/attachment/${idPath(attachmentId)}/renew`,
								)).url,
							),
					);
				} else {
					throw new Error('Unsupported attachment upload provider.');
				}
			} catch {
				try {
					await this.client.api(
						this.accessToken,
						'DELETE',
						`/ciphers/${idPath(itemId)}/attachment/${idPath(attachmentId)}`,
					);
				} catch {
					throw new Error(`Attachment upload failed; cleanup also failed. Sync and delete attachment ${attachmentId}.`);
				}
				throw new Error('Attachment upload failed; incomplete metadata was removed.');
			}
			const wire = object(response.cipherResponse ?? response.cipherMiniResponse);
			return decryptOwnedItem(wire, await this.ownerKey(wire));
		} finally {
			itemKey.fill(0);
			attachmentKey.fill(0);
		}
	}
	async getAttachment(itemId: string, idOrName: string): Promise<{ fileName: string; contents: Buffer }> {
		return this.downloadAttachment(itemId, idOrName, true);
	}
	/** Exact IDs only: internal backup and migration operations must never search filenames. */
	async getAttachmentById(itemId: string, attachmentId: string): Promise<{ fileName: string; contents: Buffer }> {
		return this.downloadAttachment(itemId, attachmentId, true, true);
	}
	private async downloadAttachment(
		itemId: string,
		idOrName: string,
		enforceEntitlement: boolean,
		idOnly = false,
	): Promise<{ fileName: string; contents: Buffer }> {
		const resolvedItemId = idOnly ? normalizedId(itemId) : text((await this.findItem(itemId)).id);
		const item = this.wire(resolvedItemId);
		if (idOnly && this.isRestrictedItem(item)) {
			throw new Error('Access to this item type is restricted by organizational policy.');
		}
		const attachments = array(item.attachments ?? []);
		if (attachments.length === 0) throw new Error('No attachments available for this item.');
		const itemKey = await this.itemKey(item);
		try {
			const query = idOrName.toLowerCase();
			if (!query) throw new Error('Attachment not found.');
			const exactId = attachments.find(attachment => text(attachment.id).toLowerCase() === query);
			if (idOnly && !exactId) throw new Error('Attachment ID was not found.');
			let matches = (exactId ? [exactId] : attachments).map(attachment => ({
				attachment,
				name: decrypt(text(attachment.fileName), itemKey).toString('utf8').toLowerCase(),
			})).filter(value => exactId !== undefined || value.name.includes(query));
			const exactNames = matches.filter(value => value.name === query);
			if (exactNames.length === 1) matches = exactNames;
			if (matches.length !== 1) {
				if (matches.length > 1) {
					throw new MultipleResultsError(matches.map(value => text(value.attachment.id)));
				}
				throw new Error(`Attachment "${idOrName}" was not found.`);
			}
			if (enforceEntitlement && !(await this.canAccessAttachment(resolvedItemId))) {
				throw new Error('Premium status is required to use this feature.');
			}
			const attachment = matches[0]!.attachment;
			let metadata: JsonObject;
			try {
				metadata = await this.client.api(
					this.accessToken,
					'GET',
					`/ciphers/${idPath(resolvedItemId)}/attachment/${idPath(text(attachment.id))}`,
				);
			} catch (error) {
				if (!(error instanceof ApiError) || error.status !== 404) throw error;
				metadata = attachment;
			}
			const wrappedKey = metadata.key ?? attachment.key;
			const key = wrappedKey ? decrypt(text(wrappedKey), itemKey) : Buffer.from(itemKey);
			try {
				return {
					fileName: decrypt(text(metadata.fileName ?? attachment.fileName), itemKey).toString('utf8'),
					contents: decryptAttachment(await this.client.downloadAttachment(text(metadata.url)), key),
				};
			} finally {
				key.fill(0);
			}
		} finally {
			itemKey.fill(0);
		}
	}
	async deleteAttachment(itemId: string, id: string): Promise<void> {
		return this.removeAttachment(itemId, id, true);
	}
	private async removeAttachment(itemId: string, id: string, enforceEntitlement: boolean): Promise<void> {
		const item = this.wire(itemId);
		const attachments = array(item.attachments ?? []);
		if (attachments.length === 0) throw new Error('No attachments available for this item.');
		const attachment = attachments.find(value => text(value.id).toLowerCase() === id.toLowerCase());
		if (!attachment) throw new Error('Attachment `' + id + '` was not found.');
		if (enforceEntitlement && !(await this.canAccessAttachment(itemId))) {
			throw new Error('Premium status is required to use this feature.');
		}
		await this.client.api(
			this.accessToken,
			'DELETE',
			`/ciphers/${idPath(itemId)}/attachment/${idPath(text(attachment.id))}`,
		);
	}
	async createFolder(input: VaultFolder): Promise<VaultFolder> {
		return this.saveFolder('POST', '/folders', input);
	}
	async editFolder(id: string, input: VaultFolder): Promise<VaultFolder> {
		this.getFolder(id);
		return this.saveFolder('PUT', `/folders/${idPath(id)}`, input);
	}
	private async saveFolder(method: string, path: string, input: VaultFolder): Promise<VaultFolder> {
		if (typeof input.name !== 'string' || !input.name.trim()) throw new Error('Folder name is required.');
		const wire = await this.client.api(this.accessToken, method, path, {
			name: encrypt(Buffer.from(input.name), this.userKey),
		});
		return { ...wire, name: decrypt(text(wire.name), this.userKey).toString('utf8') };
	}
	async deleteFolder(id: string): Promise<void> {
		this.getFolder(id);
		await this.client.api(this.accessToken, 'DELETE', `/folders/${idPath(id)}`);
	}
}
