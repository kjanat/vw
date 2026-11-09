import { randomUUID } from 'node:crypto';
import { unzipSync } from 'fflate';
import type { JsonObject } from '#client';
import type { VaultItem } from '#models';
import { importSshPkcs8, SshImportError } from '#ssh-import';

export interface ImportRecordError {
	id: string;
	reason: 'error' | 'unsupportedType' | 'sshKeyParseFailed';
}
const blank = (v: unknown): boolean => v == null || typeof v === 'string' && !v.trim();
const value = (v: unknown): string | null => typeof v === 'string' && !blank(v) ? v : null;
function record(v: unknown): JsonObject {
	if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('Invalid 1PUX structure.');
	return v as JsonObject;
}
function array(v: unknown): unknown[] {
	if (v == null) return [];
	if (!Array.isArray(v)) throw new Error('Invalid 1PUX structure.');
	return v;
}
function uris(v: string[]): JsonObject[] {
	return v.filter(v => !blank(v)).map(uri => {
		uri = uri.trim();
		if (!uri.includes('://') && uri.includes('.')) uri = `http://${uri}`;
		return { uri: uri.slice(0, 1000), match: null };
	});
}
function custom(item: VaultItem, name: unknown, raw: unknown, type = 0): void {
	if (blank(raw)) return;
	if (typeof raw !== 'string') throw new Error('Invalid 1PUX field.');
	const key = value(name) ?? '';
	if (raw.length > 200 || /\r\n|\r|\n/.test(raw.trim())) {
		item.notes = `${item.notes ? `${item.notes}\n` : ''}${key}: ${raw.replace(/\r\n|\r/g, '\n')}\n`;
	} else item.fields!.push({ name: key, value: raw, type });
}
function fullName(identity: JsonObject, name: string): void {
	const parts = name.split(' ');
	for (
		const [key, v] of Object.entries({
			firstName: parts[0],
			middleName: parts.length > 2 ? parts[1] : null,
			lastName: parts.length === 2 ? parts[1] : parts.length > 2 ? parts.slice(2).join(' ') : null,
		})
	) if (!blank(v)) identity[key] = v;
}
function cardBrand(number: string): string | null {
	const n = number.replace(/\s/g, '');
	if (/^4/.test(n)) return 'Visa';
	if (/^5[1-5]/.test(n) || Number(n.slice(0, 4)) >= 2221 && Number(n.slice(0, 4)) <= 2720) return 'Mastercard';
	if (/^3[47]/.test(n)) return 'Amex';
	if (/^6(?:011|5|4[4-9])/.test(n)) return 'Discover';
	if (/^35/.test(n)) return 'JCB';
	if (/^3(?:0[0-5]|[68])/.test(n)) return 'Diners Club';
	if (/^62/.test(n)) return 'UnionPay';
	return null;
}
/** Legacy mappings used by Vaultwarden, whose item types are login/note/card/identity/SSH. */
function fill(item: VaultItem, category: string, field: JsonObject, key: string, raw: unknown): boolean {
	const title = value(field.title) ?? '', id = field.id;
	const target = item.type === 1 ? item.login! : item.type === 3 ? item.card! : item.identity!;
	const set = (name: string): boolean => {
		if (!blank(target[name])) return false;
		target[name] = raw;
		return true;
	};
	if (item.type === 1) {
		if (title === 'username' && set('username') || title === 'password' && set('password')) return true;
		if (typeof id === 'string' && id.startsWith('TOTP_') && set('totp')) return true;
		if (
			(category === '110' && id === 'url' || category === '112' && title === 'hostname')
			&& !(target.uris as unknown[]).length
		) {
			target.uris = uris([String(raw)]);
			return true;
		}
		return category === '112' && title === 'credential' && set('password');
	}
	if (item.type === 3) {
		if (id === 'ccnum' && set('number')) {
			target.brand = cardBrand(String(raw));
			return true;
		}
		if (id === 'cvv' && set('code') || id === 'cardholder' && set('cardholderName')) return true;
		if (id === 'expiry' && blank(target.expMonth) && blank(target.expYear)) {
			const expiration = String(raw).trim();
			target.expYear = expiration.slice(0, 4);
			target.expMonth = expiration.slice(4, 6).replace(/^0/, '');
			return true;
		}
		return id === 'type' || category === '101' && id === 'owner' && set('cardholderName');
	}
	if (item.type !== 4) return false;
	const common: Record<string, string> = {
		firstname: 'firstName',
		lastname: 'lastName',
		initial: 'middleName',
		defphone: 'phone',
		company: 'company',
		username: 'username',
	};
	if (typeof id === 'string' && Object.hasOwn(common, id) && set(common[id]!)) return true;
	if (blank(target.email)) {
		if (key === 'email') {
			const email = record(raw);
			target.email = value(email.email_address);
			custom(item, 'provider', email.provider);
			return true;
		}
		if (id === 'email' && set('email')) return true;
	}
	if (key === 'address') {
		const address = record(raw);
		for (const [from, to] of Object.entries({ street: 'address1', city: 'city', zip: 'postalCode', state: 'state' })) {
			target[to] = value(address[from]);
		}
		if (!blank(address.country)) target.country = String(address.country).toUpperCase();
		return true;
	}
	const nameId: Record<string, string> = {
		'103': 'fullname',
		'104': 'name',
		'105': 'member_name',
		'106': 'fullname',
		'107': 'member_name',
		'108': 'name',
	};
	if (nameId[category] && id === nameId[category] && blank(target.firstName)) {
		fullName(target, String(raw));
		return true;
	}
	const maps: Record<string, Record<string, string>> = {
		'103': { address: 'address1', country: 'country', state: 'state', number: 'licenseNumber' },
		'104': { country: 'country', state: 'state' },
		'105': { org_name: 'company', phone: 'phone' },
		'106': { issuing_country: 'country', number: 'passportNumber' },
		'107': { company_name: 'company' },
		'108': { number: 'ssn' },
	};
	const map = maps[category];
	return !!map && typeof id === 'string' && Object.hasOwn(map, id) && set(map[id]!);
}
async function parseItem(source: JsonObject): Promise<{ item: VaultItem; tag: string | null }> {
	const category = String(source.categoryUuid),
		details = record(source.details),
		overview = record(source.overview ?? {});
	const type = ['002', '101'].includes(category)
		? 3
		: ['004', '103', '104', '105', '106', '107', '108'].includes(category)
		? 4
		: ['003', '100', '111', '113'].includes(category)
		? 2
		: category === '114'
		? 5
		: 1;
	const item: VaultItem = {
		type,
		name: value(overview.title) ?? '--',
		favorite: source.favIndex === 1,
		reprompt: 0,
		notes: null,
		fields: [],
		login: {
			username: null,
			password: null,
			totp: null,
			uris: uris(array(overview.urls).map(v => String(record(v).url ?? ''))),
		},
	};
	if (!blank(details.notesPlain)) item.notes = String(details.notesPlain).replace(/\r\n|\r/g, '\n').trimEnd();
	if (type === 2) item.secureNote = { type: 0 };
	if (type === 3) item.card = {};
	if (type === 4) item.identity = {};
	if (type === 5) item.sshKey = {};
	for (const entry of array(details.loginFields)) {
		const f = record(entry);
		if (['username', 'password'].includes(String(f.designation)) && f.value !== '') {
			item.type = 1;
			item.login![String(f.designation)] = f.value;
		} else {
			custom(
				item,
				f.name,
				f.fieldType === 'C' ? f.value !== '' ? 'true' : 'false' : f.value,
				f.fieldType === 'P' ? 1 : f.fieldType === 'C' ? 2 : 0,
			);
		}
	}
	if (category === '005') item.login!.password = details.password ?? null;
	const history = array(details.passwordHistory).map(record).filter(h => !blank(h.value) && h.time != null)
		.sort((a, b) => Number(b.time) - Number(a.time)).slice(0, 5);
	if (history.length) {
		item.passwordHistory = history.map(h => ({
			password: h.value,
			lastUsedDate: new Date(String(h.time).length >= 13 ? Number(h.time) : Number(h.time) * 1000).toISOString(),
		}));
	}
	for (const section of array(details.sections).map(record)) {
		for (const field of array(section.fields).map(record)) {
			const values = record(field.value), key = Object.keys(values)[0];
			if (!key || values[key] == null || values[key] === '') continue;
			const raw = key === 'date'
				? new Date(Number(values[key]) * 1000).toUTCString()
				: key === 'monthYear'
				? String(values[key])
				: values[key];
			if (item.type === 5 && key === 'sshKey') {
				const metadata = record(record(raw).metadata);
				if (typeof metadata.privateKey !== 'string') throw new SshImportError('sshKeyParseFailed');
				item.sshKey = await importSshPkcs8(metadata.privateKey);
				continue;
			}
			if (fill(item, category, field, key, raw)) continue;
			const name = value(field.title) ?? value(section.title) ?? '';
			if (key === 'email') {
				const email = record(raw);
				custom(item, name, email.email_address);
				custom(item, 'provider', email.provider);
				continue;
			}
			if (field.title === 'password' && item.passwordHistory?.some(h => h.password === raw)) continue;
			if (field.guarded) item.reprompt = 1;
			custom(item, name, raw, key === 'concealed' ? 1 : 0);
		}
	}
	if (
		item.type === 1 && blank(item.login!.username) && blank(item.login!.password) && blank(item.login!.totp)
		&& !(item.login!.uris as unknown[]).length
	) {
		item.type = 2;
		item.secureNote = { type: 0 };
	}
	if (item.type !== 1) delete item.login;
	if (blank(item.notes)) item.notes = null;
	if (source.state === 'archived') item.archivedDate = new Date().toISOString();
	const tag = value(array(overview.tags)[0]);
	return {
		item,
		tag: tag?.trim().replace(/\w\S*/g, w => w[0]!.toUpperCase() + w.slice(1)).replace(/\\/g, '/').replace(/^\/+/, '')
			?? null,
	};
}
/** Accept export.data JSON or a binary .1pux archive; awaits SSH conversion without writing archive paths to disk. */
export async function parseOnePassword1Pux(input: string | Uint8Array, organization = false): Promise<JsonObject> {
	let source: string;
	if (typeof input !== 'string' && input[0] === 0x50 && input[1] === 0x4b) {
		try {
			const archive = unzipSync(input, {
				filter: entry => {
					if (entry.name !== 'export.data') return false;
					if (entry.originalSize > 100 * 1024 * 1024) throw new Error();
					return true;
				},
			});
			if (!archive['export.data']) throw new Error();
			source = Buffer.from(archive['export.data']).toString('utf8');
		} catch {
			throw new Error('Invalid 1PUX archive or missing/oversized export.data.');
		}
	} else source = typeof input === 'string' ? input : Buffer.from(input).toString('utf8');
	let document: JsonObject;
	try {
		document = record(JSON.parse(source));
	} catch {
		throw new Error('Invalid 1PUX JSON.');
	}
	if (!Array.isArray(document.accounts) || !document.accounts.length) throw new Error('1PUX has no accounts.');
	const items: VaultItem[] = [],
		folders: JsonObject[] = [],
		errors: ImportRecordError[] = [],
		ids = new Map<string, string>();
	const folder = (name: string): string => {
		if (!ids.has(name)) {
			ids.set(name, randomUUID());
			folders.push({ id: ids.get(name), name });
		}
		return ids.get(name)!;
	};
	const firstAccount = record(document.accounts[0]);
	for (const vault of array(firstAccount.vaults).map(record)) {
		for (const source of array(vault.items)) {
			try {
				const { item, tag } = await parseItem(record(source));
				const id = tag != null ? folder(tag) : null;
				if (tag) {
					for (let end = tag.lastIndexOf('/'); end > 0; end = tag.lastIndexOf('/', end - 1)) {
						folder(tag.slice(0, end));
					}
				}
				item.folderId = organization ? null : id;
				item.collectionIds = organization && id ? [id] : [];
				items.push(item);
			} catch (error) {
				const uuid = source && typeof source === 'object' ? (source as JsonObject).uuid : null;
				errors.push({
					id: typeof uuid === 'string' && /^[a-zA-Z0-9_-]{1,128}$/.test(uuid) ? uuid : '',
					reason: error instanceof SshImportError ? error.reason : 'error',
				});
			}
		}
	}
	return {
		encrypted: false,
		items,
		[organization ? 'collections' : 'folders']: folders,
		...(errors.length ? { errors } : {}),
	};
}
