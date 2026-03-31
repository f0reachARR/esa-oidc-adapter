import type { TransientAuthCode, TransientAuthSession } from "./types";

const SESSION_TTL_SECONDS = 300;
const CODE_TTL_SECONDS = 300;
const USED_TTL_SECONDS = 300;

export class TransientStore {
	constructor(private readonly namespace: KVNamespace) {}

	async putSession(key: string, session: TransientAuthSession): Promise<void> {
		await this.namespace.put(this.key("session", key), JSON.stringify(session), {
			expirationTtl: SESSION_TTL_SECONDS,
		});
	}

	async getSession(key: string): Promise<TransientAuthSession | null> {
		return this.namespace.get<TransientAuthSession>(this.key("session", key), "json");
	}

	async deleteSession(key: string): Promise<void> {
		await this.namespace.delete(this.key("session", key));
	}

	async putCode(code: string, value: TransientAuthCode): Promise<void> {
		await this.namespace.put(this.key("code", code), JSON.stringify(value), {
			expirationTtl: CODE_TTL_SECONDS,
		});
	}

	async getCode(code: string): Promise<TransientAuthCode | null> {
		return this.namespace.get<TransientAuthCode>(this.key("code", code), "json");
	}

	async markCodeUsed(code: string): Promise<void> {
		await this.namespace.put(this.key("used", code), "1", {
			expirationTtl: USED_TTL_SECONDS,
		});
		await this.namespace.delete(this.key("code", code));
	}

	async isCodeUsed(code: string): Promise<boolean> {
		return (await this.namespace.get(this.key("used", code))) === "1";
	}

	private key(prefix: string, value: string): string {
		return `${prefix}:${value}`;
	}
}
