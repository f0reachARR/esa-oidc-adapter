import type { AdapterEnv } from "./types";
import { ensureTrailingSlash } from "./utils";

export interface ResolvedConfig {
	esaTeam: string;
	esaClientId: string;
	esaClientSecret: string;
	issuer: string;
	callbackUrl: string;
	transientStore: KVNamespace;
	privateKeyPemOrJwk: string;
}

export function getConfig(env: AdapterEnv): ResolvedConfig {
	const issuer = ensureTrailingSlash(env.ISSUER_URL).replace(/\/$/u, "");

	return {
		esaTeam: must(env.ESA_TEAM, "ESA_TEAM"),
		esaClientId: must(env.ESA_CLIENT_ID, "ESA_CLIENT_ID"),
		esaClientSecret: must(env.ESA_CLIENT_SECRET, "ESA_CLIENT_SECRET"),
		issuer,
		callbackUrl: `${issuer}/callback`,
		transientStore: env.TRANSIENT_STORE,
		privateKeyPemOrJwk: must(env.OIDC_JWT_PRIVATE_KEY, "OIDC_JWT_PRIVATE_KEY"),
	};
}

function must(value: string | undefined, name: string): string {
	if (!value) {
		throw new Error(`Missing required binding: ${name}`);
	}
	return value;
}
