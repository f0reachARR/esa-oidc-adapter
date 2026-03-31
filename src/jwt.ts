import type { JwtPayload } from "./types";
import { base64UrlDecode, base64UrlEncode, sha256base64Url } from "./utils";

interface CachedKeys {
	privateKey: CryptoKey;
	publicJwk: PublicJwk;
	kid: string;
}

type PublicJwk = JsonWebKey & {
	kty: string;
	n?: string;
	e?: string;
	kid?: string;
	use?: string;
	alg?: string;
	key_ops?: string[];
};

let cachedKeysPromise: Promise<CachedKeys> | undefined;

export async function signJwt(privateKeyPemOrJwk: string, payload: JwtPayload, typ = "JWT"): Promise<string> {
	const keys = await getKeys(privateKeyPemOrJwk);
	const header = {
		alg: "RS256",
		kid: keys.kid,
		typ,
	};

	const encodedHeader = base64UrlEncode(JSON.stringify(header));
	const encodedPayload = base64UrlEncode(JSON.stringify(payload));
	const signingInput = `${encodedHeader}.${encodedPayload}`;
	const signature = await crypto.subtle.sign(
		{ name: "RSASSA-PKCS1-v1_5" },
		keys.privateKey,
		new TextEncoder().encode(signingInput),
	);

	return `${signingInput}.${base64UrlEncode(signature)}`;
}

export async function exportJwks(privateKeyPemOrJwk: string): Promise<{ keys: PublicJwk[] }> {
	const keys = await getKeys(privateKeyPemOrJwk);
	return {
		keys: [
			{
				...keys.publicJwk,
				kid: keys.kid,
				use: "sig",
				alg: "RS256",
				key_ops: ["verify"],
			},
		],
	};
}

export async function verifyJwt(
	privateKeyPemOrJwk: string,
	token: string,
	options: { audience: string; issuer: string; tokenUse: "access" | "id" },
): Promise<JwtPayload> {
	const keys = await getKeys(privateKeyPemOrJwk);
	const [encodedHeader, encodedPayload, encodedSignature] = token.split(".");
	if (!encodedHeader || !encodedPayload || !encodedSignature) {
		throw new Error("Malformed JWT");
	}

	const publicKey = await crypto.subtle.importKey(
		"jwk",
		keys.publicJwk,
		{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
		false,
		["verify"],
	);

	const verified = await crypto.subtle.verify(
		{ name: "RSASSA-PKCS1-v1_5" },
		publicKey,
		base64UrlDecode(encodedSignature),
		new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`),
	);

	if (!verified) {
		throw new Error("Invalid JWT signature");
	}

	const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedPayload))) as JwtPayload;
	const now = Math.floor(Date.now() / 1000);

	if (payload.iss !== options.issuer) {
		throw new Error("Unexpected issuer");
	}

	const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
	if (!audiences.includes(options.audience)) {
		throw new Error("Unexpected audience");
	}
	if (payload.exp <= now) {
		throw new Error("Token expired");
	}
	if (payload.nbf && payload.nbf > now) {
		throw new Error("Token not yet valid");
	}
	if (payload.token_use !== options.tokenUse) {
		throw new Error("Unexpected token use");
	}

	return payload;
}

async function getKeys(privateKeyPemOrJwk: string): Promise<CachedKeys> {
	if (!cachedKeysPromise) {
		cachedKeysPromise = loadKeys(privateKeyPemOrJwk);
	}
	return cachedKeysPromise;
}

async function loadKeys(privateKeyPemOrJwk: string): Promise<CachedKeys> {
	const trimmed = privateKeyPemOrJwk.trim();
	let privateKey: CryptoKey;
	let privateJwk: JsonWebKey;

	if (trimmed.startsWith("{")) {
		privateJwk = JSON.parse(trimmed) as JsonWebKey;
		privateKey = await crypto.subtle.importKey(
			"jwk",
			privateJwk,
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			true,
			["sign"],
		);
	} else {
		const binary = atob(
			trimmed
				.replace("-----BEGIN PRIVATE KEY-----", "")
				.replace("-----END PRIVATE KEY-----", "")
				.replace(/\s+/gu, ""),
		);
		const bytes = new Uint8Array(binary.length);
		for (let index = 0; index < binary.length; index += 1) {
			bytes[index] = binary.charCodeAt(index);
		}
		privateKey = await crypto.subtle.importKey(
			"pkcs8",
			bytes,
			{ name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
			true,
			["sign"],
		);
		privateJwk = (await crypto.subtle.exportKey("jwk", privateKey)) as JsonWebKey;
	}

	const { d, dp, dq, p, q, qi, oth, ...publicJwk } = privateJwk;
	const kid = await sha256base64Url(JSON.stringify({ e: publicJwk.e, kty: publicJwk.kty, n: publicJwk.n }));

	return {
		privateKey,
		publicJwk: publicJwk as PublicJwk,
		kid,
	};
}
