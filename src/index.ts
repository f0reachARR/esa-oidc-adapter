import { buildAuthorizeUrl, exchangeAuthorizationCode, fetchCurrentUser } from "./esa";
import { getConfig } from "./config";
import { exportJwks, signJwt, verifyJwt } from "./jwt";
import { isOidcError, oidcError, parseAuthorizationRequest, scopeToEsaScope, userInfoScope, validateTokenRequest } from "./oidc";
import { TransientStore } from "./store";
import type { AdapterEnv, JwtPayload, OidcTokenResponse, OidcUserClaims } from "./types";
import { currentEpochSeconds, errorDescription, json, parseForm, randomToken, secondsFromNow } from "./utils";

const ACCESS_TOKEN_TTL_SECONDS = 3600;
const ID_TOKEN_TTL_SECONDS = 3600;

export default {
	async fetch(request: Request, env: AdapterEnv): Promise<Response> {
		try {
			const config = getConfig(env);
			const url = new URL(request.url);

			switch (url.pathname) {
				case "/.well-known/openid-configuration":
					return handleDiscovery(config);
				case "/authorize":
					return await handleAuthorize(url, config);
				case "/callback":
					return await handleCallback(url, config);
				case "/token":
					return await handleToken(request, config);
				case "/userinfo":
					return await handleUserInfo(request, config);
				case "/jwks.json":
					return await handleJwks(config);
				case "/healthz":
					return json({ ok: true });
				default:
					return json({ error: "not_found" }, { status: 404 });
			}
		} catch (error) {
			if (isOidcError(error)) {
				return json(
					{
						error: error.error,
						error_description: error.errorDescription,
					},
					{ status: error.status ?? 400 },
				);
			}

			return json(
				{
					error: "server_error",
					error_description: errorDescription(error),
				},
				{ status: 500 },
			);
		}
	},
} satisfies ExportedHandler<AdapterEnv>;

function handleDiscovery(config: ReturnType<typeof getConfig>): Response {
	return json({
		issuer: config.issuer,
		authorization_endpoint: `${config.issuer}/authorize`,
		token_endpoint: `${config.issuer}/token`,
		userinfo_endpoint: `${config.issuer}/userinfo`,
		jwks_uri: `${config.issuer}/jwks.json`,
		response_types_supported: ["code"],
		grant_types_supported: ["authorization_code"],
		subject_types_supported: ["public"],
		id_token_signing_alg_values_supported: ["RS256"],
		token_endpoint_auth_methods_supported: ["client_secret_post"],
		scopes_supported: ["openid", "profile", "email", "read", "write"],
		claims_supported: ["sub", "name", "preferred_username", "email", "email_verified", "picture"],
	});
}

async function handleAuthorize(url: URL, config: ReturnType<typeof getConfig>): Promise<Response> {
	const request = parseAuthorizationRequest(url);
	if (request.clientId !== config.esaClientId) {
		throw oidcError("unauthorized_client", "Unknown client_id", 401);
	}

	const transientState = randomToken(24);
	const store = new TransientStore(config.transientStore);
	await store.putSession(transientState, {
		clientId: request.clientId,
		redirectUri: request.redirectUri,
		oidcState: request.state,
		nonce: request.nonce,
		scope: request.scope,
		createdAt: Date.now(),
	});

	const authorizeUrl = buildAuthorizeUrl({
		team: config.esaTeam,
		clientId: config.esaClientId,
		redirectUri: config.callbackUrl,
		scope: scopeToEsaScope(request.scope),
		state: transientState,
	});

	return Response.redirect(authorizeUrl, 302);
}

async function handleCallback(url: URL, config: ReturnType<typeof getConfig>): Promise<Response> {
	const transientState = url.searchParams.get("state");
	if (!transientState) {
		throw oidcError("invalid_request", "Missing callback state");
	}

	const store = new TransientStore(config.transientStore);
	const session = await store.getSession(transientState);
	await store.deleteSession(transientState);
	if (!session) {
		throw oidcError("invalid_request", "Unknown or expired authorization session");
	}

	const target = new URL(session.redirectUri);
	if (url.searchParams.get("error")) {
		target.searchParams.set("error", "access_denied");
		if (session.oidcState) {
			target.searchParams.set("state", session.oidcState);
		}
		return Response.redirect(target.toString(), 302);
	}

	const esaCode = url.searchParams.get("code");
	if (!esaCode) {
		target.searchParams.set("error", "server_error");
		target.searchParams.set("error_description", "esa callback did not include code");
		if (session.oidcState) {
			target.searchParams.set("state", session.oidcState);
		}
		return Response.redirect(target.toString(), 302);
	}

	const adapterCode = randomToken(32);
	await store.putCode(adapterCode, {
		...session,
		esaCode,
	});

	target.searchParams.set("code", adapterCode);
	if (session.oidcState) {
		target.searchParams.set("state", session.oidcState);
	}

	return Response.redirect(target.toString(), 302);
}

async function handleToken(request: Request, config: ReturnType<typeof getConfig>): Promise<Response> {
	const params = await parseForm(request);
	validateTokenRequest(params);

	const clientId = params.get("client_id")!;
	const clientSecret = params.get("client_secret")!;
	const redirectUri = params.get("redirect_uri")!;
	const code = params.get("code")!;

	if (clientId !== config.esaClientId || clientSecret !== config.esaClientSecret) {
		throw oidcError("invalid_client", "Client authentication failed", 401);
	}

	const store = new TransientStore(config.transientStore);
	if (await store.isCodeUsed(code)) {
		throw oidcError("invalid_grant", "Authorization code has already been used");
	}

	const authCode = await store.getCode(code);
	if (!authCode) {
		throw oidcError("invalid_grant", "Authorization code is invalid or expired");
	}
	if (authCode.redirectUri !== redirectUri) {
		throw oidcError("invalid_grant", "redirect_uri mismatch");
	}

	await store.markCodeUsed(code);

	const esaToken = await exchangeAuthorizationCode({
		clientId: config.esaClientId,
		clientSecret: config.esaClientSecret,
		redirectUri: config.callbackUrl,
		code: authCode.esaCode,
	});
	const esaUser = await fetchCurrentUser(esaToken.access_token);
	const claims = mapClaims(esaUser);
	const { sub, ...claimFields } = claims;

	const now = currentEpochSeconds();
		const idTokenPayload: JwtPayload = {
			iss: config.issuer,
			sub,
			aud: clientId,
			exp: now + ID_TOKEN_TTL_SECONDS,
			iat: now,
			auth_time: now,
			nonce: authCode.nonce ?? undefined,
			token_use: "id",
			...claimFields,
		};
		const accessTokenPayload: JwtPayload = {
			iss: config.issuer,
			sub,
			aud: `${config.issuer}/userinfo`,
			exp: now + ACCESS_TOKEN_TTL_SECONDS,
			iat: now,
			nbf: now,
			jti: randomToken(16),
			scope: userInfoScope(authCode.scope),
			token_use: "access",
			...claimFields,
		};

	const tokenResponse: OidcTokenResponse = {
		access_token: await signJwt(config.privateKeyPemOrJwk, accessTokenPayload, "at+jwt"),
		token_type: "Bearer",
		expires_in: ACCESS_TOKEN_TTL_SECONDS,
		id_token: await signJwt(config.privateKeyPemOrJwk, idTokenPayload),
		scope: authCode.scope.join(" "),
	};

	return json(tokenResponse);
}

async function handleUserInfo(request: Request, config: ReturnType<typeof getConfig>): Promise<Response> {
	const authorization = request.headers.get("authorization");
	if (!authorization?.startsWith("Bearer ")) {
		return json(
			{
				error: "invalid_token",
				error_description: "Missing bearer token",
			},
			{
				status: 401,
				headers: {
					"www-authenticate": 'Bearer error="invalid_token"',
				},
			},
		);
	}

	const payload = await verifyJwt(config.privateKeyPemOrJwk, authorization.slice("Bearer ".length), {
		audience: `${config.issuer}/userinfo`,
		issuer: config.issuer,
		tokenUse: "access",
	});

	return json({
		sub: payload.sub,
		name: payload.name,
		preferred_username: payload.preferred_username,
		email: payload.email,
		email_verified: payload.email_verified,
		picture: payload.picture,
	});
}

async function handleJwks(config: ReturnType<typeof getConfig>): Promise<Response> {
	return json(await exportJwks(config.privateKeyPemOrJwk));
}

function mapClaims(user: {
	id: number;
	name: string;
	screen_name: string;
	icon?: string;
	email?: string;
}): OidcUserClaims {
	return {
		sub: String(user.id),
		name: user.name,
		preferred_username: user.screen_name,
		picture: user.icon,
		email: user.email,
		email_verified: user.email ? false : undefined,
	};
}
