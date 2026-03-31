import type { EsaTokenResponse, EsaUserProfile } from './types';

const ESA_API_BASE = 'https://api.esa.io';

export async function exchangeAuthorizationCode(input: {
	clientId: string;
	clientSecret: string;
	redirectUri: string;
	code: string;
}): Promise<EsaTokenResponse> {
	const response = await fetch(`${ESA_API_BASE}/oauth/token`, {
		method: 'POST',
		headers: {
			'content-type': 'application/json',
		},
		body: JSON.stringify({
			client_id: input.clientId,
			client_secret: input.clientSecret,
			grant_type: 'authorization_code',
			redirect_uri: input.redirectUri,
			code: input.code,
		}),
	});

	if (!response.ok) {
		throw new Error(`esa token exchange failed with status ${response.status}`);
	}

	return response.json<EsaTokenResponse>();
}

export async function fetchCurrentUser(accessToken: string): Promise<EsaUserProfile> {
	const response = await fetch(`${ESA_API_BASE}/v1/user`, {
		headers: {
			authorization: `Bearer ${accessToken}`,
		},
	});

	if (!response.ok) {
		throw new Error(`esa user lookup failed with status ${response.status}`);
	}

	return response.json<EsaUserProfile>();
}

export function buildAuthorizeUrl(input: { team: string; clientId: string; redirectUri: string; scope: string; state: string }): string {
	const url = new URL(`https://api.esa.io/oauth/authorize`);
	url.searchParams.set('client_id', input.clientId);
	url.searchParams.set('redirect_uri', input.redirectUri);
	url.searchParams.set('response_type', 'code');
	url.searchParams.set('scope', input.scope);
	url.searchParams.set('state', input.state);
	return url.toString();
}
