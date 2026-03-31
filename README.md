# esa-oidc-adapter

Cloudflare Workers 上で、esa.io の OAuth 2.0 を最小実用の OpenID Connect Provider として見せるアダプターです。

## Required bindings

- `ESA_TEAM`
- `ESA_CLIENT_ID`
- `ESA_CLIENT_SECRET`
- `ISSUER_URL`
- `OIDC_JWT_PRIVATE_KEY`
- `TRANSIENT_STORE`

`ESA_CLIENT_ID` と `ESA_CLIENT_SECRET` は v1 では upstream の esa OAuth client と downstream の OIDC client を兼用します。1 デプロイ 1 クライアントの前提です。

`OIDC_JWT_PRIVATE_KEY` は JSON JWK か PKCS#8 PEM を受け付けます。

## Endpoints

- `GET /.well-known/openid-configuration`
- `GET /authorize`
- `GET /callback`
- `POST /token`
- `GET /userinfo`
- `GET /jwks.json`
- `GET /healthz`

## Notes

認可コードと一時 state は Workers KV に短時間保存します。KV は強整合ではないため、認可コードの単回使用は best-effort です。厳密な単回使用保証が必要になったら Durable Objects への移行を推奨します。
