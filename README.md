# idmouse

`idmouse` is a Rust service built with Axum for exchanging an authenticated incoming JWT into a
new JWT selected by a named mapping.

The config defines:

- how incoming bearer tokens should be authenticated
- a list of named mappings

## Request flow

1. Call `POST /token/<mapping-name>` with an `Authorization: Bearer ...` header.
2. `idmouse` validates the incoming token using the configured authentication issuer, audience, and
   validation key when one is configured.
   If `validation_key` is omitted, `idmouse` fetches
   `<issuer>/.well-known/openid-configuration`, reads `jwks_uri`, and then discovers a matching
   verification key from that JWKS document.
   For the exact issuer `https://kubernetes.default.svc`, discovery also uses the service account
   CA bundle and bearer token from `/var/run/secrets/kubernetes.io/serviceaccount/` when those
   files exist.
3. The incoming token subject must be present in the mapping’s `allowed_subjects`.
4. `idmouse` issues a new JWT containing standard timing claims plus the mapping’s
   `additional_claims`.

## Example config

```toml
bind_address = "0.0.0.0:8080"
origin = "http://idmouse.idmouse.svc"

[authentication]
audience = "idmouse"
issuer = "https://kubernetes.default.svc"
validation_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoTljJr11MDnf6FGOXi07
EUqrmLKrT/9tPEJd98zYCP+3oUaqvDDnq72wSWmwmztjxun4O4kotsuExhitnVQ5
2p2W8fd/bgaw88G1Ud2FVe0k0BKTVZuh7jFlFaLCmzC4L+H3F3wuxVWW4KtoAW5W
lRnmMR5fvsrANs2zhIF2sEme0Y+zS/kxaWLLniq9E+OvbRUtLEDnoiDOvei/diAY
DXl7MVlwWE2RhaVnEHgMiIJbzpDGoSxYcpM0WbSX9OJp2vGt2y8wVJ4JKmkvEbLn
QNomSRZMTkPmzXK+GjSJAw90ImP+lHXlzwyZUJq1h0hbE5BvxnmQi/NbwH9CSPWm
HwIDAQAB
-----END PUBLIC KEY-----
"""

# Optional. If omitted, idmouse will attempt OpenID Connect discovery via
# <issuer>/.well-known/openid-configuration and use the returned jwks_uri.

[[mapping]]
name = "idelephant"
allowed_subjects = ["system:serviceaccount:idelephant:idelephant"]
additional_claims = { ns = "default", db = "idelephant", sub = "idelephant", ac = "token_name", id = "idelephant" }

[[mapping]]
name = "some_other_mapping"
allowed_subjects = ["system:serviceaccount:default:default"]
additional_claims = { ns = "ns_name", db = "foo" }
```

## Endpoints

- `GET /healthz`
- `GET /.well-known/jwks.json`
- `POST /token/<mapping-name>`

Example:

```bash
curl -s http://127.0.0.1:8080/token/idelephant \
  -H "Authorization: Bearer $SOURCE_TOKEN"
```

## Issued claims

Every issued token includes:

- `exp`
- `iat`
- `nbf`
- `iss`

It also includes every key from the selected mapping’s `additional_claims`.
Issued tokens are always valid for 10 minutes.
Issued tokens are always signed with ephemeral P-256 / `ES256` keys.

## Temporary signing behavior

For now, `idmouse` generates a fresh ES256 signing key each time it starts. That keeps private key
material out of the config file, but it also means previously issued tokens stop verifying after a
restart because the JWKS changes with each new process.
