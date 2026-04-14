# idmouse

`idmouse` is a Rust service built with Axum for exchanging Kubernetes-issued bearer tokens into
SurrealDB authentication tokens.

It is intended to run inside a Kubernetes cluster:

- callers present a cluster-issued JWT to `idmouse`
- `idmouse` asks the Kubernetes API server to authenticate that token via `TokenReview`
- the resulting Kubernetes identity is matched against TOML-configured user rules
- `idmouse` issues a SurrealDB-ready JWT containing the claims required by `DEFINE ACCESS ... TYPE JWT`

## Why this shape

Kubernetes service account tokens already identify workloads as usernames like
`system:serviceaccount:<namespace>:<name>`. `idmouse` turns that cluster identity into a smaller,
purpose-built token for SurrealDB.

SurrealDB expects JWTs used with `DEFINE ACCESS ... TYPE JWT` on a database to contain at least:

- `exp`
- `ac`
- `ns`
- `db`

It also understands optional claims like `id`, `nbf`, and `rl`.

## Running locally

Start the service with:

```bash
cargo run -- -c ./idmouse.toml
```

Then request a SurrealDB token by sending a Kubernetes bearer token:

```bash
curl -s http://127.0.0.1:8080/token \
  -H "Authorization: Bearer $KUBE_TOKEN"
```

The JWKS for SurrealDB lives at:

```text
http://127.0.0.1:8080/.well-known/jwks.json
```

## Example config

```toml
bind_address = "0.0.0.0:8080"
issuer = "https://idmouse.default.svc.cluster.local"

[kubernetes]
audiences = ["idmouse"]

[surreal]
access_method = "idmouse"
namespace = "app"
database = "main"
token_ttl_seconds = 3600
audience = "surrealdb"

[signing]
algorithm = "ES256"
key_id = "dev-key"
private_key_pem = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgN+6VmUXG/ef3u67r
ATInaYskFnH49T8PsjkoXN2yDeqhRANCAAQaTpxRpVzE+CCkLWI9uVtIcez7yDmX
iJSzcPn+34vupXwZBL8U/4mXcCbJbNaitEhq4SajOVtqk9WWsU7wJoWj
-----END PRIVATE KEY-----
"""

[[users]]
subject = "alice"
kubernetes_usernames = ["system:serviceaccount:team-a:alice"]
surreal_roles = ["Editor"]
claims = { email = "alice@example.com", team = "team-a" }
```

## Matching rules

- If `kubernetes_usernames` is set, the Kubernetes username must match one of them.
- If `kubernetes_groups` is set, the reviewed identity must belong to at least one of them.
- If neither is set, `subject` is matched directly against the Kubernetes username.
- If more than one user rule matches, the request is rejected.

## SurrealDB setup

Configure SurrealDB to trust `idmouse` through JWKS:

```sql
USE NS app DB main;

DEFINE ACCESS idmouse ON DATABASE TYPE JWT
  URL "https://idmouse.default.svc.cluster.local/.well-known/jwks.json"
  AUTHENTICATE {
    IF $token.iss != "https://idmouse.default.svc.cluster.local" {
      THROW "Invalid token issuer"
    };
    IF $token.aud IS NOT "surrealdb" {
      THROW "Invalid token audience"
    };
  };
```

## Kubernetes permissions

`idmouse` needs permission to create `tokenreviews.authentication.k8s.io`, because it asks the API
server to validate presented bearer tokens.
