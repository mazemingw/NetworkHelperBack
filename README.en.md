# NetworkHelperBack

[简体中文](README.md)

Node.js / Express / MySQL backend for [Oplus Network Helper](https://github.com/mazemingw/oplus-network-helper), covering updates, announcements, LTE/NR cell parameters, nearby queries, developer authentication and engineering-plugin sharing. Original code is licensed under [Apache 2.0](LICENSE).

## Setup

Requires Node.js 18+, npm and MySQL. Install with `npm ci`, copy `.env.example` to `.env`, and fill in database settings. Create the target database and import `schema.sql` using a MySQL client. The schema contains table definitions only, with `CREATE TABLE IF NOT EXISTS`; it does not seed records or migrate existing tables. Existing databases need no schema change for nearby queries.

Set `DEV_AUTH_TOKEN_SECRET` to a separate random secret, then run `npm start`. The default port is `9895` and all routes use the `/networkhelp` prefix. Legacy deployments fall back to `DB_PASSWORD` for token signing; if both values are absent, an ephemeral random secret is used and tokens expire on restart.

Developer credentials are configured in `dev_auth_credentials` using role (`developer` or `super_admin`), SHA-256 password hash and enabled status. There are no default accounts or passwords. Optional plugin sharing requires the OSS settings in `.env.example`.

Real `.env` files, credential seed SQL, database records and cloud credentials are excluded. Deploy access controls appropriate to the existing routes: this server does not enforce authentication uniformly across every read/write endpoint.

## Nearby cells

`POST /networkhelp/cell-params/nearby` accepts WGS84 coordinates, `radius_km` from 1 to 10, optional `rat` (LTE/4G, NR/5G or ALL) and optional `band` (number, B-prefixed LTE or n-prefixed NR). Either filter, both or neither may be specified. Numeric bands without a RAT match the corresponding number in both RATs; a prefix restricts the RAT. Conflicting RAT/prefix filters return HTTP 400.

Filters run before distance sorting and truncation. Responses contain `lte` and `nr` arrays, at most 1000 cells per RAT, with truncation flags. Band matching uses downlink channel-number ranges; overlapping NR bands can match the same frequency. See [the complete API guide (Chinese)](nearby-api.md).

Update `routes.js`, `nearby.js` and `nearby-bands.js` together and restart the Node service. A GitHub push does not restart the deployed service.

## Validation

```sh
npm run check
npm test
```

Nearby API tests use an injected database stub and a temporary local HTTP server, covering validation, RAT/band combinations, geographic bounds, parameterized filtering and truncation. They do not require production database access.

## License

Original source: Apache-2.0, see [LICENSE](LICENSE). Dependencies retain their own licenses. Supply your own authorized cell data and application settings.
