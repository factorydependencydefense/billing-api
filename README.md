# billing-api

Billing plan and invoice draft API. Part of the dependency-defense demo fleet.

```bash
npm ci
npm test
npm run build
npm start
```

## Tests

`npm test` runs `test/*.test.js` only: the plan resolution unit tests (`test/plans.test.js`), the
legitimate HS256 and RS256 token flows that must keep working across a `jsonwebtoken` upgrade
(`test/preservation.test.js`), and `test/characterization.test.js`, which pins today's behaviour so
a dependency change shows up as a diff rather than a surprise.

`npm run test:security` runs `test/security/**/*.test.js` and is deliberately **not** part of
`npm test`. Both of its tests are **red today**:

- `verifyBillingToken rejects an HS256 token signed with the RSA public key`
- `POST /plans/:id/change returns 401 for a token forged with the RSA public key`

They are red because the service was migrated from a shared secret to RSA and still accepts both,
so `verifyBillingToken` passes one key into `jwt.verify(token, key, { algorithms: ['HS256',
'RS256'] })`. On `jsonwebtoken` 8.5.1 an attacker can take the *public* key, use it as an HMAC
secret, sign an HS256 token with it and have it accepted. The two `vulnerable today:` tests in
`test/characterization.test.js` assert exactly that and are expected to be inverted when the issue
is fixed.

What these tests do not cover: there is no coverage of key rotation, `kid` selection, token expiry
or revocation, and nothing checks that only the right actors hold `plans:write`. The security suite
checks a single confusion between symmetric and asymmetric keys, not the full JWT threat model.
