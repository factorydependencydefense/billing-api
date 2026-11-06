// These assertions pinned the vulnerable behaviour of jsonwebtoken 8.5.1 and were inverted by the
// upgrade to 9.0.3 (GHSA-8cf7-32gw-wr33, GHSA-hjrf-2m68-5959, GHSA-qwph-4952-7xr6).
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { verifyBillingToken } from '../src/auth.js';
import { createApp } from '../src/index.js';

const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });

const legacyPair = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
const LEGACY_PRIVATE_PEM = legacyPair.privateKey.export({ type: 'pkcs8', format: 'pem' });

function forgeWithPublicKey(payload) {
  return jwt.sign(payload, PUBLIC_PEM, { algorithm: 'HS256' });
}

async function withPublicKey(key, fn) {
  const previous = process.env.BILLING_JWT_PUBLIC_KEY;
  process.env.BILLING_JWT_PUBLIC_KEY = key;
  try {
    return await fn();
  } finally {
    if (previous === undefined) delete process.env.BILLING_JWT_PUBLIC_KEY;
    else process.env.BILLING_JWT_PUBLIC_KEY = previous;
  }
}

test('secure now: an HS256 token signed with the RSA public key is rejected', () => {
  assert.throws(() => verifyBillingToken(forgeWithPublicKey({ sub: 'attacker' }), PUBLIC_PEM), {
    name: 'JsonWebTokenError',
    message: /must be a symmetric key when using HS256/,
  });
});

test('secure now: POST /plans/:id/change rejects a token forged with the RSA public key', async () => {
  await withPublicKey(PUBLIC_PEM, async () => {
    const token = forgeWithPublicKey({ sub: 'attacker', scopes: ['plans:write'] });
    const res = await request(createApp())
      .post('/plans/team/change')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
    assert.deepEqual(res.body, { error: 'invalid token' });
    assert.equal(res.body.actor, undefined);
  });
});

test('secure now: an unsigned "none" token is rejected', async () => {
  const token = jwt.sign({ sub: 'attacker', scopes: ['plans:write'] }, '', { algorithm: 'none' });
  assert.throws(() => verifyBillingToken(token, PUBLIC_PEM), { name: 'JsonWebTokenError' });
  await withPublicKey(PUBLIC_PEM, async () => {
    await request(createApp())
      .post('/plans/team/change')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
  });
});

test('secure now: signing RS256 with a sub-2048-bit legacy RSA key is rejected', () => {
  assert.throws(() => jwt.sign({ sub: 'ops@example.com' }, LEGACY_PRIVATE_PEM, { algorithm: 'RS256' }), {
    message: /minimum key size of 2048 bits for RS256/,
  });
});
