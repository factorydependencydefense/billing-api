// These assertions pin the secure behaviour after the jsonwebtoken 9.0.3 upgrade: a key passed to
// jwt.verify is no longer reinterpreted as an HMAC secret, so an RSA public key cannot be replayed
// as the signing key of an HS256 token.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { verifyBillingToken } from '../src/auth.js';
import { createApp } from '../src/index.js';

const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });

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
  assert.throws(
    () => verifyBillingToken(forgeWithPublicKey({ sub: 'attacker' }), PUBLIC_PEM),
    jwt.JsonWebTokenError,
  );
});

test('secure now: POST /plans/:id/change refuses a token forged with the RSA public key', async () => {
  await withPublicKey(PUBLIC_PEM, async () => {
    const token = forgeWithPublicKey({ sub: 'attacker', scopes: ['plans:write'] });
    const res = await request(createApp())
      .post('/plans/team/change')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
    assert.equal(res.body.error, 'invalid token');
    assert.equal(res.body.actor, undefined);
  });
});
