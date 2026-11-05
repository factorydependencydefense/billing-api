// These assertions pinned the RSA-public-key-as-HMAC-secret forgery and were inverted when
// jsonwebtoken was upgraded to 9.0.3; they now pin the rejection of that forgery.
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

function unsignedToken(payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.`;
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
    message: /must be a symmetric key/,
  });
});

test('secure now: POST /plans/:id/change rejects a token forged with the RSA public key', async () => {
  await withPublicKey(PUBLIC_PEM, async () => {
    const token = forgeWithPublicKey({ sub: 'attacker', scopes: ['plans:write'] });
    const res = await request(createApp())
      .post('/plans/team/change')
      .set('Authorization', `Bearer ${token}`)
      .expect(401);
    assert.equal(res.body.error, 'invalid token');
  });
});

test('secure now: an unsigned alg:none token is rejected', () => {
  const token = unsignedToken({ sub: 'attacker', scopes: ['plans:write'] });
  assert.throws(() => verifyBillingToken(token, PUBLIC_PEM), {
    name: 'JsonWebTokenError',
    message: /signature is required/,
  });
});

test('secure now: a legacy 1024-bit RSA key is refused for RS256', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
  const legacyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => jwt.sign({ sub: 'ops@example.com' }, legacyPem, { algorithm: 'RS256' }), {
    message: /minimum key size of 2048 bits/,
  });
});
