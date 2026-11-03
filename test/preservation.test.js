import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import jwt from 'jsonwebtoken';
import request from 'supertest';
import { authorizePlanChange, verifyBillingToken } from '../src/auth.js';
import { createApp } from '../src/index.js';

const SHARED_SECRET = 'billing-preservation-secret';
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PUBLIC_PEM = publicKey.export({ type: 'spki', format: 'pem' });
const PRIVATE_PEM = privateKey.export({ type: 'pkcs8', format: 'pem' });

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

test('verifyBillingToken accepts a legitimate HS256 token from the shared secret era', () => {
  const token = jwt.sign({ sub: 'ops@example.com' }, SHARED_SECRET, { algorithm: 'HS256' });
  assert.equal(verifyBillingToken(token, SHARED_SECRET).sub, 'ops@example.com');
});

test('verifyBillingToken accepts a legitimate RS256 token', () => {
  const token = jwt.sign({ sub: 'ops@example.com' }, PRIVATE_PEM, { algorithm: 'RS256' });
  assert.equal(verifyBillingToken(token, PUBLIC_PEM).sub, 'ops@example.com');
});

test('verifyBillingToken rejects an HS256 token signed with another secret', () => {
  const token = jwt.sign({ sub: 'ops@example.com' }, 'other-secret', { algorithm: 'HS256' });
  assert.throws(() => verifyBillingToken(token, SHARED_SECRET), jwt.JsonWebTokenError);
});

test('authorizePlanChange requires the plans:write scope', () => {
  const scoped = jwt.sign({ sub: 'ops@example.com', scopes: ['plans:write'] }, PRIVATE_PEM, { algorithm: 'RS256' });
  const unscoped = jwt.sign({ sub: 'ops@example.com', scopes: ['plans:read'] }, PRIVATE_PEM, { algorithm: 'RS256' });
  assert.deepEqual(authorizePlanChange(scoped, 'team', PUBLIC_PEM), {
    actor: 'ops@example.com',
    planId: 'team',
  });
  assert.throws(() => authorizePlanChange(unscoped, 'team', PUBLIC_PEM), /not allowed to change plans/);
});

test('POST /plans/:id/change accepts a legitimate RS256 token', async () => {
  await withPublicKey(PUBLIC_PEM, async () => {
    const token = jwt.sign({ sub: 'ops@example.com', scopes: ['plans:write'] }, PRIVATE_PEM, { algorithm: 'RS256' });
    const res = await request(createApp())
      .post('/plans/team/change')
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    assert.equal(res.body.actor, 'ops@example.com');
    assert.deepEqual(res.body.line, { id: 'team', seats: 10, currency: 'USD' });
  });
});

test('POST /plans/:id/change returns 401 without a bearer token', async () => {
  await withPublicKey(PUBLIC_PEM, async () => {
    await request(createApp()).post('/plans/team/change').expect(401);
  });
});
