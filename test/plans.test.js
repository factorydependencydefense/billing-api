import assert from 'node:assert/strict';
import test from 'node:test';
import request from 'supertest';
import { createApp } from '../src/index.js';
import { indexPlans, invoiceLine, planChanged, resolvePlan } from '../src/plans.js';

test('resolvePlan deep merges feature flags', () => {
  const plan = resolvePlan({ seats: 10, features: { sso: true } });
  assert.equal(plan.seats, 10);
  assert.equal(plan.features.sso, true);
  assert.equal(plan.features.audit, false);
  assert.equal(plan.features.support, 'community');
});

test('planChanged compares deeply', () => {
  const a = resolvePlan({ seats: 2 });
  assert.equal(planChanged(a, resolvePlan({ seats: 2 })), false);
  assert.equal(planChanged(a, resolvePlan({ seats: 3 })), true);
});

test('indexPlans keys by id', () => {
  const byId = indexPlans([{ id: 'a' }, { id: 'b' }]);
  assert.deepEqual(Object.keys(byId), ['a', 'b']);
});

test('invoiceLine keeps only billable fields', () => {
  assert.deepEqual(invoiceLine(resolvePlan({ id: 'team', seats: 10 })), {
    id: 'team',
    seats: 10,
    currency: 'USD',
  });
});

test('GET /plans/:id returns a resolved plan', async () => {
  const res = await request(createApp()).get('/plans/team').expect(200);
  assert.equal(res.body.features.sso, true);
  assert.equal(res.body.features.audit, false);
});

test('GET /plans/:id 404s on unknown plan', async () => {
  await request(createApp()).get('/plans/nope').expect(404);
});
