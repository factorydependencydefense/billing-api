import _ from 'lodash';

const basePlan = {
  seats: 1,
  currency: 'USD',
  features: { sso: false, audit: false, support: 'community' },
};

export function resolvePlan(overrides) {
  return _.merge({}, basePlan, overrides);
}

export function planChanged(before, after) {
  return !_.isEqual(before, after);
}

export function indexPlans(plans) {
  return _.keyBy(plans, 'id');
}

export function invoiceLine(plan) {
  return _.pick(plan, ['id', 'seats', 'currency']);
}
