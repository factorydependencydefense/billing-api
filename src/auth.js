import jwt from 'jsonwebtoken';

export function billingVerificationKey() {
  return process.env.BILLING_JWT_PUBLIC_KEY ?? process.env.BILLING_JWT_SECRET ?? '';
}

export function bearerToken(authorization) {
  if (typeof authorization !== 'string') return undefined;
  const [scheme, value] = authorization.split(' ');
  if (scheme !== 'Bearer' || !value) return undefined;
  return value;
}

export function verifyBillingToken(token, key = billingVerificationKey()) {
  return jwt.verify(token, key, { algorithms: ['HS256', 'RS256'] });
}

export function authorizePlanChange(token, planId, key = billingVerificationKey()) {
  const claims = verifyBillingToken(token, key);
  const scopes = claims.scopes ?? [];
  if (!scopes.includes('plans:write')) {
    throw new Error('token is not allowed to change plans');
  }
  return { actor: claims.sub, planId };
}
