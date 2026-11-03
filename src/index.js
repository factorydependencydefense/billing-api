import express from 'express';
import { authorizePlanChange, bearerToken } from './auth.js';
import { indexPlans, invoiceLine, planChanged, resolvePlan } from './plans.js';

const catalog = [
  { id: 'starter', seats: 1 },
  { id: 'team', seats: 10, features: { sso: true } },
  { id: 'enterprise', seats: 100, features: { sso: true, audit: true, support: 'dedicated' } },
];

export function createApp() {
  const app = express();
  app.use(express.json());

  app.get('/plans/:id', (req, res) => {
    const plan = indexPlans(catalog)[req.params.id];
    if (!plan) return res.status(404).json({ error: 'unknown plan' });
    return res.json(resolvePlan(plan));
  });

  app.post('/plans/:id/preview', (req, res) => {
    const current = resolvePlan(indexPlans(catalog)[req.params.id] ?? {});
    const next = resolvePlan({ ...current, ...req.body });
    res.json({ changed: planChanged(current, next), line: invoiceLine(next) });
  });

  app.post('/plans/:id/change', (req, res) => {
    const token = bearerToken(req.get('authorization'));
    if (!token) return res.status(401).json({ error: 'missing bearer token' });

    let authorized;
    try {
      authorized = authorizePlanChange(token, req.params.id);
    } catch {
      return res.status(401).json({ error: 'invalid token' });
    }

    const plan = indexPlans(catalog)[req.params.id];
    if (!plan) return res.status(404).json({ error: 'unknown plan' });
    return res.json({ ...authorized, line: invoiceLine(resolvePlan(plan)) });
  });

  return app;
}

if (process.argv[1] && process.argv[1].endsWith('index.js')) {
  const port = Number(process.env.PORT ?? 3001);
  createApp().listen(port, () => console.log(`billing-api listening on ${port}`));
}
