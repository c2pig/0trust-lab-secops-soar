import { timingSafeEqual } from 'node:crypto';
import { Hono } from 'hono';
import { onRequest as observabilityMiddleware } from '../functions/api/_middleware';
import { onRequestPost as containPost } from '../functions/api/secops-soar/contain';
import {
  onRequestPost as ingestPost,
  type KVNamespace,
  type SecopsEnv
} from '../functions/api/secops-soar/ingest';
import { createKvAdapter } from './kvAdapter';

export interface CloudRunEnv extends SecopsEnv {
  LAB_SLUG?: string;
  LAB_ROUTER_SECRET?: string;
  FIRESTORE_COLLECTION?: string;
  OTLP_ENDPOINT?: string;
  OTLP_AUTH_HEADER?: string;
}

export function verifyRouterSecret(
  provided: string | null | undefined,
  expected: string | undefined
): boolean {
  if (!provided || !expected) {
    return false;
  }
  const providedBuf = Buffer.from(provided, 'utf8');
  const expectedBuf = Buffer.from(expected, 'utf8');
  if (providedBuf.length !== expectedBuf.length) {
    return false;
  }
  return timingSafeEqual(providedBuf, expectedBuf);
}

type PagesHandler = (context: {
  request: Request;
  env: CloudRunEnv;
}) => Promise<Response>;

export function createCloudRunApp(options?: {
  env?: CloudRunEnv;
  kv?: KVNamespace;
}): Hono {
  const app = new Hono();
  const baseEnv: CloudRunEnv = options?.env ?? {
    ENVIRONMENT: process.env.ENVIRONMENT || (process.env.K_SERVICE ? 'production' : 'development'),
    LAB_SLUG: process.env.LAB_SLUG || 'secops-soar',
    LAB_ROUTER_SECRET: process.env.LAB_ROUTER_SECRET,
    FIRESTORE_COLLECTION: process.env.FIRESTORE_COLLECTION || 'kv_state',
    OTLP_ENDPOINT: process.env.OTLP_ENDPOINT,
    OTLP_AUTH_HEADER: process.env.OTLP_AUTH_HEADER
  };

  const labSlug = baseEnv.LAB_SLUG || 'secops-soar';
  const kv =
    options?.kv ??
    baseEnv.STATE_KV ??
    createKvAdapter({
      labSlug,
      collectionName: baseEnv.FIRESTORE_COLLECTION || 'kv_state'
    });

  const runtimeEnv: CloudRunEnv = {
    ...baseEnv,
    STATE_KV: kv
  };

  // Cloud Run startup/liveness probe — exempt from X-Lab-Router-Secret, no Firestore/secret access
  app.get('/healthz', (c) => {
    return c.json({ ok: true, lab: labSlug }, 200);
  });

  // Fail-closed constant-time X-Lab-Router-Secret validation on all /api/* routes
  app.use('/api/*', async (c, next) => {
    const isProduction = baseEnv.ENVIRONMENT === 'production';
    const expectedSecret = baseEnv.LAB_ROUTER_SECRET;
    const mustEnforce = isProduction || Boolean(expectedSecret);

    if (mustEnforce) {
      const providedSecret = c.req.header('x-lab-router-secret');
      if (!verifyRouterSecret(providedSecret, expectedSecret)) {
        return c.json({ error: 'FORBIDDEN_DIRECT_ORIGIN' }, 403);
      }
    }

    await next();
  });

  const wrap = (handler: PagesHandler) => {
    return async (c: { req: { raw: Request } }): Promise<Response> => {
      return observabilityMiddleware({
        request: c.req.raw,
        env: runtimeEnv,
        next: () => handler({ request: c.req.raw, env: runtimeEnv }),
        waitUntil: (promise: Promise<unknown>) => {
          promise.catch(() => {
            // Non-blocking background OTLP export; never crash request or process
          });
        }
      });
    };
  };

  app.post('/api/secops-soar/ingest', wrap(ingestPost));
  app.post('/api/secops-soar/contain', wrap(containPost));

  return app;
}
