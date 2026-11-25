import type { Hono } from 'hono';
import { onRequestPost as containPost } from '../functions/api/secops-soar/contain';
import {
  onRequestPost as ingestPost,
  type SecopsEnv
} from '../functions/api/secops-soar/ingest';
import type { KVNamespace } from './kvAdapter';
import {
  createBaseLabApp,
  verifyRouterSecret,
  type BaseCloudRunEnv
} from './runtime';

export { verifyRouterSecret };

export interface CloudRunEnv extends BaseCloudRunEnv, SecopsEnv {}

export function createCloudRunApp(options?: {
  env?: CloudRunEnv;
  kv?: KVNamespace;
}): Hono {
  return createBaseLabApp<CloudRunEnv>({
    labSlug: 'secops-soar',
    env: options?.env,
    kv: options?.kv,
    registerRoutes(app, wrap) {
      app.post('/api/secops-soar/ingest', wrap(ingestPost));
      app.post('/api/secops-soar/contain', wrap(containPost));
    }
  });
}
