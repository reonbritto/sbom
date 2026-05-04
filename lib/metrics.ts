import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

const globalForMetrics = globalThis as unknown as {
  registry?: Registry;
  httpRequests?: Counter;
  httpDuration?: Histogram;
  sbomUploads?: Counter;
  osvQueries?: Counter;
};

export const registry =
  globalForMetrics.registry ??
  (() => {
    const r = new Registry();
    collectDefaultMetrics({ register: r });
    return r;
  })();

export const httpRequests =
  globalForMetrics.httpRequests ??
  new Counter({
    name: 'sbom_http_requests_total',
    help: 'HTTP requests handled',
    labelNames: ['method', 'route', 'status'],
    registers: [registry],
  });

export const httpDuration =
  globalForMetrics.httpDuration ??
  new Histogram({
    name: 'sbom_http_request_duration_seconds',
    help: 'HTTP request latency',
    labelNames: ['method', 'route'],
    buckets: [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
    registers: [registry],
  });

export const sbomUploads =
  globalForMetrics.sbomUploads ??
  new Counter({
    name: 'sbom_uploads_total',
    help: 'Number of SBOMs uploaded',
    labelNames: ['format', 'status'],
    registers: [registry],
  });

export const osvQueries =
  globalForMetrics.osvQueries ??
  new Counter({
    name: 'sbom_osv_queries_total',
    help: 'OSV API queries',
    labelNames: ['endpoint', 'status'],
    registers: [registry],
  });

if (process.env.NODE_ENV !== 'production') {
  globalForMetrics.registry = registry;
  globalForMetrics.httpRequests = httpRequests;
  globalForMetrics.httpDuration = httpDuration;
  globalForMetrics.sbomUploads = sbomUploads;
  globalForMetrics.osvQueries = osvQueries;
}
