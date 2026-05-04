export const openApiSpec = {
  openapi: '3.0.3',
  info: {
    title: 'SBOM Vulnerability Analyzer API',
    version: '0.1.0',
    description:
      'Upload Software Bill of Materials (CycloneDX or SPDX JSON), parse components, and resolve every known vulnerability via OSV.dev — enriched with EPSS exploit-probability scores and malicious-package detection.',
  },
  servers: [
    { url: 'http://localhost:3000', description: 'Local docker-compose' },
  ],
  tags: [
    { name: 'system', description: 'Liveness, configuration, metrics' },
    { name: 'auth', description: 'Auth0 session handlers' },
    { name: 'sbom', description: 'SBOM uploads and analyses' },
    { name: 'components', description: 'Components within an analysis' },
    { name: 'vulns', description: 'Vulnerability lookups (OSV + EPSS)' },
  ],
  components: {
    securitySchemes: {
      betterAuthSession: {
        type: 'apiKey',
        in: 'cookie',
        name: 'better-auth.session_token',
        description:
          'Better Auth session cookie set after `/api/auth/sign-in/email`. Log in via browser; cookie is sent automatically.',
      },
    },
    schemas: {
      AnalysisStatus: {
        type: 'string',
        enum: ['PARSING', 'SCANNING', 'COMPLETE', 'ERROR'],
      },
      Severity: {
        type: 'string',
        enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'],
      },
      AnalysisSummary: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          filename: { type: 'string' },
          format: { type: 'string', enum: ['CycloneDX', 'SPDX'] },
          specVersion: { type: 'string' },
          status: { $ref: '#/components/schemas/AnalysisStatus' },
          componentCount: { type: 'integer' },
          vulnerableCount: { type: 'integer' },
          maliciousCount: { type: 'integer' },
          riskScore: { type: 'integer' },
          isDemo: { type: 'boolean' },
          createdAt: { type: 'string', format: 'date-time' },
        },
      },
      Component: {
        type: 'object',
        properties: {
          id: { type: 'string', format: 'uuid' },
          purl: { type: 'string', example: 'pkg:pypi/django@2.2.0' },
          name: { type: 'string' },
          version: { type: 'string' },
          ecosystem: { type: 'string', nullable: true, example: 'PyPI' },
          licenses: { type: 'array', items: { type: 'string' } },
          vulnCount: { type: 'integer' },
          maxSeverity: { $ref: '#/components/schemas/Severity', nullable: true },
          maxEpss: { type: 'number', format: 'float', nullable: true },
          isMalicious: { type: 'boolean' },
          maliciousReason: {
            type: 'string',
            nullable: true,
            enum: ['osv_malicious', 'typosquat', 'suspicious_name', null],
          },
          maliciousDetail: { type: 'string', nullable: true },
        },
      },
      Vulnerability: {
        type: 'object',
        properties: {
          id: { type: 'string', example: 'GHSA-jfh8-c2jp-5v3q' },
          aliases: { type: 'array', items: { type: 'string' } },
          summary: { type: 'string' },
          details: { type: 'string' },
          severity: { $ref: '#/components/schemas/Severity' },
          cvssScore: { type: 'number', format: 'float', nullable: true },
          cvssVector: { type: 'string', nullable: true },
          fixedVersions: { type: 'array', items: { type: 'string' } },
          references: {
            type: 'array',
            items: {
              type: 'object',
              properties: { type: { type: 'string' }, url: { type: 'string', format: 'uri' } },
            },
          },
          published: { type: 'string', format: 'date-time', nullable: true },
          modified: { type: 'string', format: 'date-time', nullable: true },
          epss: {
            type: 'object',
            nullable: true,
            properties: {
              cve: { type: 'string' },
              epss: { type: 'number', description: '0-1 exploit probability over next 30 days' },
              percentile: { type: 'number', description: '0-1 rank vs all CVEs' },
              date: { type: 'string', format: 'date' },
            },
          },
          epssPriority: {
            type: 'string',
            nullable: true,
            enum: ['urgent', 'elevated', 'low', null],
          },
          isMalicious: { type: 'boolean' },
        },
      },
      SeverityDistribution: {
        type: 'object',
        properties: {
          CRITICAL: { type: 'integer' },
          HIGH: { type: 'integer' },
          MEDIUM: { type: 'integer' },
          LOW: { type: 'integer' },
          NONE: { type: 'integer' },
        },
      },
      Stats: {
        type: 'object',
        properties: {
          componentCount: { type: 'integer' },
          vulnerableCount: { type: 'integer' },
          severityDistribution: { $ref: '#/components/schemas/SeverityDistribution' },
          licenseCounts: {
            type: 'object',
            additionalProperties: { type: 'integer' },
          },
          topVulnerable: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                name: { type: 'string' },
                version: { type: 'string' },
                purl: { type: 'string' },
                vulnCount: { type: 'integer' },
                maxSeverity: { $ref: '#/components/schemas/Severity' },
              },
            },
          },
        },
      },
      Error: {
        type: 'object',
        properties: { error: { type: 'string' } },
      },
    },
  },
  paths: {
    '/api/health': {
      get: {
        tags: ['system'],
        summary: 'Liveness probe',
        responses: {
          200: {
            description: 'Service is alive',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { status: { type: 'string' }, timestamp: { type: 'string' } },
                },
              },
            },
          },
        },
      },
    },
    '/api/config': {
      get: {
        tags: ['system'],
        summary: 'Public client bootstrap config',
        responses: {
          200: {
            description: 'Client config',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    authProvider: { type: 'string' },
                    audience: { type: 'string', nullable: true },
                    maxSbomBytes: { type: 'integer' },
                    maxComponents: { type: 'integer' },
                  },
                },
              },
            },
          },
        },
      },
    },
    '/api/metrics': {
      get: {
        tags: ['system'],
        summary: 'Prometheus scrape endpoint',
        responses: {
          200: {
            description: 'Prometheus metrics',
            content: { 'text/plain': { schema: { type: 'string' } } },
          },
        },
      },
    },
    '/api/auth/sign-up/email': {
      post: {
        tags: ['auth'],
        summary: 'Sign up with email + password',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', properties: { email: { type: 'string' }, password: { type: 'string' }, name: { type: 'string' } }, required: ['email', 'password', 'name'] } } },
        },
        responses: { 200: { description: 'Account created, session set' }, 400: { description: 'Validation error' } },
      },
    },
    '/api/auth/sign-in/email': {
      post: {
        tags: ['auth'],
        summary: 'Sign in with email + password',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', properties: { email: { type: 'string' }, password: { type: 'string' } }, required: ['email', 'password'] } } },
        },
        responses: { 200: { description: 'Session set' }, 401: { description: 'Invalid credentials' } },
      },
    },
    '/api/auth/sign-out': {
      post: {
        tags: ['auth'],
        summary: 'Clear session',
        security: [{ betterAuthSession: [] }],
        responses: { 200: { description: 'Signed out' } },
      },
    },
    '/api/auth/get-session': {
      get: {
        tags: ['auth'],
        summary: 'Current session',
        security: [{ betterAuthSession: [] }],
        responses: { 200: { description: 'Session + user' } },
      },
    },
    '/api/sbom/demo': {
      post: {
        tags: ['sbom'],
        summary: 'Load the bundled demo SBOM',
        description: 'Loads a curated demo SBOM that exercises all features (Log4Shell, typosquats, low-Scorecard packages, clean packages). The created Analysis is tagged with isDemo=true.',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: {
            description: 'Demo analysis created',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    analysisId: { type: 'string', format: 'uuid' },
                    format: { type: 'string' },
                    componentCount: { type: 'integer' },
                    status: { $ref: '#/components/schemas/AnalysisStatus' },
                    isDemo: { type: 'boolean' },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          500: { description: 'Demo SBOM not bundled' },
        },
      },
    },
    '/api/sbom/upload': {
      post: {
        tags: ['sbom'],
        summary: 'Upload an SBOM',
        description: 'Accepts a CycloneDX or SPDX JSON file. Parses, persists, kicks off async OSV+EPSS scan.',
        security: [{ betterAuthSession: [] }],
        requestBody: {
          required: true,
          content: {
            'multipart/form-data': {
              schema: {
                type: 'object',
                properties: { file: { type: 'string', format: 'binary' } },
                required: ['file'],
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Analysis accepted',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    analysisId: { type: 'string', format: 'uuid' },
                    format: { type: 'string' },
                    componentCount: { type: 'integer' },
                    status: { $ref: '#/components/schemas/AnalysisStatus' },
                  },
                },
              },
            },
          },
          400: { description: 'Bad request', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/sbom/analyses': {
      get: {
        tags: ['sbom'],
        summary: 'List your analyses',
        security: [{ betterAuthSession: [] }],
        parameters: [
          { name: 'limit', in: 'query', schema: { type: 'integer', maximum: 200, default: 50 } },
        ],
        responses: {
          200: {
            description: 'Recent analyses',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    analyses: { type: 'array', items: { $ref: '#/components/schemas/AnalysisSummary' } },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
        },
      },
    },
    '/api/sbom/analyses/{id}': {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
      get: {
        tags: ['sbom'],
        summary: 'Get analysis summary',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: { description: 'Analysis', content: { 'application/json': { schema: { $ref: '#/components/schemas/AnalysisSummary' } } } },
          401: { description: 'Unauthorized' },
          404: { description: 'Not found' },
        },
      },
      delete: {
        tags: ['sbom'],
        summary: 'Delete analysis',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: { description: 'Deleted' },
          401: { description: 'Unauthorized' },
          404: { description: 'Not found' },
        },
      },
    },
    '/api/sbom/analyses/{id}/components': {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
      get: {
        tags: ['components'],
        summary: 'List components in an analysis',
        security: [{ betterAuthSession: [] }],
        parameters: [
          { name: 'search', in: 'query', schema: { type: 'string' }, description: 'Match name or purl' },
          { name: 'severity', in: 'query', schema: { $ref: '#/components/schemas/Severity' } },
          { name: 'sort', in: 'query', schema: { type: 'string', enum: ['name', 'version', 'ecosystem', 'vulnCount', 'maxSeverity'] } },
          { name: 'order', in: 'query', schema: { type: 'string', enum: ['asc', 'desc'] } },
        ],
        responses: {
          200: {
            description: 'Components',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: { components: { type: 'array', items: { $ref: '#/components/schemas/Component' } } },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Analysis not found' },
        },
      },
    },
    '/api/sbom/analyses/{id}/components/{purl}': {
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        { name: 'purl', in: 'path', required: true, schema: { type: 'string' }, description: 'base64url-encoded purl' },
      ],
      get: {
        tags: ['components'],
        summary: 'Component detail with vulnerabilities',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: {
            description: 'Component + vulnerabilities',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    component: { $ref: '#/components/schemas/Component' },
                    vulnerabilities: { type: 'array', items: { type: 'object' } },
                  },
                },
              },
            },
          },
          401: { description: 'Unauthorized' },
          404: { description: 'Not found' },
        },
      },
    },
    '/api/sbom/analyses/{id}/stats': {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
      get: {
        tags: ['sbom'],
        summary: 'Aggregate statistics',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: { description: 'Stats', content: { 'application/json': { schema: { $ref: '#/components/schemas/Stats' } } } },
          401: { description: 'Unauthorized' },
          404: { description: 'Not found' },
        },
      },
    },
    '/api/sbom/analyses/{id}/export/{format}': {
      parameters: [
        { name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } },
        { name: 'format', in: 'path', required: true, schema: { type: 'string', enum: ['json', 'html', 'pdf', 'vex', 'cyclonedx-vex'] } },
      ],
      get: {
        tags: ['sbom'],
        summary: 'Export an analysis report',
        description: 'json = full structured dump; vex = CycloneDX VEX format; html/pdf = print-ready report.',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: { description: 'Report content (varies by format)' },
          401: { description: 'Unauthorized' },
          404: { description: 'Not found' },
        },
      },
    },
    '/api/kev/refresh': {
      post: {
        tags: ['system'],
        summary: 'Force refresh CISA KEV catalog',
        security: [{ betterAuthSession: [] }],
        responses: { 200: { description: 'KEV catalog metadata' }, 401: { description: 'Unauthorized' } },
      },
      get: {
        tags: ['system'],
        summary: 'Get current KEV catalog metadata',
        responses: { 200: { description: 'KEV metadata' } },
      },
    },
    '/api/vulns/{id}': {
      parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' }, example: 'GHSA-jfh8-c2jp-5v3q' }],
      get: {
        tags: ['vulns'],
        summary: 'Vulnerability detail (OSV + EPSS)',
        security: [{ betterAuthSession: [] }],
        responses: {
          200: { description: 'Vulnerability', content: { 'application/json': { schema: { $ref: '#/components/schemas/Vulnerability' } } } },
          401: { description: 'Unauthorized' },
          404: { description: 'Not found' },
        },
      },
    },
  },
};
