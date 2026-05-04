#!/bin/sh
set -e
echo "Syncing Prisma schema to database..."
node ./node_modules/prisma/build/index.js db push --schema=./prisma/schema.prisma --skip-generate --accept-data-loss || echo "Schema sync failed (continuing anyway)"
exec "$@"
