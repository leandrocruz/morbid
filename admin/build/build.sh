#!/usr/bin/env bash
#
# Builds the admin UI and deploys it to the production host via rsync.
#
# Usage:
#   ./build.sh                  # build only (dist stays in admin/dist)
#   ./build.sh <user@host>      # build + rsync dist/ to the host's /opt/morbid/nginx/shared/admin-ui/current/
#
# Matches the presto-console pattern: build locally, ship static files.

set -e

REMOTE="$1"
REMOTE_PATH="/opt/morbid/admin-ui/shared/console/current"

# 1. Produce the ScalaJS bundle (runs from repo root)
pushd ../.. > /dev/null
sbt "admin/fullLinkJS"
popd > /dev/null

# 2. Produce the Vite static bundle (runs from admin/)
pushd .. > /dev/null
npm install
npm run build
popd > /dev/null

echo
echo "Built admin UI at $(cd .. && pwd)/dist"

if [ -z "$REMOTE" ]; then
  echo
  echo "Deploy with:"
  echo "  rsync -avz --delete ../dist/ <user@host>:$REMOTE_PATH"
  exit 0
fi

echo
echo "Deploying to $REMOTE:$REMOTE_PATH"
rsync -avz --delete ../dist/ "$REMOTE:$REMOTE_PATH"
echo "Done."
