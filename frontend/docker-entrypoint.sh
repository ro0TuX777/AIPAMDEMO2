#!/bin/sh
# Runtime entrypoint for the aipam-frontend nginx image.
#
# Writes /usr/share/nginx/html/runtime-config.js from $AIPAM_API_TOKEN so the
# browser bundle can read the operator's current API token without rebuilding
# the image.  Loaded synchronously by index.html before the React bundle.

set -e

TOKEN="${AIPAM_API_TOKEN:-}"

# JSON-string-escape the token so unusual characters cannot break the JS
# file or inject markup: backslash -> \\, double-quote -> \"
ESCAPED="$(printf %s "$TOKEN" | sed 's/\\/\\\\/g; s/"/\\"/g')"

cat > /usr/share/nginx/html/runtime-config.js <<EOF
// Generated at container start from \$AIPAM_API_TOKEN by docker-entrypoint.sh.
// Read by frontend/src/main.tsx — do not edit by hand inside the container;
// rotate via the host .env file and restart the aipam-frontend container.
window.__AIPAM_CONFIG__ = { apiToken: "$ESCAPED" };
EOF

if [ -z "$TOKEN" ]; then
    echo "aipam-frontend: WARNING — AIPAM_API_TOKEN is empty; runtime-config.js was written with apiToken=''" >&2
    echo "aipam-frontend: set AIPAM_API_TOKEN in your .env or rotate via localStorage in the browser." >&2
fi

exec nginx -g 'daemon off;'
