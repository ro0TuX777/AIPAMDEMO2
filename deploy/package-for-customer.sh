#!/bin/bash
# AIPAM Customer Package Script
# Creates a deployable package with Docker images for customer delivery
#
# Usage: ./deploy/package-for-customer.sh [output-dir]
#
# Output: aipam-deployment-YYYYMMDD.tar.gz containing:
#   - aipam-app.tar (Docker image)
#   - aipam-ollama.tar (Docker image with model)
#   - docker-compose.yml
#   - README.md
#   - install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${1:-$PROJECT_ROOT/dist}"
DATE=$(date +%Y%m%d)
PACKAGE_NAME="aipam-deployment-$DATE"

cd "$PROJECT_ROOT"

echo "============================================"
echo "AIPAM Customer Package Builder"
echo "============================================"

# Check prerequisites
echo "Checking prerequisites..."

if ! docker images | grep -q "aipam-app"; then
    echo "❌ aipam-app image not found. Run ./deploy/build.sh first."
    exit 1
fi

if ! docker images | grep -q "aipam-ollama"; then
    echo "❌ aipam-ollama image not found. Run ./deploy/build.sh first."
    exit 1
fi

echo "✅ Docker images found"

# Create output directory
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME"
cd "$OUTPUT_DIR/$PACKAGE_NAME"

echo ""
echo "Exporting Docker images..."

# Export images
echo "  Exporting aipam-app..."
docker save aipam-app:latest > aipam-app.tar
echo "  Exporting aipam-ollama..."
docker save aipam-ollama:latest > aipam-ollama.tar

# Copy deployment files
echo ""
echo "Copying deployment files..."
cp "$SCRIPT_DIR/docker-compose.yml" ./
cp "$SCRIPT_DIR/README.md" ./

# Create install script
cat > install.sh << 'EOF'
#!/bin/bash
# AIPAM Installation Script
set -e

echo "============================================"
echo "AIPAM Installation"
echo "============================================"

# Load Docker images
echo "Loading Docker images (this may take a few minutes)..."
docker load < aipam-app.tar
docker load < aipam-ollama.tar

echo ""
echo "✅ Images loaded successfully!"
echo ""
echo "To start AIPAM:"
echo "  docker-compose up -d"
echo ""
echo "Access the application at: http://localhost"
EOF
chmod +x install.sh

# Create the final package
echo ""
echo "Creating package archive..."
cd "$OUTPUT_DIR"
tar -czvf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"

# Calculate sizes
APP_SIZE=$(du -h "$PACKAGE_NAME/aipam-app.tar" | cut -f1)
OLLAMA_SIZE=$(du -h "$PACKAGE_NAME/aipam-ollama.tar" | cut -f1)
TOTAL_SIZE=$(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)

echo ""
echo "============================================"
echo "Package Complete!"
echo "============================================"
echo ""
echo "Package: $OUTPUT_DIR/${PACKAGE_NAME}.tar.gz"
echo ""
echo "Contents:"
echo "  - aipam-app.tar      ($APP_SIZE)"
echo "  - aipam-ollama.tar   ($OLLAMA_SIZE)"
echo "  - docker-compose.yml"
echo "  - README.md"
echo "  - install.sh"
echo ""
echo "Total size: $TOTAL_SIZE"
echo ""
echo "Customer instructions:"
echo "  1. Transfer ${PACKAGE_NAME}.tar.gz to customer server"
echo "  2. Extract: tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. cd $PACKAGE_NAME"
echo "  4. Run: ./install.sh"
echo "  5. Start: docker-compose up -d"

