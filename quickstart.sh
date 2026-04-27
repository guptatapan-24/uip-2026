#!/bin/bash
# Quick start script for local development

set -e

echo "🔥 LLM Hallucination Firewall - Quick Start"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker to continue."
    exit 1
fi

# Check Python
if ! command -v python3.11 &> /dev/null; then
    echo "⚠️  Python 3.11 not found. Using available Python version."
fi

# Create .env from template
if [ ! -f .env ]; then
    echo "📋 Creating .env from template..."
    cp .env.example .env
    echo "✓ Created .env - please edit with your API keys"
fi

# Install Python dependencies
echo "📦 Installing Python dependencies..."
make install

# Start Docker services
echo "🐳 Starting Docker services..."
make docker-up

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Run migrations
echo "🗄️  Running database migrations..."
# TODO: Run alembic upgrade head

# Start development server
echo ""
echo "✅ All services started!"
echo ""
echo "📊 Dashboard:      http://localhost:3000"
echo "🔌 API Docs:       http://localhost:8000/docs"
echo "📈 Prometheus:     http://localhost:9090"
echo "🎨 Grafana:        http://localhost:3000 (admin/admin)"
echo ""
echo "📝 Development server running..."
echo "Press Ctrl+C to stop"
echo ""

make dev
