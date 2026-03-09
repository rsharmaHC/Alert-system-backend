#!/bin/bash
set -e

echo "========================================="
echo "Starting Alert System Backend"
echo "========================================="

echo "Step 1: Validating database schema..."
python scripts/validate_db_schema.py --fix || true

echo "Step 2: Running database migrations..."
alembic upgrade head

echo "Step 3: Starting application server..."
exec "$@"
