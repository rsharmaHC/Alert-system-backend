# Database Migration & Schema Management

## Overview

This project uses Alembic for database migrations with automatic schema validation to prevent column mismatch errors in production.

## Architecture

### Migration Files
Located in `alembic/versions/`:
- Each migration adds/modifies database schema
- Migrations run automatically on deployment
- Downgrade scripts available for rollback

### Schema Validation Scripts

#### `scripts/check_schema.py`
Pre-deployment validation script. Use in CI/CD:
```bash
python scripts/check_schema.py
# Returns: 0 = valid, 1 = has issues
```

#### `scripts/validate_db_schema.py`
Interactive schema validation and auto-fix:
```bash
# Dry-run (show issues without fixing)
python scripts/validate_db_schema.py

# Auto-fix (add missing columns)
python scripts/validate_db_schema.py --fix
```

### Startup Script

`start.sh` - Runs on every deployment:
1. Validates database schema
2. Auto-fixes missing columns
3. Runs Alembic migrations
4. Starts the application

## Creating New Migrations

### For New Models/Columns

1. **Add the model/column to `app/models.py`**

2. **Generate migration automatically:**
   ```bash
   alembic revision --autogenerate -m "description of change"
   ```

3. **Review the generated migration** in `alembic/versions/`

4. **Test locally:**
   ```bash
   alembic upgrade head
   ```

### For Data Preservation (user_email pattern)

When adding foreign keys to users, always add `user_email` for data preservation:

```python
user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
user_email = Column(String(255), nullable=True)  # Preserved after user deletion
```

Then create a migration:
```bash
alembic revision -m "add user_email to <table_name>"
```

Edit the migration to check if column exists before adding.

## Deployment Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     Railway Deploy                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  1. start.sh executes                                       │
│     - python scripts/validate_db_schema.py --fix            │
│     - alembic upgrade head                                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  2. Schema Validation                                       │
│     - Checks all model columns exist in DB                  │
│     - Auto-adds missing columns                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  3. Alembic Migrations                                      │
│     - Runs all pending migrations                           │
│     - Updates alembic_version table                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  4. Application Starts                                      │
│     - uvicorn starts on port 8000                           │
└─────────────────────────────────────────────────────────────┘
```

## Troubleshooting

### Column Does Not Exist Error

If you see errors like:
```
sqlalchemy.exc.ProgrammingError: column table_name.column_name does not exist
```

**Immediate fix:**
```bash
# On production (Railway)
# The startup script will auto-fix on next deploy

# Locally
python scripts/validate_db_schema.py --fix
```

**Prevent future issues:**
1. Always create migrations for model changes
2. Run `alembic upgrade head` before testing locally
3. Use `scripts/check_schema.py` in CI/CD

### Migration Conflicts

If migrations are out of order:
```bash
# Check current revision
alembic current

# See all migrations
alembic history

# Fix: Update down_revision in migration file
# Then re-run
alembic upgrade head
```

### Rollback Migrations

```bash
# Rollback one migration
alembic downgrade -1

# Rollback to specific revision
alembic downgrade <revision_id>

# Rollback all (careful!)
alembic downgrade base
```

## Best Practices

1. **Always create migrations for schema changes** - Never modify DB manually
2. **Test migrations locally first** - Run `alembic upgrade head` before deploying
3. **Add user_email for audit tables** - Preserves data after user deletion
4. **Use ON DELETE SET NULL** - For foreign keys to users table
5. **Run schema validation in CI/CD** - Catch issues before production
6. **Keep migrations small and focused** - One change per migration
7. **Never edit applied migrations** - Create new ones for changes

## Migration Chain

Current migration order:
```
location_audience_v1
  ↓
add_audit_log_user_email
  ↓
remove_user_deleted_at
  ↓
add_user_email_columns (delivery_logs, notification_responses)
  ↓
fix_audit_logs_fk
  ↓
add_user_email_incoming (incoming_messages)
  ↓
ensure_all_user_email_columns (all tables)
  ↓
ensure_all_columns_exist (comprehensive check)
```

## Environment Variables

```bash
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

Required for migrations to run.
