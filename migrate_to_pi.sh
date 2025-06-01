#!/bin/bash
TARGET="pi@192.168.0.186"
APP_DIR="~/flask_prod"

# 1. Sync only changed files (with exclusions)
rsync -avz \
  --exclude='__pycache__' \
  --exclude='venv' \
  --exclude='.git' \
  --exclude='instance' \
  --exclude='config.py' \
  --exclude='cookie.txt' \
  --exclude='uploads' \
  --exclude='*.db' \
  --include='app/' \
  --include='app/***' \
  --include='migrations/' \
  --include='migrations/***' \
  --include='config.example.py' \
  --include='requirements.txt' \
  --include='run.py' \
  --include='Dockerfile' \
  --include='docker-compose.yml' \
  --exclude='*' \
  ./ "$TARGET":$APP_DIR/

# 2. Update dependencies only if needed
ssh "$TARGET" "cd $APP_DIR && venv/bin/pip install -r requirements.txt"

# 3. Apply database migrations
ssh "$TARGET" "cd $APP_DIR && source venv/bin/activate && flask db upgrade"

echo "Production update complete! No data was overwritten."