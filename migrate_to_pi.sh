#!/bin/bash
TARGET="cat@192.168.0.186"

# 1. Utwórz folder na RPi jeśli nie istnieje
ssh "$TARGET" "mkdir -p ~/flask_prod"

# 2. Wyślij projekt (z wykluczeniami)
rsync -avz \
  --exclude='__pycache__' \
  --exclude='venv' \
  --exclude='.git' \
  ./ "$TARGET":~/flask_prod/

# 3. Zainstaluj zależności na RPi
ssh "$TARGET" "cd ~/flask_prod && python3 -m venv venv && venv/bin/pip install -r requirements.txt"