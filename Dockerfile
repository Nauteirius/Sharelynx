# Buduj dla architektury ARM (ważne dla Raspberry Pi)
# Jeśli testujesz na laptopie x64, użyj: FROM python:3.11-slim
FROM python:3.11-slim
#FROM --platform=linux/arm/v7 python:3.11-slim

# Środowisko pracy
WORKDIR /app

# Instalacja zależności systemowych
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Kopiowanie wymagań i instalacja
COPY requirements.txt .
RUN pip install --no-cache-dir -U pip && \
    pip install --no-cache-dir -r requirements.txt

# Kopiuj resztę plików
COPY . .

# Port i wolumeny
EXPOSE 5000
VOLUME /app/uploads

# Uruchomienie aplikacji
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "app:app"]