# TRACE-X backend — FastAPI + SQLAlchemy + Alembic
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY alembic.ini .
COPY alembic ./alembic
COPY app ./app

# Non-root: the app only needs /app/data (volume-mounted in compose)
RUN useradd --create-home --uid 10001 tracex \
    && mkdir -p /app/data && chown -R tracex:tracex /app/data
USER tracex

VOLUME ["/app/data"]
EXPOSE 8000

# Migrations run as a controlled startup step (additive schema only);
# uvicorn serves the API and, when frontend/dist is present, the built UI.
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
