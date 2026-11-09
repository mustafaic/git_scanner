FROM python:3.12-slim

WORKDIR /srv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY core ./core
COPY app ./app
# Sadece bu script (RUNBOOK.md 3: ilk admin bootstrap/parola sifirlama
# "docker compose exec app python tools/create_admin.py" ile calisir).
# tools/backup.py, tools/restore.py, tools/dependabot_compare.py buraya
# BILEREK kopyalanmaz -- bunlar orchestrator imajindan (pg_dump/pg_restore
# client, orchestrator'in kendi bagimliliklari) calisir, app'in sorumluluk
# alaninda degildir.
COPY tools/create_admin.py ./tools/create_admin.py

EXPOSE 8081
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
