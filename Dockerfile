# Optional second way to run the app. The normal way is still: python run.py
FROM python:3.13-slim

WORKDIR /app

# Install the packages first, so Docker can reuse this layer when only the code changes.
# They go into /app/.venv, the same place run.py uses, so run.py skips its own install.
COPY requirements.txt .
RUN python -m venv /app/.venv && /app/.venv/bin/pip install --no-cache-dir -r requirements.txt

COPY run.py .
COPY app ./app

# Do not run as root: if someone breaks into Flask, they get a user that owns only /app
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

# Listen on every address inside the container, so the Nginx container can reach Flask
ENV APP_HOST=0.0.0.0
EXPOSE 8000

CMD ["/app/.venv/bin/python", "run.py"]
