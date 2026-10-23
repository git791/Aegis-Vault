FROM python:3.11-slim

WORKDIR /app

# Install project dependencies
COPY pyproject.toml README.md ./
COPY aegis ./aegis
RUN pip install --no-cache-dir .

EXPOSE 8000

ENV PORT=8000

CMD ["python", "-m", "aegis.cli", "serve"]
