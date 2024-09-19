# Dockerfile
FROM python:3.9-slim

# Install poetry
RUN pip install poetry

WORKDIR /app

# Copy poetry files
COPY pyproject.toml poetry.lock* ./

# Install dependencies
RUN poetry config virtualenvs.create false \
    && poetry install --no-interaction --no-ansi

COPY app.py .

EXPOSE 5001

CMD ["python", "app.py"]