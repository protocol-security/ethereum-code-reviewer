FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["gunicorn", "pr_security_review.web:create_app()", "--bind", "0.0.0.0:5000", "--workers", "4"]