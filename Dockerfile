# Guardrail Assurance Console — container image.
#
#   docker build -t assurance-console .
#   docker run --rm -p 8000:8000 assurance-console
#   # open http://127.0.0.1:8000
#
# Python 3.12 (stable wheels for all deps); the code targets >=3.10.
FROM python:3.12-slim

WORKDIR /app

# Copy the package sources, then install dependencies from pyproject.
# (docs/, .venv, .git, tests, etc. are excluded via .dockerignore, so nothing
# internal is baked into the image.)
COPY pyproject.toml README.md ./
COPY common ./common
COPY sut_claims ./sut_claims
COPY assurance ./assurance
COPY web ./web

RUN pip install --no-cache-dir .

# Ensure the /app source tree (which includes web/templates and web/static) is
# what gets imported, not the wheel copy in site-packages.
ENV PYTHONPATH=/app

EXPOSE 8000

# 0.0.0.0 so the console is reachable from the host via the published port.
CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8000"]
