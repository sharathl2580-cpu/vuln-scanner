FROM python:3.11-slim

RUN useradd --create-home --shell /bin/bash scanner
WORKDIR /app

COPY pyproject.toml setup.cfg requirements.txt README.md LICENSE ./
COPY vuln_scanner/ ./vuln_scanner/

RUN pip install --no-cache-dir .

USER scanner
ENTRYPOINT ["vuln-scanner"]
CMD ["/workspace"]
