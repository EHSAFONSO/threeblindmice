# Imagem do tbm. Para escanear a sua LAN, use a rede do host:
#   docker build -t tbm .
#   docker run --rm --network host -v tbm-data:/data tbm scan 192.168.0.0/24 --label casa
# Imagem base fixada por digest (tag + digest): a tag sozinha pode apontar para outra imagem amanhã.
FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TBM_HOME=/data \
    PIP_CONFIG_FILE=/app/requirements/pip.conf

WORKDIR /app
COPY requirements ./requirements
# Dependências travadas (versões exatas + hash, só wheels, 3+ dias): ver requirements/pip.conf.
# O pip da imagem pode ser antigo para a política; o bootstrap instala o pip travado antes.
RUN PIP_CONFIG_FILE=/dev/null pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps \
        -r requirements/bootstrap.txt \
    && pip install --no-cache-dir --require-hashes --no-build-isolation -r requirements/runtime.txt
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps --no-build-isolation . \
    && useradd --create-home --uid 10001 tbm \
    && mkdir -p /data && chown tbm /data

USER tbm
VOLUME ["/data"]
ENTRYPOINT ["tbm"]
CMD ["--help"]
