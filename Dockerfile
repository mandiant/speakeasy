FROM python:3.13-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc-dev git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN git submodule update --init deps/win32json deps/phnt \
    || true
RUN pip install --no-cache-dir build \
    && python -m build --wheel \
    && pip install --no-cache-dir dist/*.whl

FROM python:3.13-slim

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
RUN mkdir /sandbox && chown appuser:appgroup /sandbox

COPY --from=builder /usr/local/lib/python3.13/site-packages/ /usr/local/lib/python3.13/site-packages/
COPY --from=builder /usr/local/bin/speakeasy /usr/local/bin/speakeasy

USER appuser
WORKDIR /sandbox
ENTRYPOINT ["speakeasy"]
