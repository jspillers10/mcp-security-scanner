FROM python:3.13-alpine@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d

ENV HOME=/tmp
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --requirement requirements.txt

RUN addgroup -S -g 10001 labgroup \
    && adduser -S -D -H -u 10001 -G labgroup labuser

COPY --chown=labuser:labgroup server.py client.py ./

USER 10001:10001

CMD ["python", "client.py"]