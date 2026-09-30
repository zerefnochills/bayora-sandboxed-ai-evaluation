FROM python:3.12-slim
RUN useradd -u 10001 -m anchor && mkdir /anchor-data && chown anchor /anchor-data
COPY anchor_service.py /app/anchor_service.py
USER anchor
WORKDIR /app
CMD ["python", "-u", "anchor_service.py"]
