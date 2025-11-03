FROM python:3.12.2-slim-bookworm
MAINTAINER noone@example.com

RUN mkdir /tmp/src/
COPY pyproject.toml /tmp/src/
COPY src /tmp/src/
ENV VIRTUAL_ENV=/usr/local
RUN pip install /tmp/src
ENTRYPOINT ["/usr/local/bin/network-exporter"]
EXPOSE 8080
