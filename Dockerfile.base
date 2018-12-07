FROM fpco/pid1

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
  ca-certificates \
  libgmp-dev \
  netbase

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

