FROM debian:latest

ENV RUST_BACKTRACE="1"

# install libcrypto
RUN set -eux; \
  apt-get update; \
  apt-get -y install libssl-dev; \
  rm -rf /var/lib/apt/lists/*; \
  apt-get clean; \
  rm -rf /tmp/*; \
  echo done;

# copy runner
ARG driver="target/release/netbench"
COPY ${driver} /usr/bin/netbench-driver
RUN set -eux; \
  chmod +x /usr/bin/netbench-driver; \
  ldd /usr/bin/netbench-driver; \
  # ensure the binary works \
  netbench-driver --help; \
  echo done

ARG library="s2n-quic"
ARG endpoint="server"
ENTRYPOINT [ "/usr/bin/netbench-driver", "${library}", "${endpoint}" ]