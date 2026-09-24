# ISODE's FTAM responder (tsapd -> ftamd over RFC 1006), as an independent
# peer for TELEXFER interoperability tests.
#
# Source: the maintained Wildboar Software fork of ISODE 8.0, pinned to a
# known commit so an upstream change cannot silently alter the tests.
FROM ubuntu:24.04

ARG ISODE_REPO=https://github.com/Wildboar-Software/isode.git
ARG ISODE_COMMIT=0f29f178e30ede69cdb1f4da5db717e192c7e23e

# retries: Ubuntu mirrors are occasionally caught mid-sync
RUN for i in 1 2 3; do apt-get -o Acquire::Retries=3 update && break; sleep 10; done \
 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
      build-essential git bison flex ca-certificates openssl iproute2 \
 && rm -rf /var/lib/apt/lists/*

RUN git clone "$ISODE_REPO" /isode \
 && cd /isode \
 && git checkout -q "$ISODE_COMMIT"

WORKDIR /isode
# Upstream 43aaabae ("get gnu23 building") left ssapd declared as a function
# pointer while tsapd.c defines it as a function, so tsapd no longer
# compiles unless NOGOSIP is set.  Restore the prototypes (the NOGOSIP
# declarations end in "= NULL;" and are not touched).
RUN sed -i -E 's/^([[:space:]]*)static int \(\*ssapd\)\((.*)\);$/\1static int ssapd(\2);/' \
        support/tsapd.c \
 && grep -c 'static int ssapd(' support/tsapd.c | grep -qx 2

# the fork's documented "green" build: linux.h + linux.make (not linux-dev)
RUN cp config/linux.h h/config.h \
 && cp config/linux.make config/CONFIG.make \
 && cp config/*.local support/ \
 && ./make everything \
 && (./make inst-everything || true) \
 && test -x /usr/local/sbin/tsapd && test -x /usr/local/sbin/iso.ftam

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 10102
ENTRYPOINT ["/entrypoint.sh"]
