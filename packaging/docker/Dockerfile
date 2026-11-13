ARG RUNTIME_IMAGE
FROM ${RUNTIME_IMAGE}
COPY --chmod=0555 syncd /usr/local/bin/syncd
COPY --chmod=0555 entrypoint.sh /usr/local/bin/sync-extend-entrypoint
USER 65532:65532
WORKDIR /state
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/sync-extend-entrypoint"]
