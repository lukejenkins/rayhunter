# The binary is built outside (see ../build.sh) and only copied in here.
ARG BUILD_FROM=ghcr.io/home-assistant/aarch64-base
FROM ${BUILD_FROM}
COPY m2100-archive /usr/local/bin/m2100-archive
# The decoder guest; the binary refuses it unless its sha256 matches the build (src/sandbox.rs).
COPY m2100-decoder.wasm /usr/local/share/m2100-archive/m2100-decoder.wasm
ENV RUST_LOG=info
# s6-overlay (the base image's init) hides the container environment, incl.
# SUPERVISOR_TOKEN, unless the program runs under with-contenv (found on the Yellow).
CMD ["/usr/bin/with-contenv", "/usr/local/bin/m2100-archive"]
