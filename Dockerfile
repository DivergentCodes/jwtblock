FROM golang:alpine AS builder
# Where to find the local built jwtblock binary.
ARG SRC_BIN_DIR="."
# Create an unprivileged user.
RUN adduser --system --no-create-home app
# Create an unprivileged runtime location with the binary.
RUN mkdir /app
# Copy the Golang binary.
COPY ${SRC_BIN_DIR}/jwtblock /app/jwtblock
RUN chown -R app /app


FROM scratch
# Retain important files.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /app /app
# Run as the unprivileged user.
USER app

ENTRYPOINT ["/app/jwtblock"]
CMD ["serve"]
