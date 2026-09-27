# Build arguments provided by Docker Buildx and GoReleaser dockers_v2
ARG BUILDPLATFORM
ARG TARGETPLATFORM

# Pinned base image used only to extract CA certificates and timezone data
ARG BASE_IMAGE=alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Builder stage
FROM --platform=$BUILDPLATFORM ${BASE_IMAGE} AS builder
RUN apk add --no-cache ca-certificates tzdata

# Final minimal scratch image
FROM scratch

# Re-declare TARGETPLATFORM for this stage
ARG TARGETPLATFORM

# Copy supporting files from builder stage
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the Go binary (placed by GoReleaser under $TARGETPLATFORM/)
COPY --chmod=0755 ${TARGETPLATFORM}/agh-cli /agh-cli

# Run as a non-root user
USER 1000:1000

# Set the entrypoint
ENTRYPOINT ["/agh-cli"]
