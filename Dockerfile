# mcp-turnstile — tiny image, zero runtime dependencies.
# Build:  docker build -t mcp-turnstile .
# Run  :  docker run --rm mcp-turnstile scan --http https://example.com/mcp --fail-on high
#         docker run --rm mcp-turnstile --version
#
# Note: scanning a --stdio server means that server's command must exist INSIDE
# the container; the image ships Python + node/npx so `npx -y <mcp-server>` works
# out of the box, and remote --http scans need nothing extra.
FROM python:3.12-slim

# node + npx so `scan --stdio -- npx -y @modelcontextprotocol/server-…` works
RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# drop to a non-root user
RUN useradd -m runner
USER runner

ENTRYPOINT ["mcpturn"]
CMD ["--help"]
