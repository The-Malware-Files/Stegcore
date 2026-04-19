# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM rust:1.88-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libwayland-dev \
    libgtk-3-dev \
    libglib2.0-dev \
    libjavascriptcoregtk-4.1-dev \
    libwebkit2gtk-4.1-dev \
    libayatana-appindicator3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependencies separately from source
COPY Cargo.toml Cargo.lock ./
COPY crates/engine/Cargo.toml crates/engine/Cargo.toml
COPY crates/core/Cargo.toml   crates/core/Cargo.toml
COPY crates/cli/Cargo.toml    crates/cli/Cargo.toml

# Stub src-tauri so workspace Cargo.toml resolves (not built in Docker)
COPY src-tauri/Cargo.toml src-tauri/Cargo.toml
RUN mkdir -p src-tauri/src \
    && echo 'fn main() {}' > src-tauri/src/main.rs \
    && echo '' > src-tauri/src/lib.rs \
    && echo 'fn main() {}' > src-tauri/build.rs

# Stub source files so cargo can fetch deps without full source
RUN mkdir -p crates/engine/src crates/core/src crates/cli/src \
    && echo 'pub fn placeholder() {}' > crates/engine/src/lib.rs \
    && echo 'pub fn placeholder() {}' > crates/core/src/lib.rs \
    && echo 'fn main() {}' > crates/cli/src/main.rs

# Fetch and cache all dependencies
RUN cargo fetch

# Copy real source
COPY crates/ crates/

# Build CLI binary only (no Tauri, no frontend)
RUN cargo build --release -p stegcore-cli

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -u 1000 stegcore
USER stegcore
WORKDIR /home/stegcore

COPY --from=builder /app/target/release/stegcore /usr/local/bin/stegcore

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=1 \
    CMD stegcore --version || exit 1

ENTRYPOINT ["stegcore"]
