# Recurse Gateway — Audit Console runtime container.
#
# Multi-stage debian build. Build stage uses
# `hexpm/elixir:1.19.5-erlang-28.5-debian-bookworm-20260421` which is
# the SAME image build:release uses on the self-hosted runner; the
# runtime stage is `debian:bookworm-slim`. Both bookworm → glibc ABI
# matches, so the BEAM's crypto.so links cleanly against the runtime
# stage's apt-installed libssl3 with no support/openssl/lib/ bundling
# step.
#
# Cache strategy — plain layer cache, so the file builds under the legacy
# builder as well as BuildKit (`docker compose build` on a machine with
# no buildx; spec 012 S7). Layers are content-addressed:
#   1. apt + node + rust toolchain (changes only on tool bumps)
#   2. mix deps.compile        (invalidates on mix.lock or per-app mix.exs)
#   3. SPA build (pnpm)        (invalidates on ui/ or pnpm-lock.yaml)
#   4. mix compile + release   (invalidates on apps/, native/, config/)
#
# The `RUN --mount=type=cache` slots that used to keep cargo target dirs,
# the hex cache and the pnpm store warm between builds were removed: they
# need BuildKit, and a stranger's Docker without it died at the first one.
# CI may re-add registry-backed caching (`--cache-from`/`--cache-to`) on
# its own build command; nothing in this file depends on it.
#
# Replaced the prior single-stage "consume build:release artifact"
# Dockerfile (!126) and made the parallel build:release:amd64 job
# (!138 + !140) obsolete. The original arm64 build:release on the
# self-hosted Graviton stays alive for the EC2 deploy:audit-dev path
# until VM retirement post-EKS proof-out.

# ---------------------------------------------------------------------- #
# Build stage
# ---------------------------------------------------------------------- #
FROM hexpm/elixir:1.19.5-erlang-28.5-debian-bookworm-20260421 AS build

ENV MIX_ENV=prod \
    LANG=C.UTF-8 \
    DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

# System deps. Pinned to the apt repo's current state; bumped manually
# when we need a newer libssl / build-essential.
RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential curl git pkg-config libssl-dev zstd ca-certificates \
        gnupg && \
    rm -rf /var/lib/apt/lists/*

# Node.js 20 + pnpm. Same versions as build:release (.gitlab-ci.yml).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    corepack enable && \
    corepack prepare pnpm@9.15.0 --activate && \
    node --version && pnpm --version

# Rust toolchain — pinned via .tool-versions (same as build:release).
COPY .tool-versions ./.tool-versions
RUN RUST_VERSION=$(grep '^rust' .tool-versions | awk '{print $2}') && \
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | \
        sh -s -- --default-toolchain "$RUST_VERSION" --profile minimal -y && \
    rustc --version && cargo --version

WORKDIR /src

RUN mix local.hex --force && mix local.rebar --force

# ---------------------------------------------------------------------- #
# Layer: mix dependencies. Invalidates only on mix.lock or per-app
# mix.exs change, so nine-out-of-ten code edits hit cache here.
# ---------------------------------------------------------------------- #
COPY mix.exs mix.lock ./
COPY apps/recurse_shared/mix.exs      apps/recurse_shared/mix.exs
COPY apps/recurse_providers/mix.exs   apps/recurse_providers/mix.exs
COPY apps/recurse_gateway/mix.exs     apps/recurse_gateway/mix.exs
COPY apps/recurse_runtime/mix.exs     apps/recurse_runtime/mix.exs
COPY apps/recurse_integration/mix.exs apps/recurse_integration/mix.exs
COPY apps/recurse_broker/mix.exs      apps/recurse_broker/mix.exs
COPY apps/recurse_provenance/mix.exs  apps/recurse_provenance/mix.exs
# The Core verifier library is a path dependency inside the repository.
COPY vendor ./vendor

RUN mix deps.get --only prod && \
    mix deps.compile

# ---------------------------------------------------------------------- #
# Layer: SPA. Invalidates only on ui/ source change.
#
# `mkdir -p apps/recurse_gateway/priv/static` runs BEFORE sync-to-priv
# because the apps/ tree hasn't been COPYed at this layer (that's the
# next layer for cache hit-rate reasons). sync-to-priv's `cp -r dist
# ../apps/recurse_gateway/priv/static/admin` requires the parent path
# to exist.
# ---------------------------------------------------------------------- #
COPY ui ./ui
RUN mkdir -p apps/recurse_gateway/priv/static && \
    cd ui && \
    pnpm install --frozen-lockfile && \
    pnpm run build && \
    pnpm run sync-to-priv && \
    test -f ../apps/recurse_gateway/priv/static/admin/index.html

# ---------------------------------------------------------------------- #
# Layer: native NIFs + Elixir compile + release. Invalidates on app or
# NIF source change; the cedar + spiffe crates compile from scratch in
# this layer (no BuildKit cache mounts, see the header).
# ---------------------------------------------------------------------- #
COPY native ./native
COPY config ./config
COPY apps ./apps

RUN mix compile && \
    mix release --overwrite audit_console && \
    cp -r _build/prod/rel/audit_console /opt/release

# Fail-fast architecture assertion, arch-agnostic (spec 012 D7). ELF
# bytes 18-19 = e_machine (little-endian): 0x003e = amd64, 0x00b7 =
# arm64. BuildKit populates TARGETARCH from `--platform`; the legacy
# builder leaves it unset and `uname -m` stands in. Either way the image
# builds natively on Apple Silicon AND under `--platform linux/amd64`, and
# still refuses to ship an ERTS that does not match the manifest it will
# be tagged with.
ARG TARGETARCH
RUN ERLEXEC=$(find /opt/release/erts-*/bin -name erlexec -type f | head -1) && \
    [ -n "$ERLEXEC" ] || { echo "FATAL: erlexec not found in /opt/release" >&2; exit 1; } && \
    MACHINE=$(od -An -t x1 -N 2 -j 18 "$ERLEXEC" | tr -d ' ') && \
    case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) EXPECTED=3e00 ;; \
        arm64|aarch64) EXPECTED=b700 ;; \
        *) echo "FATAL: unsupported TARGETARCH '${TARGETARCH:-$(uname -m)}'" >&2; exit 1 ;; \
    esac && \
    if [ "$MACHINE" = "$EXPECTED" ]; then \
        echo "[assert] OK: ERTS matches build platform ${TARGETARCH:-$(uname -m)} (ELF e_machine=$MACHINE at $ERLEXEC)"; \
    else \
        echo "FATAL: ERTS architecture mismatch — expected $EXPECTED for ${TARGETARCH:-$(uname -m)}, got $MACHINE for $ERLEXEC" >&2; \
        exit 1; \
    fi

# Belt-and-suspenders SPA + NIF presence asserts (same shape as
# build:release's release-tarball checks; we run them on the staged
# release dir directly here).
RUN test -f /opt/release/lib/recurse_gateway-*/priv/static/admin/index.html || \
        { echo "FATAL: SPA missing from staged release" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_gateway-*/priv/static/admin/vs/loader.js || \
        { echo "FATAL: Monaco bundle (vs/loader.js) missing — Policy Simulator will hang" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_shared-*/priv/native/recurse_cedar.so || \
        { echo "FATAL: cedar NIF missing from staged release" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_shared-*/priv/native/recurse_spiffe.so || \
        { echo "FATAL: spiffe NIF missing from staged release" >&2; exit 1; } && \
    test -f /opt/release/lib/recurse_gateway-*/priv/cedar/schema.cedarschema.json || \
        { echo "FATAL: Cedar entity schema missing from staged release" >&2; exit 1; } && \
    echo "[assert] OK: SPA + Monaco + NIFs + Cedar schema present in staged release"

# Stable, version-independent path for the Cedar entity schema so
# RECURSE_POLICY_SCHEMA_PATH does not have to encode the
# `recurse_gateway-<version>` lib directory name.
RUN mkdir -p /opt/release/etc/cedar && \
    cp /opt/release/lib/recurse_gateway-*/priv/cedar/schema.cedarschema.json \
       /opt/release/etc/cedar/schema.cedarschema.json

# ---------------------------------------------------------------------- #
# Runtime stage — debian:bookworm-slim. ABI matches the build stage.
# No support/openssl/lib/ bundling: the BEAM's crypto.so was linked
# against this same libssl3 / libcrypto3 that we apt-install here.
# ---------------------------------------------------------------------- #
FROM debian:bookworm-slim AS runtime

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        openssl libstdc++6 libgcc-s1 ca-certificates curl bash && \
    rm -rf /var/lib/apt/lists/*

# Non-root runtime user (spec 012 §13 container hardening). uid/gid 1000
# so a single-user host's bind mounts line up. `/secrets`, `/data/cas`
# and `/policy` are created here, owned by that user, so the named
# volumes compose mounts there inherit the ownership on first creation
# and the entrypoint can write first-boot key material (and the policy
# volume's seed link, spec 012 S5) without root.
RUN groupadd --gid 1000 recurse && \
    useradd --uid 1000 --gid recurse --home-dir /app --no-create-home \
            --shell /usr/sbin/nologin recurse && \
    mkdir -p /secrets /data/cas /policy && \
    chown recurse:recurse /secrets /data/cas /policy && \
    chmod 700 /secrets

WORKDIR /app

COPY --from=build --chown=recurse:recurse /opt/release/ ./
COPY --chown=recurse:recurse docker-compose/gateway-entrypoint.sh /app/bin/entrypoint.sh
RUN chmod +x /app/bin/entrypoint.sh

# Baked Cedar entity schema (copied to a version-independent path in the
# build stage). Operators supply the policy bundle; the schema ships with
# the image because it is part of the gateway's contract, not policy.
#
# RELEASE_TMP: the release script writes its runtime sys.config under
# this dir; pointing it at /tmp lets the root filesystem be mounted
# read-only (compose: `read_only: true` + tmpfs /tmp). Crash dumps go
# there too.
ENV HOME=/app \
    LANG=C.UTF-8 \
    RECURSE_POLICY_SCHEMA_PATH=/app/etc/cedar/schema.cedarschema.json \
    RELEASE_TMP=/tmp \
    ERL_CRASH_DUMP=/tmp/erl_crash.dump

USER recurse

# 4000 = audit plane (dashboard + API); 4443 = LLM proxy listener.
EXPOSE 4000 4443

# The entrypoint generates first-boot secrets + runs migrations, then
# exec's `bin/audit_console <cmd>` (spec 012 S1). Override CMD for
# `eval` / `remote` / `rpc` — the entrypoint passes arguments through.
ENTRYPOINT ["/app/bin/entrypoint.sh"]
CMD ["start"]
