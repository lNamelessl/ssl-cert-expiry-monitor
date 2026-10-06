# syntax=docker/dockerfile:1
# ---- deps stage: install production deps and prove the native prebuild works ----
FROM node:22-bookworm-slim AS deps
WORKDIR /app
ENV NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
COPY package.json package-lock.json ./
# --ignore-scripts: better-sqlite3 v13 bundles its native prebuilds in the
# tarball (prebuilds/linux-x64.node) and needs NO install step, but npm's
# default auto-gyp (binding.gyp present, no install script) would demand
# Python. Skipped scripts are safe: all deps are pure JS except better-sqlite3,
# whose prebuild the require-smoke-test below proves loadable.
RUN npm ci --omit=dev --ignore-scripts
# Fail the BUILD (not the runtime) if the bundled better-sqlite3 prebuild
# does not match this Node ABI. better-sqlite3 v13 ships prebuilds inside the
# npm tarball (prebuildify) so this needs no compiler and no network.
RUN node -e "const db=require('better-sqlite3')(':memory:');db.exec('create table t(x)');db.prepare('insert into t values (?)').run(1);if(db.prepare('select x from t').get().x!==1)throw new Error('sqlite broken');console.log('better-sqlite3 prebuild OK')"

# ---- runtime stage: non-root app user, root-owned /data handled at boot ----
FROM node:22-bookworm-slim
ENV NODE_ENV=production DATA_DIR=/data PORT=8080
RUN apt-get update \
 && apt-get install -y --no-install-recommends gosu \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 app \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin app \
 && mkdir -p /data && chown app:app /data
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY server ./server
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Root wrapper: chown the (possibly root-owned) volume, then drop privileges.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "server/index.js"]
