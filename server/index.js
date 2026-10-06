// Process bootstrap: Fastify serves the UI (static) and the API from the same
// process. Listens on $PORT (Railway injects 8080) with a baked default.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import config from './config.js';
import db from './db.js';
import registerRoutes from './routes.js';
import scheduler from './scheduler.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const publicDir = path.join(__dirname, '..', 'public');

const app = Fastify({
  logger: { level: 'info' },
  disableRequestLogging: true
});

await app.register(fastifyStatic, { root: publicDir });
registerRoutes(app);

const start = async () => {
  scheduler.start();
  await app.listen({ port: config.port, host: '0.0.0.0' });
};

for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    app.log.info({ msg: 'shutting_down', signal: sig });
    scheduler.stop();
    app
      .close()
      .catch(() => {})
      .finally(() => {
        db.raw.close();
        process.exit(0);
      });
  });
}

start().catch((err) => {
  app.log.error(err);
  process.exit(1);
});
