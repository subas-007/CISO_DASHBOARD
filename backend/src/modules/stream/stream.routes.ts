/**
 * Server-Sent Events stream for real-time dashboard updates. The connection is
 * terminated when the caller's access token expires, forcing re-authentication
 * (continuous verification for long-lived connections).
 */
import { Router } from 'express';
import { requirePermission } from '../../auth/middleware.js';
import { HttpError } from '../../lib/errors.js';
import { subscribe } from '../../lib/events.js';

export const streamRouter = Router();

const MAX_STREAMS_PER_USER = 5;
const perUser = new Map<string, number>();

streamRouter.get('/', requirePermission('dashboard:read'), (req, res) => {
  const auth = req.auth!;
  const current = perUser.get(auth.userId) ?? 0;
  if (current >= MAX_STREAMS_PER_USER) throw new HttpError(429, 'TOO_MANY_STREAMS', 'Too many open streams');
  perUser.set(auth.userId, current + 1);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-store',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.write('retry: 5000\n\n');
  res.write(`event: ready\ndata: {}\n\n`);

  const unsubscribe = subscribe((e) => {
    res.write(`event: ${e.type}\ndata: ${JSON.stringify(e.data ?? {})}\n\n`);
  });
  const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
  const ttl = Math.max(1_000, auth.exp * 1000 - Date.now());
  const expiry = setTimeout(() => {
    res.write('event: reauth\ndata: {}\n\n');
    res.end();
  }, ttl);

  req.on('close', () => {
    unsubscribe();
    clearInterval(ping);
    clearTimeout(expiry);
    const n = (perUser.get(auth.userId) ?? 1) - 1;
    if (n <= 0) perUser.delete(auth.userId);
    else perUser.set(auth.userId, n);
  });
});
