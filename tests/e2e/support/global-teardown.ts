import { existsSync, readFileSync, rmSync } from 'node:fs';
import { USERS_FILE } from './env';
import { deleteUser } from './keycloak';

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(USERS_FILE)) return;
  const { users } = JSON.parse(readFileSync(USERS_FILE, 'utf8')) as { users: Record<string, { id: string }> };
  await new Promise((r) => setTimeout(r, 3000)); // let edge rate-limit buckets drain
  for (const u of Object.values(users)) await deleteUser(u.id).catch(() => undefined);
  rmSync(USERS_FILE, { force: true });
}
