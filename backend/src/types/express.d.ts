import type { Role } from '@prisma/client';

export interface AuthContext {
  userId: string;
  sessionId: string;
  name: string;
  roles: Role[];
  /** Access token expiry (epoch seconds) */
  exp: number;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: AuthContext;
    }
  }
}
