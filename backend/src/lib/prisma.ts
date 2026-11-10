/**
 * Prisma client. All queries are parameterised by the ORM; raw SQL is only used through
 * tagged templates ($queryRaw`...`), which are also parameterised.
 *
 * Multi-cluster support: when DATABASE_REPLICA_URLS is set (comma separated), read
 * queries are routed to replicas and writes/transactions go to the primary.
 */
import { PrismaClient } from '@prisma/client';
import { readReplicas } from '@prisma/extension-read-replicas';
import { env } from '../config/env.js';

const replicaUrls = env.DATABASE_REPLICA_URLS.split(',')
  .map((u) => u.trim())
  .filter(Boolean);

const base = new PrismaClient({
  datasourceUrl: env.DATABASE_URL,
  log: env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error'],
});

export const prisma = (
  replicaUrls.length > 0 ? base.$extends(readReplicas({ url: replicaUrls })) : base
) as unknown as PrismaClient;

export type Tx = Omit<
  PrismaClient,
  '$connect' | '$disconnect' | '$on' | '$transaction' | '$use' | '$extends'
>;

export const replicaCount = replicaUrls.length;
