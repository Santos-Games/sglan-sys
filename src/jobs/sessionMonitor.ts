import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function monitorSessions() {
  const now = new Date();
  const timeoutSeconds = 20;

  const sessions = await prisma.session.findMany({
    where: {
      logoutAt: null,
      OR: [
        { lastHeartbeat: null, loginAt: { lt: new Date(now.getTime() - timeoutSeconds * 1000) } },
        { lastHeartbeat: { lt: new Date(now.getTime() - timeoutSeconds * 1000) } }
      ]
    }
  });

  for (const session of sessions) {
    const loginAt = new Date(session.loginAt);
    const lastHeartbeat = session.lastHeartbeat ? new Date(session.lastHeartbeat) : null;

    const shouldLogout =
      (lastHeartbeat == null && loginAt < new Date(now.getTime() - timeoutSeconds * 1000)) ||
      (lastHeartbeat != null && lastHeartbeat < new Date(now.getTime() - timeoutSeconds * 1000));

    if (shouldLogout) {
      await prisma.session.update({
        where: { id: session.id },
        data: { logoutAt: now }
      });
      await prisma.auditLog.create({
        data: {
          userId: session.userId,
          action: 'auto_logout',
          details: 'Desconectado por falta de heartbeat. Verifique a conexão com a internet.',
          createdAt: now
        }
      });
    }
  }
}
