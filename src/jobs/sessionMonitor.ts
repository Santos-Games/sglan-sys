import { PrismaClient } from '@prisma/client';
import { DateTime } from 'luxon';

const prisma = new PrismaClient();

export async function monitorSessions() {
  // Use sempre o timezone de São Paulo
  const now = DateTime.now().setZone('America/Sao_Paulo');
  const timeoutSeconds = 20; // tolerância de atraso do heartbeat
  const sessions = await prisma.session.findMany({
    where: {
      logoutAt: null,
      lastHeartbeat: {
        lt: now.minus({ seconds: timeoutSeconds }).toJSDate()
      }
    }
  });

  for (const session of sessions) {
    await prisma.session.update({
      where: { id: session.id },
      data: { logoutAt: now.toJSDate() }
    });
    await prisma.auditLog.create({
      data: {
        userId: session.userId,
        action: 'auto_logout',
        details: 'Desconectado por falta de heartbeat',
        createdAt: now.toJSDate()
      }
    });
  }
}
