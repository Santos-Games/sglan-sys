import { PrismaClient } from '@prisma/client';
import { DateTime } from 'luxon';

const prisma = new PrismaClient();

export async function monitorSessions() {
  // Garanta que o horário de São Paulo está sendo usado em toda a aplicação
  const now = DateTime.now().setZone('America/Sao_Paulo');
  const timeoutSeconds = 20;

  const sessions = await prisma.session.findMany({
    where: {
      logoutAt: null,
      OR: [
        // Sessões sem heartbeat nunca enviado (lastHeartbeat é null)
        { lastHeartbeat: null, loginAt: { lt: now.minus({ seconds: timeoutSeconds }).toJSDate() } },
        // Sessões com heartbeat, mas atrasado
        { lastHeartbeat: { lt: now.minus({ seconds: timeoutSeconds }).toJSDate() } }
      ]
    }
  });

  for (const session of sessions) {
    // Converta loginAt e lastHeartbeat para o timezone de São Paulo para comparação correta
    const loginAt = DateTime.fromJSDate(session.loginAt, { zone: 'utc' }).setZone('America/Sao_Paulo');
    const lastHeartbeat = session.lastHeartbeat
      ? DateTime.fromJSDate(session.lastHeartbeat, { zone: 'utc' }).setZone('America/Sao_Paulo')
      : null;

    const shouldLogout =
      (lastHeartbeat == null && loginAt < now.minus({ seconds: timeoutSeconds })) ||
      (lastHeartbeat != null && lastHeartbeat < now.minus({ seconds: timeoutSeconds }));

    if (shouldLogout) {
      await prisma.session.update({
        where: { id: session.id },
        data: { logoutAt: now.toJSDate() }
      });
      await prisma.auditLog.create({
        data: {
          userId: session.userId,
          action: 'auto_logout',
          details: 'Desconectado por falta de heartbeat. Verifique a conexão com a internet.',
          createdAt: now.toJSDate()
        }
      });
    }
  }
}
