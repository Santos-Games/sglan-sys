import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { DateTime } from 'luxon';

const prisma = new PrismaClient();

export async function loginUser(req: Request, res: Response) {
  const { email, password, ip, deviceName, macAddress } = req.body;
  try {
    const user = await prisma.user.findUnique({ where: { email } });

    // Auditoria: tentativa de login
    await prisma.auditLog.create({
      data: {
        userId: user?.id,
        action: 'login_attempt',
        details: `Tentativa de login para ${email}`,
        ip: ip || req.ip,
      },
    });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      await prisma.auditLog.create({
        data: {
          userId: user?.id,
          action: 'login_failed',
          details: `Falha de login para ${email}`,
          ip: ip || req.ip,
        },
      });
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    if (!user.canLogin) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'login_blocked',
          details: 'Usuário não autorizado a logar',
          ip: ip || req.ip,
        },
      });
      res.status(403).json({ error: 'User is not authorized to log in' });
      return;
    }

    // Impedir login se não houver saldo de horas ou dinheiro
    if (user.hoursBalance <= 0 && user.moneyBalance < 15) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'login_denied_no_balance',
          details: 'Usuário sem saldo de horas ou dinheiro',
          ip: ip || req.ip,
        },
      });
      res.status(403).json({ error: 'Insufficient balance or hours to login' });
      return;
    }

    // Impedir sessões simultâneas
    const activeSession = await prisma.session.findFirst({
      where: { userId: user.id, logoutAt: null },
    });
    if (activeSession) {
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          action: 'login_denied_active_session',
          details: 'Sessão já ativa',
          ip: ip || req.ip,
        },
      });
      res.status(403).json({ error: 'User already has an active session' });
      return;
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    const token = jwt.sign(
      { id: user.id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET || 'Susuki1249*',
      {
        expiresIn: user.jwtExpiration || '1h',
      }
    );

    const loginAt = DateTime.now().setZone('America/Sao_Paulo').toJSDate();

    const session = await prisma.session.create({
      data: {
        userId: user.id,
        loginAt,
        token,
        ip: ip || req.ip,
        deviceName,
        macAddress,
      },
    });

    await prisma.auditLog.create({
      data: {
        userId: user.id,
        action: 'login_success',
        details: `Login bem-sucedido para ${email}`,
        ip: ip || req.ip,
      },
    });

    res.json({ token, sessionId: session.id });
  } catch (error) {
    await prisma.auditLog.create({
      data: {
        action: 'login_error',
        details: `Erro no login: ${error}`,
        ip: req.body.ip || req.ip,
      },
    });
    res.status(500).json({ error: 'Failed to log in' });
  }
}

export const registerUser = async (req: Request, res: Response) => {
  try {
    const { name, email, password, isAdmin } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashedPassword,
        isAdmin: !!isAdmin,
      },
    });
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: 'Erro' });
  }
};

export const getUsers = async (req: Request, res: Response) => {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Error' });
  }
};

export async function getUserBalance(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ hoursBalance: user.hoursBalance, moneyBalance: user.moneyBalance });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar saldo' });
  }
}

export async function getUserHistory(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const sessions = await prisma.session.findMany({
      where: { userId: req.user.userId },
      orderBy: { loginAt: 'desc' }
    });
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar histórico' });
  }
}

export async function getUserPayments(req: Request, res: Response) {
  try {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const payments = await prisma.payment.findMany({
      where: { userId: req.user.userId },
      orderBy: { paidAt: 'desc' }
    });
    res.json(payments);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar pagamentos' });
  }
}

export async function getPendingSessions(req: Request, res: Response) {
  try {
    const sessions = await prisma.session.findMany({
      where: { paid: false },
      include: { user: true },
      orderBy: { loginAt: 'desc' }
    });
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar sessões pendentes' });
  }
}

export async function getUsageReport(req: Request, res: Response) {
  try {
    // Filtros podem ser passados por query params (exemplo: ?userId=1&start=2024-01-01&end=2024-01-31)
    const { userId, start, end } = req.query;
    const where: any = {};
    if (userId) where.userId = Number(userId);
    if (start || end) {
      where.loginAt = {};
      if (start) where.loginAt.gte = new Date(start as string);
      if (end) where.loginAt.lte = new Date(end as string);
    }
    const sessions = await prisma.session.findMany({
      where,
      include: { user: true },
      orderBy: { loginAt: 'desc' }
    });
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar relatório' });
  }
}

export async function paySession(req: Request, res: Response) {
  try {
    const sessionId = Number(req.params.id);
    const { amount, paymentMethod } = req.body;
    const session = await prisma.session.update({
      where: { id: sessionId },
      data: { paid: true }
    });
    await prisma.payment.create({
      data: {
        userId: session.userId,
        amount,
        paymentMethod,
        sessionId: session.id
      }
    });
    res.json({ message: 'Session marked as paid', session });
  } catch (error) {
    res.status(500).json({ error: 'Error' });
  }
}

export async function logoutUser(req: Request, res: Response): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ error: 'Unauthorized: user not found in request' });
      return;
    }
    const userId = req.user.userId;
    const { sessionId } = req.body || {};
    if (!sessionId) {
      res.status(400).json({ error: 'sessionId is required in request body' });
      return;
    }
    const session = await prisma.session.findFirst({
      where: {
        id: sessionId,
        userId: userId,
        logoutAt: null,
      },
    });
    if (!session) {
      res.status(404).json({ error: 'Session not found or already logged out' });
      return;
    }
    const logoutAt = DateTime.now().setZone('America/Sao_Paulo').toJSDate();
    const loginAt = DateTime.fromJSDate(session.loginAt).setZone('America/Sao_Paulo');
    const diffMs = DateTime.fromJSDate(logoutAt).diff(loginAt, 'hours').hours;
    const hours = Math.ceil(diffMs > 0 ? diffMs : 1);
    const amountDue = hours * 15;
    await prisma.session.update({
      where: { id: sessionId },
      data: { logoutAt: logoutAt, amountDue: amountDue, paid: false },
    });
    res.json({ message: 'Logout successful', hours, amountDue });
  } catch (error) {
    res.status(500).json({ error: 'Failed to logout' });
  }
}

export async function logoutAllSessions(req: Request, res: Response): Promise<void> {
  try {
    const now = DateTime.now().setZone('America/Sao_Paulo').toJSDate();
    const { count } = await prisma.session.updateMany({
      where: {
        logoutAt: null,
      },
      data: {
        logoutAt: now,
      },
    });
    res.json({ message: `Logout realizado em ${count} sessões.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to logout all sessions' });
  }
}

export async function authorizeUser(req: Request, res: Response): Promise<void> {
  const { id } = req.params;
  const { canLogin, jwtExpiration } = req.body;

  if (isNaN(Number(id))) {
    res.status(400).json({ error: 'Invalid user id' });
    return;
  }

  try {
    const user = await prisma.user.update({
      where: { id: Number(id) },
      data: {
        ...(canLogin !== undefined && { canLogin }),
        ...(jwtExpiration !== undefined && { jwtExpiration }),
      },
    });
    res.json({ message: 'User authorization updated successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user authorization', details: error });
  }
}
