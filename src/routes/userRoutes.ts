import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { loginUser, registerUser, getUsers } from '../controllers/userController';
import { authenticate, authorizeAdmin } from '../middlewares/authMiddleware';
import bcrypt from 'bcrypt';
import { DateTime } from 'luxon'; // Adicione luxon

const prisma = new PrismaClient();
const router = Router();

router.post('/login', async (req: Request, res: Response) => {
  const { email, password, ip, deviceName, macAddress } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });

    console.log('Login attempt:', { email, password, user, ip, deviceName, macAddress });

    if (!user || !(await bcrypt.compare(password, user.password))) {
       res.status(401).json({ error: 'Invalid credentials' });
       return;
    }

    if (!user.canLogin) {
      res.status(403).json({ error: 'User is not authorized to log in' });
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

    // Use timezone de São Paulo
    const loginAt = DateTime.now().setZone('America/Sao_Paulo').toJSDate();

    // Crie uma sessão de login com os novos campos
    const session = await prisma.session.create({
      data: {
        userId: user.id,
        loginAt: loginAt,
        token: token,
        ip: ip || req.ip,
        deviceName,
        macAddress,
      },
    });

    res.json({ token, sessionId: session.id });

  } catch (error) {
    res.status(500).json({ error: 'Failed to log in' });
  }
});

router.post('/register', authenticate, authorizeAdmin, registerUser);
router.get('/users', authenticate, authorizeAdmin, getUsers);
router.post('/logout', authenticate, async (req: Request, res: Response) => {
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

  try {
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

    // Use timezone de São Paulo
    const logoutAt = DateTime.now().setZone('America/Sao_Paulo').toJSDate();

    // Calcule o tempo em horas (arredondando para cima)
    const loginAt = DateTime.fromJSDate(session.loginAt).setZone('America/Sao_Paulo');
    const diffMs = DateTime.fromJSDate(logoutAt).diff(loginAt, 'hours').hours;
    const hours = Math.ceil(diffMs > 0 ? diffMs : 1); // mínimo 1 hora
    const amountDue = hours * 15;

    await prisma.session.update({
      where: { id: sessionId },
      data: { logoutAt: logoutAt, amountDue: amountDue, paid: false },
    });

    res.json({ message: 'Logout successful', hours, amountDue });
  } catch (error) {
    res.status(500).json({ error: 'Failed to logout' });
  }
});

// Rota para consultar todas as sessões de um usuário (admin pode ver todas)
router.get('/sessions', authenticate, async (req: Request, res: Response) => {
  if (!req.user) {
    res.status(401).json({ error: 'Unauthorized: user not found in request' });
    return;
  }
  try {
    let sessions;
    if (req.user.isAdmin) {
      sessions = await prisma.session.findMany({ include: { user: true } });
    } else {
      sessions = await prisma.session.findMany({
        where: { userId: req.user.userId },
        include: { user: true },
      });
    }
    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Rota para marcar uma sessão como paga
router.post('/sessions/:id/pay', authenticate, authorizeAdmin, async (req: Request, res: Response) => {
  const sessionId = Number(req.params.id);
  try {
    const session = await prisma.session.update({
      where: { id: sessionId },
      data: { paid: true },
    });
    res.json({ message: 'Session marked as paid', session });
  } catch (error) {
    res.status(500).json({ error: 'Failed to mark session as paid' });
  }
});

export default router;
