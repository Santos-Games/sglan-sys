import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import {
  loginUser,
  logoutUser,
  getUserBalance,
  getUserHistory,
  getUserPayments
} from '../controllers/userController';
import { authenticate } from '../middlewares/authMiddleware';


const prisma = new PrismaClient();
const router = Router();

router.post('/login', loginUser);
router.post('/logout', authenticate, logoutUser);


router.get('/balance', authenticate, (req, res) => { getUserBalance(req, res); });


router.get('/history', authenticate, (req, res) => { getUserHistory(req, res); });
router.get('/payments', authenticate, (req, res) => { getUserPayments(req, res); });
router.post('/heartbeat', authenticate, async (req: Request, res: Response): Promise<void> => {
  const { sessionId } = req.body;
  if (!sessionId) {
    res.status(400).json({ error: 'sessionId is required' });
    return;
  }
  await prisma.session.update({
    where: { id: sessionId },
    data: { lastHeartbeat: new Date() }
  });
  res.json({ ok: true });
});

export default router;
