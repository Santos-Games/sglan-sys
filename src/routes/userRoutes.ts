import { Router, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import {
  loginUser,
  registerUser,
  getUsers,
  logoutUser,
  getUserBalance,
  getUserHistory,
  getUserPayments,
  getUsageReport,
  getPendingSessions,
  paySession
} from '../controllers/userController';
import { authenticate, authorizeAdmin } from '../middlewares/authMiddleware';
import bcrypt from 'bcrypt';
import { DateTime } from 'luxon';

const prisma = new PrismaClient();
const router = Router();

router.post('/login', loginUser);
router.post('/logout', authenticate, logoutUser);

// Consulta saldo/horas disponíveis
router.get('/balance', authenticate, (req, res) => { getUserBalance(req, res); });

// Histórico de uso e pagamentos do usuário autenticado
router.get('/history', authenticate, (req, res) => { getUserHistory(req, res); });
router.get('/payments', authenticate, (req, res) => { getUserPayments(req, res); });

export default router;
