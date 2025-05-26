import express from 'express';
import { authenticate, authorizeAdmin } from '../middlewares/authMiddleware';
import {
  registerUser,
  getUsers,
  getUsageReport,
  getPendingSessions,
  paySession,
  logoutAllSessions,
  authorizeUser,
  setNegativeHoursLimit
} from '../controllers/userController';

const router = express.Router();

router.put('/user/:id/authorize', authenticate, authorizeAdmin, authorizeUser);
router.post('/register', authenticate, authorizeAdmin, registerUser);
router.get('/users', authenticate, authorizeAdmin, getUsers);
router.get('/report/usage', authenticate, authorizeAdmin, (req, res) => { getUsageReport(req, res); });
router.get('/report/pending', authenticate, authorizeAdmin, (req, res) => { getPendingSessions(req, res); });
router.post('/sessions/:id/pay', authenticate, authorizeAdmin, (req, res) => { paySession(req, res); });
router.post('/logout-all', authenticate, authorizeAdmin, logoutAllSessions);
router.put('/user/:id/negative-hours-limit', authenticate, authorizeAdmin, setNegativeHoursLimit);

export default router;