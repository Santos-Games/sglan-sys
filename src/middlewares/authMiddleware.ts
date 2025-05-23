import { Request, Response, NextFunction } from 'express';
import * as jwt from 'jsonwebtoken';

declare global {
  namespace Express {
    interface Request {
      user?: { userId: number; isAdmin: boolean };
    }
  }
}

const secret = process.env.JWT_SECRET || 'Susuki1249*';

export const authenticate = (req: Request, res: Response, next: NextFunction): void => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    res.status(401).json({ error: 'Token not provided' });
    return;
  }

  try {
    const decoded = jwt.verify(token, secret) as { userId: number; isAdmin: boolean };
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};

export const authorizeAdmin = (req: Request, res: Response, next: NextFunction): void => {
  if (!req.user?.isAdmin) {
    res.status(403).json({ error: 'Access denied' });
    return;
  }
  next();
};
