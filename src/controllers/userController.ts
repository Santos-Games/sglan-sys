import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { login, register } from '../services/authService';

const prisma = new PrismaClient();

export const loginUser = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const result = await login(email, password);
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: 'Erro' });
  }
};

export const registerUser = async (req: Request, res: Response) => {
  try {
    const { name, email, password, isAdmin } = req.body;
    const user = await register(name, email, password, isAdmin);
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
