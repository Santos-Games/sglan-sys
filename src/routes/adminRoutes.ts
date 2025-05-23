import express from 'express';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const router = express.Router();

router.put('/user/:id/authorize', async (req, res) => {
  const { id } = req.params;
  const { canLogin, jwtExpiration } = req.body;

  // Validação básica
  if (isNaN(Number(id))) {
    res.status(400).json({ error: 'Invalid user id' });
    return;
  }

  // Log dos dados recebidos
  console.log('Received:', { id, canLogin, jwtExpiration });

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
    console.error(error);
    res.status(500).json({ error: 'Failed to update user authorization', details: error });
  }
});

export default router;