import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import userRoutes from './routes/userRoutes';
import adminRoutes from './routes/adminRoutes';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Registra as rotas
app.use('/', userRoutes);
app.use('/admin', adminRoutes); // agora as rotas de admin ficam com prefixo /admin

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
