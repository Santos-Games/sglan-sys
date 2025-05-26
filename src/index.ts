import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import userRoutes from './routes/userRoutes';
import adminRoutes from './routes/adminRoutes';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());


app.use('/', userRoutes);
app.use('/admin', adminRoutes); 

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
