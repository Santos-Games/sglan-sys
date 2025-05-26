import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import userRoutes from './routes/userRoutes';
import adminRoutes from './routes/adminRoutes';
import { monitorSessions } from './jobs/sessionMonitor';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

setInterval(monitorSessions, 10000);

app.use('/', userRoutes);
app.use('/admin', adminRoutes); 

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
