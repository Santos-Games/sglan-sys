import prisma from '../prisma/client';
import * as bcrypt from 'bcrypt';

async function createAdmin() {
  const hashedPassword = await bcrypt.hash('admin123', 10);

  try {
    const admin = await prisma.user.create({
      data: {
        name: 'admin', 
        email: 'admin2@sg.com', 
        password: hashedPassword,
        isAdmin: true,
      },
    });
    console.log('Admin user created:', admin);
  } catch (error) {
    console.error('Error creating admin user:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createAdmin();
