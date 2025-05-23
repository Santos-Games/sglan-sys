import { PrismaClient } from '@prisma/client';
import * as bcrypt from 'bcrypt';

const prisma = new PrismaClient();

async function main() {
  const hashedPassword = await bcrypt.hash('admin123', 10);

  await prisma.user.upsert({
    where: { email: 'contato@styxx.com.br' },
    update: {},
    create: {
      name: 'Pedro Souza',
      email: 'contato@styxx.com.br',
      password: hashedPassword,
      isAdmin: true,
      lastLogin: null,
    },
  });

  console.log('Admin user created');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
