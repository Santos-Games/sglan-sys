-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "minutesUsed" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "minutesBalance" INTEGER NOT NULL DEFAULT 0;
