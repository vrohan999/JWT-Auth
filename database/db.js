require("dotenv/config");
const { PrismaPg } = require("@prisma/adapter-pg");
const { PrismaClient } = require("@prisma/client");

const dbUrl = `${process.env.DATABASE_URL}`;

const pgAdapter = new PrismaPg({ connectionString: dbUrl });
const prisma = new PrismaClient({ adapter: pgAdapter });

module.exports = { prisma };
