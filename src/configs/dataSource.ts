// data-source.ts
import { DataSource } from 'typeorm';
import { config } from 'dotenv';
import { User } from '../entities/user.entity';
import { Earning } from '../entities/earnings.entity';
import { Investment } from '../entities/investment.entity';
import { Return } from '../entities/return.entity';
import { Promotion } from '../entities/promotion.entity';
config();

export const dataSource = new DataSource({
  type: 'mysql',
  host: process.env.DB_HOST || 'localhost',
  port: 3306,
  username: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  entities: [User, Earning, Investment, Return, Promotion],
  synchronize: true,
});
