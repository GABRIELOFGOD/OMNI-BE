import express from 'express';
import { InvestmentController } from '../controllers/investment.controller';
import { InvestmentService } from '../services/investment.service';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { dataSource } from '../configs/dataSource';
import { Investment } from '../entities/investment.entity';
import authMiddleware from '../middlewares/auth.middleware';
import { Earning } from '../entities/earnings.entity';
import { Return } from '../entities/return.entity';
import { ReturnController } from '../controllers/Return.controller';
import { Promotion } from '../entities/promotion.entity';

const router = express.Router();
let userRepository: Repository<User> = dataSource.getRepository(User);
let investmentRepository: Repository<Investment> = dataSource.getRepository(Investment);
let earningHistoryRepository: Repository<Earning> = dataSource.getRepository(Earning);
let returnRepository: Repository<Return> = dataSource.getRepository(Return);
let promotionRepository: Repository<Promotion> = dataSource.getRepository(Promotion);
let returnService = new ReturnController(userRepository, returnRepository, promotionRepository);
let investmentService = new InvestmentService(userRepository, earningHistoryRepository, returnService);

let investmentController = new InvestmentController(investmentService, userRepository, investmentRepository, earningHistoryRepository, returnRepository, returnService, promotionRepository);

router.use(authMiddleware);
router.post("/invest", investmentController.createInvestment);
router.post("/activate", investmentController.activateAccount);
router.get("/claim/:id", investmentController.claimInvestment);

// =============== ADMIN RIGHTS ================= //
router.post("/rate", investmentController.createReturn);
router.post("/promotion", investmentController.createPromotion);

router.get("/all-investments", investmentController.getAllInvestments);
// =============== ADMIN RIGHTS ================= //
export default router;