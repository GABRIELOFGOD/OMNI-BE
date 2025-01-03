import catchAsync from "../utils/catchAsyncHandler";
import { InvestmentService } from "../services/investment.service";
import { Request } from "../@types/custom";
import { NextFunction, Response } from "express";
import { Repository } from "typeorm";
import { User } from "../entities/user.entity";
import { AppError } from "../services/errorHandling.service";
import { Investment, InvestmentType } from "../entities/investment.entity";
import cron from "node-cron";
import { Earning, EarningType } from "../entities/earnings.entity";
import { Return } from "../entities/return.entity";
import { ReturnController } from "./Return.controller";
import { Promotion } from "../entities/promotion.entity";

export class InvestmentController {
  private isRunning = false;
  constructor(
    private readonly investmentService: InvestmentService,
    private readonly userRepository: Repository<User>,
    private readonly investmentRepository: Repository<Investment>,
    private readonly earningHistoryRepository: Repository<Earning>,
    private readonly returnRepository: Repository<Return>,
    private readonly returnService: ReturnController,
    private readonly promotionRepository: Repository<Promotion>
  ) {
    this.autoExecute();
  }

  private autoExecute() {
    cron.schedule('0/40 * * * * *', async () => {
      if (this.isRunning) {
        console.log("Skipped execution: getInvestmentRoi is already running");
        return;
      }
      
      this.isRunning = true;

      try {
        console.log("Running getInvestmentRoi...");
        const investments = await this.investmentRepository.find();

        for (const theInvestment of investments) {
          // console.log("theInvestment", theInvestment);
          const investment = await this.investmentRepository.findOne({
            where: { id: theInvestment.id },
            relations: ["investor", "investor.earningsHistory"],
          });

          if (!investment) continue;

          if (investment.expired || investment.type === InvestmentType.ACCOUNT_ACTIVATION || investment.amountReturned >= investment.amount * 3) {
            continue;
          }
          
          const lastRate = await this.returnService.getLastAddedReturn();
          if (!lastRate) continue;

          const roi = (lastRate.amount / 100) * investment.amount;
          const newEarning = this.earningHistoryRepository.create({
            amount: roi,
            type: EarningType.ROI,
            user: investment.investor,
          });

          await this.earningHistoryRepository.save(newEarning);
          investment.amountReturned = parseFloat((Number(investment.amountReturned) + Number(roi)).toFixed(4));
          investment.availableAmount = parseFloat((Number(investment.availableAmount) + Number(roi)).toFixed(4));

          const updatedInvestment = await this.investmentRepository.save(investment);

          const user = await this.userRepository.findOne({
            where: { email: investment.investor.email },
            relations: ["earningsHistory"],
          });

          if (!user) continue;

          user.earningsHistory.push(newEarning);
          await this.userRepository.save(user);

          // ====================== TODO: RUN REFERRAL BONUS ====================== //

        }
        
        console.log("getInvestmentRoi completed successfully");
      } catch (error) {
        console.error("Error in getInvestmentRoi:", error);
        // Optionally, you can add a retry or notification mechanism here
      } finally {
        this.isRunning = false;  // Release the "lock"
      }
    });
  }

  // ====================== CLAIM INVESTMENT ============================= //
  claimInvestment = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const reqUser = req.user;
    if (!reqUser) return next(new AppError("User not found", 400));
    const { id } = req.params;

    if (!id) return next(new AppError("Investment ID is required", 400));

    const user = await this.userRepository.findOne({
        where: { email: reqUser.email },
        relations: ["investments", "earningsHistory"]
    });

    if (!user) return next(new AppError("User not found", 400));

    if (!user.hasActiveInvestment) return next(new AppError("You do not have any active investment", 400));

    const userOwnsInvestment = user.investments.some((investment) => investment.id === Number(id));
    if (!userOwnsInvestment) return next(new AppError("You do not own this investment, if you think something is wrong, please logout and login again.", 400));

    const investment = await this.investmentRepository.findOne({
        where: { id: Number(id) },
        relations: ["investor", "investor.earningsHistory"]
    });

    if (!investment) return next(new AppError("Investment not found", 400));

    user.balance = parseFloat((Number(user.balance) + Number(investment.availableAmount)).toFixed(4));
    await this.userRepository.save(user);

    investment.availableAmount = 0;
    await this.investmentRepository.save(investment);

    res.status(200).json({
        status: "success",
        message: "Investment claimed successfully",
    });
  });
  
  // ====================== CREATE INVESTMENT ============================= //
  createInvestment = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { amount } = req.body;

    // ============== VALIDATE REQUEST ============== //
    if (!amount) return next(new AppError("Amount is required", 400));

    // ====================== GET USER ====================== //
    const reqUser = req.user;
    if (!reqUser) return next(new AppError("User not found", 400));

    // ========================= FIND USER ========================= //
    const user = await this.userRepository.findOne({
        where: { email: reqUser.email },
        relations: ["referrers", "referredBy", "referredBy.investments", "referredBy.earningsHistory"]
    });

    if (!user) return next(new AppError("User not found", 400));
    
    // ============== CHECK USER ================== //
    if(user.role !== "user" || user.accountActivated == false) return next(new AppError("You are not allowed to invest", 400));
    
    // TODO: Integrate payment gateway

    // ======================= CONFIRM WALLET OWNER ======================== //
    // if (user.wallet !== wallet) return next(new AppError("Sorry you cannot invest with other people's wallet", 400));

    // ======================= CREATE NEW INVESTMENT ======================= //
    const newInvestment = this.investmentRepository.create({
      amount,
      investor: user,
      type: InvestmentType.INVESTMENT
    });

    // ======================= SAVE NEW INVESTMENT ======================= //
    const savedInvestment = await this.investmentRepository.save(newInvestment);
    const payPromotion = await this.investmentService.promotionalIncome(user, savedInvestment.amount);
    user.hasActiveInvestment = true;
    const savedUser = await this.userRepository.save(user);

    // ===================== RETURN RESPONSE ===================== //
    res.status(201).json({
        status: "success",
        message: `You have successfully invested ${amount}`,
    });
  });

  activateAccount = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { amount } = req.body;
    if (!amount || amount < 20) return next(new AppError("Account activation requires $20 deposit", 400));
    
    const reqUser = req.user;
    if (!reqUser) return next(new AppError("User not found", 400));

    const user = await this.userRepository.findOne({
        where: { email: reqUser.email },
        relations: ["investments", "referrers", "referredBy", "referredBy.investments", "referredBy.earningsHistory"]
    });

    if (!user) return next(new AppError("User not found", 400));

    if (user.accountActivated) return next(new AppError("Account already activated", 400));

    // ======================= ONE DOLLAR MAGIC ======================= //
    if (user.referredBy) {
      const oneDollarMagic = await this.investmentService.oneDollarMagic(user);
      if (!oneDollarMagic) return next(new AppError("Failed to activate account", 400));
    }

    // ======================= CREATE NEW INVESTMENT ======================= //
    const newInvestment = this.investmentRepository.create({
        amount,
        investor: user,
        type: InvestmentType.ACCOUNT_ACTIVATION
    });

    // ======================= SAVE NEW INVESTMENT ======================= //
    const saveNewInvestment = await this.investmentRepository.save(newInvestment);

    user.investments && user.investments.push(saveNewInvestment);
    user.accountActivated = true;

    await this.userRepository.save(user);

    res.status(200).json({
        status: "success",
        message: "Account activated successfully",
    });
  });


  // =========================== ADMIN RIGHTS ============================== //
  createReturn = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { amount } = req.body;
    if (!amount) return next(new AppError("Rate is required", 400));

    const theUser = req.user;
    if (!theUser) return next(new AppError("User not found", 404));

    const user = await this.userRepository.findOne({
        where: { email: theUser.email },
    });

    if (!user) return next(new AppError("User not found", 404));

    if (user.role !== "admin" || user.status !== "active") return next(new AppError("You are not allowed to perform this operation", 401));

    const newReturn = this.returnRepository.create({
      amount,
      updateUser: user,
    });

    await this.returnRepository.save(newReturn);

    res.status(201).json({
        status: "success",
        message: "Return created successfully",
    });
  });

  createPromotion = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { amount } = req.body;
    if (!amount) return next(new AppError("Amount is required", 400));

    const theUser = req.user;
    if (!theUser) return next(new AppError("User not found", 404));

    const user = await this.userRepository.findOne({
        where: { email: theUser.email },
    });

    if (!user) return next(new AppError("User not found", 404));

    if (user.role !== "admin" || user.status !== "active") return next(new AppError("You are not allowed to perform this operation", 401));

    const newPromotion = this.promotionRepository.create({
      amount,
      updateUser: user,
    });

    await this.promotionRepository.save(newPromotion);

    res.status(201).json({
        status: "success",
        message: "Promotion created successfully",
    });
  });

  getAllInvestments = async (req: Request, res: Response, next: NextFunction) => {
    const theUser = req.user;
    if (!theUser) return next(new AppError("User not found", 400));
    const user = await this.userRepository.findOne({
      where: { email: theUser.email }
    });
    if (!user) return next(new AppError("User not found", 400));
    if (user.role !== "admin") return next(new AppError("You are not allowed to view all investments", 400));
    
    const investments = await this.investmentRepository.find();
    res.status(200).json({
      status: "success",
      data: investments
    });
  }

  // =========================== ADMIN RIGHTS ============================== //
}