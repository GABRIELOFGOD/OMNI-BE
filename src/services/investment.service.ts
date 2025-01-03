import { Repository } from "typeorm";
import { User } from "../entities/user.entity";
import { Earning, EarningType } from "../entities/earnings.entity";
import { ReturnController } from "../controllers/Return.controller";

export class InvestmentService {
  constructor(
    private readonly userRepository: Repository<User>,
    private readonly earningHistoryRepository: Repository<Earning>,
    private readonly returnService: ReturnController
  ) {}

  calculateInvestmentRoi(amount: number): number{
    let roi = 0;
    roi = amount * 0.0055;
    return roi;
  }

  async calculateReferralBonus(
    user: User,
    generation: number,
    visited: Set<string> = new Set<string>()
  ): Promise<number> {
    if (generation > 15) return 0; // Stop recursion after the 15th generation.
  
    // Prevent circular references by checking the visited set.
    if (visited.has(user.email)) return 0;
    visited.add(user.email);
  
    // Preload user data with all necessary relations.
    const theUser = await this.userRepository.findOne({
      where: { email: user.email },
      relations: [
        "investments",
        "referrers",
        "referrers.investments",
        "earningsHistory",
        "referrers.referrers",
      ],
    });
  
    if (!theUser) return 0;
  
    const referrals = theUser.referrers;
    let bonus = 0;
  
    // Bonus percentages for each generation.
    const bonusPercentages: Record<number, number> = {
      1: 0.18,
      2: 0.12,
      3: 0.1,
      4: 0.05,
      5: 0.03,
      6: 0.02,
      7: 0.01,
      8: 0.01,
      9: 0.01,
      10: 0.01,
      11: 0.01,
      12: 0.005,
      13: 0.005,
      14: 0.005,
      15: 0.005,
    };
  
    const bonusPercentage = bonusPercentages[generation] || 0;
  
    for (const theReferral of referrals) {
      const referral = await this.userRepository.findOne({
        where: { email: theReferral.email },
        relations: [
          "investments",
          "referrers",
          "referrers.investments",
          "earningsHistory",
          "referrers.referrers",
        ],
      });
  
      if (!referral) continue;
  
      // Calculate total investment for the referral.
      const referralTotalInvestment = referral.investments.reduce(
        (sum, investment) => sum + investment.amount,
        0
      );
  
      // Calculate daily earnings based on total investment.
      const referralDailyEarnings = referralTotalInvestment * 0.0055;
  
      // Calculate bonus for the current generation.
      bonus += referralDailyEarnings * bonusPercentage;
  
      // Recursive call for the next generation.
      if (referral.referrers && referral.referrers.length > 0) {
        bonus += await this.calculateReferralBonus(
          referral,
          generation + 1,
          visited
        );
      }
    }
  
    return bonus;
  }

  oneDollarMagic = async (user: User): Promise<boolean> => {
    try {
      const amountoBeDistributed = 20;
      // ================= GIVE DIRECT REFERRAL BONUS OF $6 ================= //
      const directReferral = await this.userRepository.findOne({ 
        where: { id: user.referredBy.id },
        relations: ["earningsHistory"]
       });
      if (!directReferral) return false;
      directReferral.oneDollar = parseFloat((Number(directReferral.oneDollar) + Number(6)).toFixed(4));
      const directReferralEarning = this.earningHistoryRepository.create({
        amount: 6,
        user: directReferral,
        type: EarningType.SIX_DOLLAR_MAGIC,
        description: "Direct referral bonus",
      });
      const newUserEarning = await this.earningHistoryRepository.save(directReferralEarning);
      directReferral.earningsHistory && directReferral.earningsHistory.push(newUserEarning);
      await this.userRepository.save(directReferral);

      // ================= GIVE INDIRECT REFERRAL BONUS OF $1 ================= //
      let referrer = directReferral.referredBy;
      for (let i = 0; i < 14; i++) {
        if (!referrer) break;
        referrer.oneDollar = parseFloat((Number(directReferral.oneDollar) + Number(1)).toFixed(4));
        const referrerEarning = this.earningHistoryRepository.create({
          amount: 1,
          user: referrer,
          type: EarningType.ONE_DOLLAR_MAGIC,
          description: "Indirect referral bonus",
        });
        const newReferrerEarning = await this.earningHistoryRepository.save(referrerEarning);
        referrer.earningsHistory && referrer.earningsHistory.push(newReferrerEarning);
        await this.userRepository.save(referrer);
        referrer = referrer.referredBy;
      }
      return true;
    } catch (error: any) {
      throw error;
    }
  }

  promotionalIncome = async (user: User, amount: number) => {
    try {
      const upline = user.referredBy;
      if (!upline) return;
      const newEarning = this.earningHistoryRepository.create({
        amount: 1,
        user: upline,
        type: EarningType.PROMOTIONAL_INCOME,
        description: "Promotional income",
      });
      const earning = await this.earningHistoryRepository.save(newEarning);
      upline.earningsHistory && upline.earningsHistory.push(earning);

      const lastPromotion = await this.returnService.getLastAddedPromotion();
      if (!lastPromotion) return;
      const percentageToEarn = (lastPromotion.amount / 100) * amount;
      
      upline.promotion = parseFloat((Number(upline.promotion) + Number(percentageToEarn)).toFixed(4));
      const savedUpline = await this.userRepository.save(upline);
      
    } catch (error) {
      throw error
    }
  }
  
}