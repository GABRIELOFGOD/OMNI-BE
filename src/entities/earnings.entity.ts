import {
  Column,
  CreateDateColumn,
  Entity,
  ManyToMany,
  ManyToOne,
  OneToMany,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from "typeorm";
import { User } from "./user.entity";

export enum EarningStatus {
  CLAIMED = "claimed",
  PENDING = "pending",
  EXPIRED = "expired",
}

export enum EarningType {
  ONE_DOLLAR_MAGIC = "one-dollar-magic",
  SIX_DOLLAR_MAGIC = "six-dollar-magic",
  ROI = "roi",
  PROMOTIONAL_INCOME = "promotional-income",
  REFERRAL_BONUS = "referral-bonus",
}

@Entity("earnings")
export class Earning {
  @PrimaryGeneratedColumn()
  id!: number;

  @ManyToOne(() => User, (user) => user.earningsHistory)
  user!: User;

  @Column({ type: "decimal", precision: 10, scale: 4 })
  amount!: number;

  @Column({ type: "enum", enum: EarningType })
  type!: EarningType;

  @Column({ nullable: true })
  description!: string;

  @Column({ nullable: true })
  reference!: string;

  @Column({ type: "enum", enum: EarningStatus, default: EarningStatus.PENDING })
  status!: EarningStatus;

  @Column({ nullable: true })
  transactionId!: string;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;
}
