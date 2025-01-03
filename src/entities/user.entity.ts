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
import { Earning } from "./earnings.entity";
import { Investment } from "./investment.entity";

export enum UserRank {
  USER = "us",
  ASSOCIATE_GROUP_LEADER = "agl",
  GROUP_LEADER = "gl",
  ASSOCIATE_MASTER_LEADER = "aml",
  MASTER_LEADER = "ml",
  ASSOCIATE_LEADING_LEADER = "all",
  LEADING_LEADER = "ll",
  CROWN_LEADER = "cl",
  PRINCE_OF_OMNI_STOCK = "pos",
}

@Entity("users")
export class User {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column()
  firstName!: string;

  @Column()
  lastName!: string;

  @Column()
  country!: string;

  @Column()
  city!: string;

  @Column({ default: false })
  hasActiveInvestment!: boolean;

  @Column()
  state!: string;

  @Column()
  address!: string;

  @Column({ nullable: true })
  lastIpAdress!: string;

  @ManyToOne(() => User, (user) => user.referrers)
  referredBy!: User;

  @OneToMany(() => User, (user) => user.referredBy)
  referrers!: User[];

  @Column({ default: false })
  accountActivated!: boolean;

  @Column()
  phoneNumber!: string;

  @Column({ type: "enum", enum: UserRank, default: UserRank.USER })
  rank!: UserRank;

  @Column({ nullable: true })
  referralCode!: string;

  @Column()
  email!: string;

  @Column({ type: "decimal", precision: 10, scale: 4, default: "0.00" })
  balance!: number;

  @Column({ type: "decimal", precision: 10, scale: 4, default: "0.00" })
  promotion!: number;

  @Column({ type: "decimal", precision: 10, scale: 4, default: "0.00" })
  claimable!: number;

  @Column({ type: "decimal", precision: 10, scale: 4, default: "0.00" })
  oneDollar!: number;

  @Column()
  password!: string;

  @Column({ default: "user" })
  role!: string;

  @Column({ type: "enum", enum: ["blocked", "deleted", "active"], default: "active" })
  status!: string;
  
  @OneToMany(() => Earning, (earning) => earning.user)
  earningsHistory!: Earning[];

  @OneToMany(() => Investment, (investment) => investment.investor)
  investments!: Investment[];

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  @Column({ type: "varchar", length: 255, nullable: true })
  verificationToken!: string | null;

  @CreateDateColumn({ nullable: true })
  verificationTokenExpires!: Date | null;

  @Column({ default: false })
  isVerified!: boolean;
}
