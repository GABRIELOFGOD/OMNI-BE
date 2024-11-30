

import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  BeforeInsert,
  BeforeUpdate,
  ManyToOne,
  OneToMany,
} from "typeorm";
import bcrypt from "bcryptjs";

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

  @Column()
  address!: string;

  @Column({ nullable: true })
  lastIpAdress?: string;

  @ManyToOne(() => User, (user) => user.referrers, { nullable: true })
  referredBy?: User;

  @OneToMany(() => User, (user) => user.referredBy)
  referrers?: User[];

  @Column()
  phoneNumber!: string;

  @Column({ nullable: true })
  referralCode?: string;

  @Column()
  email!: string;

  @Column()
  password!: string;

  @Column({ default: "user" })
  role!: string;

  @Column({ type: "varchar", nullable: true })
  passwordResetToken?: string;

  @Column({ type: "timestamp", nullable: true })
  passwordResetExpires?: Date;

  @Column({ type: "bigint", nullable: true })
  passwordChangedAt?: Date | number;

  @Column({ type: "varchar", length: 255, nullable: true })
  verificationToken?: string;

  @CreateDateColumn({ nullable: true })
  verificationTokenExpires?: Date;

  @Column({ default: false })
  isVerified!: boolean;

  @CreateDateColumn()
  createdAt!: Date;

  @UpdateDateColumn()
  updatedAt!: Date;

  // Hash password before saving for the first time
  @BeforeInsert()
  async hashPasswordBeforeInsert() {
    if (this.password && !this.password.startsWith("$2b$")) {
      this.password = await bcrypt.hash(this.password, 12);
    }
  }

  // Hash password on update only if it has changed
  @BeforeUpdate()
  async hashPasswordBeforeUpdate() {
    if (this.password && !this.password.startsWith("$2b$")) {
      this.password = await bcrypt.hash(this.password, 12);
      this.passwordChangedAt = Date.now() - 1000;
    }
  }
}
