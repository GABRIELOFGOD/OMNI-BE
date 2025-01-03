import { Request } from "../@types/custom";
import { NextFunction, Response } from "express";
import { getClientIp } from "request-ip";
import { CreateUserDto } from "../dtos/userRegister.dto";
import { User } from "../entities/user.entity";
import catchAsync from "../utils/catchAsyncHandler";
import { Repository } from "typeorm";
import { isEmail, isMobilePhone, isStrongPassword } from "validator";
import { UserService } from "../services/user.service";
import { MailService } from "../services/mail.service";
import { AppError } from "../services/errorHandling.service";

export  class UserController {
  constructor (
    private readonly userRepository: Repository<User>,
    private readonly userService: UserService,
    private readonly mailService: MailService
  ){}

  createUser = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const createUserDto: CreateUserDto = req.body;
    const userIp = getClientIp(req) || req.ip || "";

    let user = await this.userRepository.findOne({
      where: {email: createUserDto.email}
    });

    if (user) return next(new AppError("User already exists", 400));

    // ==================== VALIDATION ==================== //
    if (!isEmail(createUserDto.email)) return next(new AppError("Invalid email", 400));
    if (!isStrongPassword(createUserDto.password)) return next(new AppError("Password is not strong enough", 400));
    if (!isMobilePhone(createUserDto.phone)) return next(new AppError("Invalid phone number", 400));

    const newUser = this.userRepository.create(createUserDto);
    newUser.phoneNumber = createUserDto.phone;
    newUser.lastIpAdress = userIp;
    newUser.referralCode = this .userService.createReferralCode();

    if (createUserDto.referralCode) {
      const referrer = await this.userRepository.findOne({
        where: {referralCode: createUserDto.referralCode.toUpperCase()}
      });
      if (!referrer) return next(new AppError("Referral code is invalid", 400));
      newUser.referredBy = referrer;
    }

    // =================== HASH PASSWORD =================== //
    const hashedPassword = await this.userService.hashPassword(createUserDto.password);
    newUser.password = hashedPassword;

    // ============= SAVE USER TO DATABASE ============= //
    await this.userRepository.save(newUser);

    // ============== CREATE TOKEN ============== //
    const authToken = this.userService.generateAuthToken(newUser);
    // console.log("authToken", authToken);
    return res.status(201).json({ status: "success", message: "User created successfully", token: authToken });
  });

  // =================== LOGIN =================== //
  userLogin = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;
    const userIp = getClientIp(req) || req.ip || "";

    // ============= CHECK IF USER EXISTS ============= //
    const user = await this.userRepository.findOne({ where: { email } });
    if (!user) return next(new AppError("Invalid email or password", 400));

    // ============= CHECK IF PASSWORD IS CORRECT ============= //
    const isPasswordCorrect = await this.userService.comparePassword(password, user.password);
    if (!isPasswordCorrect) return next(new AppError("Invalid email or password", 400));

    // ============= UPDATE USER LAST IP ADDRESS ============= //
    if (user.lastIpAdress !== userIp) {
      this.mailService.newIpDiscoverEmail(user, userIp);
    }
    user.lastIpAdress = userIp;
    await this.userRepository.save(user);

    // ============== CREATE TOKEN ============== //
    const authToken = this.userService.generateAuthToken(user);
    return res.status(200).json({ status: "success", message: "User logged in successfully", token: authToken });
  });

  // =================== PROFILE =================== //
  userProfile = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const theUser = req.user;
    const user = await this.userRepository.findOne({
      where: { id: theUser.id },
      relations: ["referrers", "referredBy", "investments", "earningsHistory"]
    });
    if (!user) return next(new AppError("User not found", 404));

    const { password, isVerified, lastIpAdress, verificationToken, verificationTokenExpires, hasActiveInvestment, ...rest } = user;
    
    return res.status(200).json({ status: "User profile", user: rest });
  });

  // ==================== GET ALL USERS CONTROLLER ================= //
  getAllUsers = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const theUser = req.user;
    if(!theUser) return next(new AppError("Unauthorized request", 400));
    const user = await this.userRepository.findOne({
      where: { email: theUser.email }
    });
    if (!user || user.role !== "admin") return next(new AppError("Sorry! you are not allowed to perform this operation.", 404));
    const users = await this.userRepository.find();
    res.status(200).json({ users });
  });

  // ========================= ALL TEAM MEMBERS ======================= //
  totalTeamMembers = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const theUser = req.user;
  
    const getAllReferrers = async (user: User, generation: number): Promise<User[]> => {
      if (generation > 15) return []; // Stop at the 15th generation
  
      const currentUser = await this.userRepository.findOne({
        where: { id: user.id },
        relations: ["referrers", "referrers.investments"],
      });
      if (!currentUser || !currentUser.referrers) return [];  
      let allReferrers = [...currentUser.referrers];  
      for (const referrer of currentUser.referrers) {
        const nestedReferrers = await getAllReferrers(referrer, generation + 1);
        allReferrers = [...allReferrers, ...nestedReferrers];
      }  
      return allReferrers;
    };
  
    const user = await this.userRepository.findOne({
      where: { id: theUser.id },
      relations: ["referrers", "referrers.investments"],
    });  
    if (!user) return next(new AppError("User not found", 404));  
    const allReferrers = await getAllReferrers(user, 1);
  
    return res.status(200).json({
      status: "success",
      totalTeamMembers: allReferrers.length,
      referrers: allReferrers,
    });
  });
  
}