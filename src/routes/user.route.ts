import { Router } from "express";
import { validateRequest } from "../middlewares/validator.middleware";
import {
  createUserSchema,
  loginUserSchema,
} from "../schema/user.validatorSchema";
import authMiddleware from "../middlewares/auth.middleware";
import { UserService } from "../services/user.service";
import { Repository } from "typeorm";
import { User } from "../entities/user.entity";
import { dataSource } from "../configs/dataSource";
import { UserController } from "../controllers/user.controller";
import { MailService } from "../services/mail.service";
const router = Router();

let userRepository: Repository<User> = dataSource.getRepository(User);
let userService: UserService = new UserService(userRepository);
let mailService: MailService = new MailService();

let userController: UserController = new UserController(userRepository, userService, mailService);

router.post("/register", validateRequest(createUserSchema), userController.createUser);
router.post("/login", validateRequest(loginUserSchema), userController.userLogin);
// router.get("/verifyUser/:token", verifyUser);

router.use(authMiddleware);
router.get("/profile", userController.userProfile);
router.get("/team", userController.totalTeamMembers);

// ============== ADMIN ROLES ============== //
router.get("/", userController.getAllUsers);

export default router;
// https://github.com/GABRIELOFGOD/OMNI-BE