import { Router } from "express";
import { validateRequest } from "../middlewares/validator.middleware";
import {
  createUserSchema,
  loginUserSchema,
} from "../schema/user.validatorSchema";
import {
  userLogin,
  userRegister,
  verifyUser,
  forgotPassword,
  resetPassword,
  protect,
  updatePassword,
  logout,
} from "../controllers/user.controller";
const router = Router();

router.post("/register", validateRequest(createUserSchema), userRegister);
router.post("/login", validateRequest(loginUserSchema), userLogin);
router.get("/verifyUser/:token", verifyUser);
router.post("/forgotPassword", forgotPassword);
router.post("/resetPassword/:token", resetPassword);
router.get("/logout", logout);

router.use(protect);
router.patch("/updatePassword", updatePassword);
export default router;
