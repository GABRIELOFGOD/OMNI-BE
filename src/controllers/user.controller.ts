import { NextFunction, Request, Response } from "express";
import crypto from "crypto";

import { MoreThan } from "typeorm";
import bcrypt from "bcryptjs";
import { User } from "../entities/user.entity";
import { dataSource } from "../configs/dataSource";
import { addMinutes } from "date-fns";
import Email from "../services/email.service";
import jwt, { JwtPayload } from "jsonwebtoken";
import {
  createUserSchema,
  loginUserSchema,
} from "../schema/user.validatorSchema";
import catchAsync from "../utils/catchAsyncHandler";
import { HttpStatus } from "../helper/httpsStatus";
import AppError from "../utils/appError";

const userRepository = dataSource.getRepository(User);

export default userRepository;

// extended the  jwt verify function to return a custom payload type
interface CustomJwtPayload extends JwtPayload {
  id: string;
}

const jwtVerify = (token: string, secret: string): Promise<CustomJwtPayload> =>
  new Promise((resolve, reject) => {
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        reject(err);
      } else if (
        typeof decoded === "object" &&
        decoded !== null &&
        "id" in decoded
      ) {
        resolve(decoded as CustomJwtPayload);
      } else {
        reject(new Error("Invalid token payload"));
      }
    });
  });

// extended the protect function to include user in the request object
interface ProtectedUserRequest extends Request {
  user?: User;
}

//  function to create a signed JWT token
const signToken = (id: number): string => {
  const expiresIn = process.env.JWT_EXPIRES_IN as string;
  return jwt.sign({ id }, process.env.JWT_SECRET as string, {
    expiresIn: isNaN(Number(expiresIn)) ? expiresIn : parseInt(expiresIn, 10),
  });
};

// function to generate random id
const generateRandomId = (length: number): string => {
  return crypto.randomBytes(length).toString("hex");
};

exports.restrictTo = (...roles: any) => {
  return (req: ProtectedUserRequest, res: Response, next: NextFunction) => {
    // roles ['admin']. default role='user'
    if (req.user && !roles.includes(req.user.role)) {
      return next(
        new AppError("You do not have permission to perform this action", 403)
      );
    }

    next();
  };
};

//
const createSendToken = (
  user: any,
  statusCode: HttpStatus,
  req: Request,
  res: Response
) => {
  const token = signToken(user.id);
  const cookieExpiresInDays = parseInt(
    process.env.JWT_COOKIES_EXPIRES_IN || "20",
    10
  );
  if (isNaN(cookieExpiresInDays)) {
    throw new Error(
      "Invalid JWT_COOKIES_EXPIRES_IN value in environment variables."
    );
  }
  const cookieOptions: object = {
    expires: new Date(Date.now() + cookieExpiresInDays * 24 * 60 * 60 * 1000),
    httpOnly: true,
    sameSite: "lax",
    secure: req.secure || req.headers["x-forwarded-proto"] === "https",
  };
  res.cookie("jwt", token, cookieOptions);
  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

// Middleware to hash password before saving
const hashPasswordMiddleware = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    console.log(req.body);
    if (req.body.password) {
      req.body.password = await bcrypt.hash(req.body.password, 12);
    }
    next();
  }
);

// middleware to validate and protect routes if there is currentUser
export const protect = catchAsync(
  async (req: ProtectedUserRequest, res: Response, next: NextFunction) => {
    //  Check if token exists on the request header or cookies
    let token;

    if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies?.jwt) {
      token = req.cookies.jwt;
    }

    if (!token) {
      return next(
        new AppError(
          "You are not logged in. Please login to access this resource.",
          HttpStatus.UNAUTHORIZED
        )
      );
    }

    //  verify the token using await
    let decoded: CustomJwtPayload;
    try {
      decoded = await jwtVerify(token, process.env.JWT_SECRET as string);
    } catch (error) {
      return next(
        new AppError(
          "Invalid or expired token.Please login and try again!",
          HttpStatus.UNAUTHORIZED
        )
      );
    }
    const userId = parseInt(decoded.id, 10);
    // find the user in the database
    const currentUser = await userRepository.findOne({
      where: { id: userId },
    });

    if (!currentUser) {
      return next(
        new AppError(
          "The user belonging to this token no longer exists.",
          HttpStatus.NOT_FOUND
        )
      );
    }

    if (!decoded || !decoded.iat) {
      return next(
        new AppError(
          "Invalid token or token has no issue time.",
          HttpStatus.UNAUTHORIZED
        )
      );
    }

    // check if user changed their password after the token was issued

    const changePasswordAfter = currentUser.passwordChangedAt;
    console.log(changePasswordAfter);
    if (
      changePasswordAfter &&
      new Date(changePasswordAfter).getTime() / 1000 > decoded.iat
    ) {
      return next(
        new AppError(
          "User recently changed their password. Please login again.",
          HttpStatus.UNAUTHORIZED
        )
      );
    }

    //  grant access to the protected route and attach the user to the request object
    req.user = currentUser;
    // optionally make the user available in templates cuase i'm using a pug template engine to send emails
    res.locals.user = currentUser;
    next();
  }
);

// Register a new user

export const userRegister = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    // Validate `req.body` is not an array
    if (Array.isArray(req.body)) {
      return res.status(400).json({
        message: "Invalid input format. Expected a single user object.",
      });
    }

    try {
      // Validate user input with password confirmation
      const { error } = createUserSchema.validate(req.body);
      if (error) {
        return res
          .status(HttpStatus.OK)
          .json({ message: error.details[0].message });
      }

      const {
        password,
        firstName,
        lastName,
        email,
        country,
        city,
        address,
        phoneNumber,
      } = req.body;

      // Check if email is already registered
      const existingUser = await userRepository.findOne({
        where: { email: req.body.email },
      });
      if (existingUser) {
        return res.status(400).json({ message: "Email already registered." });
      }

      // Proceed with hashing the password after confirmation validation
      const hashedPassword = await bcrypt.hash(password, 12); // Hashing password before storing it

      // Create a new user object, excluding confirmPassword
      const newUser: User = userRepository.create({
        firstName,
        lastName,
        email,
        password,
        country,
        city,
        address,
        phoneNumber,
        lastIpAdress: req.ip,
        referralCode: generateRandomId(9),
        verificationToken: generateRandomId(32),
        verificationTokenExpires: addMinutes(new Date(), 10),
      });

      // Save the new user to the database
      await userRepository.save(newUser);

      // Send verification email
      const verificationUrl = `${req.protocol}://${req.get(
        "host"
      )}/api/v1/users/verifyUser/${newUser.verificationToken}`;
      await new Email(newUser, verificationUrl).sendVerificationEmail();

      // Respond with success
      res.status(HttpStatus.OK).json({
        success: true,
        data: {
          user: newUser,
          message: "User registered successfully. Please verify your email.",
        },
      });
    } catch (error) {
      next(error);
    }
  }
);
// hashPasswordMiddleware, // Ensure this comes after password validation

// Verify a new user to be more certain that the email exists
export const verifyUser = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const verificationToken = req.params.token;

    // Find user by verification token and ensure token has not expired
    const user = await userRepository.findOne({
      where: {
        verificationToken,
        verificationTokenExpires: MoreThan(new Date()), // Compare with the current date
      },
    });

    // If user is not found or token expired
    if (!user) {
      return next(
        new AppError("Token is invalid or has expired", HttpStatus.BAD_REQUEST)
      );
    }

    // Mark user as verified
    await userRepository.update(user.id, {
      isVerified: true,
      verificationToken: undefined,
      verificationTokenExpires: undefined,
    });

    // Fetch the updated user
    const verifiedUser = await userRepository.findOne({
      where: { id: user.id },
    });

    if (!verifiedUser) {
      return next(
        new AppError(
          "Verification failed. Please try again later.",
          HttpStatus.INTERNAL_SERVER_ERROR
        )
      );
    }
    console.log(verifiedUser, "this is verifiedUser");
    createSendToken(verifiedUser, HttpStatus.OK, req, res);
  }
);

// Login  a new user
export const userLogin = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email, password } = req.body;

    // Validate user input
    const { error } = loginUserSchema.validate(req.body);
    if (error) {
      return next(new AppError(error.details[0].message, 400));
    }
    // Check if email and password are provided

    if (!email || !password) {
      return next(new AppError("Please provide email and password!", 400));
    }
    // Check if the user exists in the database
    const user = await userRepository.findOne({
      where: { email },
      select: ["id", "email", "password", "isVerified"],
    });

    // If the user is not found, throw an error
    if (!user) {
      return next(new AppError("Incorrect email or password", 401));
    }
    // Check if the password is correct
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      return next(new AppError("Incorrect email or password", 401));
    }

    // check if the user is verified
    if (!user.isVerified) {
      return next(new AppError("Your account is not verified yet!", 403));
    }
    // Generate and send the JWT token
    console.log(user, "this is login user");
    createSendToken(user, 200, req, res);
  }
);

// Reset password logic
export const forgotPassword = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const { email } = req.body;

    // Find the user by email
    const user = await userRepository.findOne({ where: { email } });

    //  If no user is found, throw an error
    if (!user) {
      return next(
        new AppError(
          "No user found with this email address",
          HttpStatus.NOT_FOUND
        )
      );
    }

    //  Generate a password reset token
    const resetToken = generateRandomId(32);
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    user.passwordResetToken = hashedToken;
    // token is only  valid for 10 minutes . User will see it in the mail just for future dev
    user.passwordResetExpires = new Date(Date.now() + 10 * 60 * 1000);

    try {
      //  save the user with the reset token and expiration
      await userRepository.save(user);

      //  generate a reset URL and send the email
      const resetUrl = `${req.protocol}://${req.get(
        "host"
      )}/api/v1/users/resetPassword/${resetToken}`;

      await new Email(user, resetUrl).sendResetPassword();

      //  respond with success
      res.status(HttpStatus.OK).json({
        status: "success",
        data: {
          message: "Password reset link sent to your email",
        },
      });
    } catch (error) {
      console.error(error);

      // clear the reset token fields in case of email sending failure
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await userRepository.save(user);

      // pass the error to the error-handling middleware //
      return next(
        new AppError(
          "There was a problem sending an email! Please try again later.",
          HttpStatus.INTERNAL_SERVER_ERROR
        )
      );
    }
  }
);

export const resetPassword = catchAsync(
  async (req: Request, res: Response, next: NextFunction) => {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    // find the user with the hashed token and ensure the token hasn't expired
    const user = await userRepository.findOne({
      where: {
        passwordResetToken: hashedToken,
        passwordResetExpires: MoreThan(new Date()),
      },
    });

    if (!user) {
      return next(
        new AppError(
          "Invalid token or token has expired. Please login and try again.",
          HttpStatus.BAD_REQUEST
        )
      );
    }

    // validate passwords match
    if (req.body.password !== req.body.passwordConfirm) {
      return next(
        new AppError(
          "Password and confirmPassword need to match",
          HttpStatus.BAD_REQUEST
        )
      );
    }

    // update the password and clear reset token fields
    user.password = req.body.password; // Assign raw password
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    // save the updated user to the database
    console.log("Before save:", user.password);
    await userRepository.save(user);
    console.log("After save:", user.password);

    // log the user in by sending a new JWT
    createSendToken(user, HttpStatus.OK, req, res);
  }
);

export const updatePassword = catchAsync(
  async (req: ProtectedUserRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      return next(
        new AppError("User not found in request", HttpStatus.UNAUTHORIZED)
      );
    }

    const user = await userRepository.findOne({
      where: { id: req.user.id },
      select: ["id", "password"], // Include the password field explicitly
    });

    if (!user) {
      return next(
        new AppError("No user found with that ID", HttpStatus.NOT_FOUND)
      );
    }

    // check if the current password is correct
    const isPasswordCorrect = await bcrypt.compare(
      req.body.currentPassword,
      user.password
    );
    if (!isPasswordCorrect) {
      return next(
        new AppError(
          "Your current password is incorrect. Please try again.",
          HttpStatus.UNAUTHORIZED
        )
      );
    }

    // validate new password and confirm password
    if (req.body.password !== req.body.passwordConfirm) {
      return next(
        new AppError(
          "Password and confirmPassword need to match",
          HttpStatus.BAD_REQUEST
        )
      );
    }

    // update the password
    user.password = req.body.password;

    // save the updated user to the database
    await userRepository.save(user);

    // log the user in by sending a new JWT
    createSendToken(user, HttpStatus.OK, req, res);
  }
);

export const logout = (_: any, res: Response) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({
    status: "success",
    data: { message: "user Logged out successfully" },
  });
};
