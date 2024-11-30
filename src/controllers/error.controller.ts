import express from "express";
import AppError from "../utils/appError";

interface ExtendedError extends Error {
  statusCode?: number;
  status?: string;
  code?: string | number;
  path?: string;
  value?: string;
  errMessage?: string;
  isOperational?: boolean;
  errors?: any;
  errmsg?: any;
  sqlMessage?: string;
}

const handleInvalidForeignKeyError = (err: ExtendedError): AppError => {
  const message = `Invalid foreign key constraint: ${err.sqlMessage}`;
  return new AppError(message, 400);
};

const handleDuplicateErrorInDB = (err: ExtendedError): AppError => {
  const value = err.sqlMessage?.match(/Duplicate entry '(.+?)'/)?.[1];
  const message = `Duplicate field value: ${value}. Please use another value.`;
  return new AppError(message, 400);
};

const handleValidationErrorInDB = (err: ExtendedError): AppError => {
  const message = `Validation failed: ${err.message}. Please provide correct data.`;
  return new AppError(message, 400);
};

const handleJsonWebTokenError = (): AppError => {
  return new AppError(
    "Invalid token, Please provide a valid token. Please login again!",
    401
  );
};

const handleTokenExpiredError = (): AppError => {
  return new AppError("Token expired. Please login again.", 401);
};

const sendErrorDev = (
  err: ExtendedError,
  req: express.Request,
  res: express.Response
) => {
  if (req.originalUrl.startsWith("/api")) {
    return res.status(err.statusCode || 500).json({
      status: err.status,
      message: err.message,
      error: err,
      stack: err.stack,
    });
  }
};

const sendErrorProd = (
  err: ExtendedError,
  req: express.Request,
  res: express.Response
) => {
  if (req.originalUrl.startsWith("/api")) {
    if (err.isOperational) {
      return res.status(err.statusCode || 500).json({
        status: err.status,
        message: err.message,
      });
    }
    return res.status(500).json({
      status: "error",
      message: "Something went wrong!",
    });
  }
};

export default (
  error: ExtendedError,
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
) => {
  error.statusCode = error.statusCode || 500;
  error.status = error.status || "error";

  if (process.env.NODE_ENV === "development") {
    sendErrorDev(error, req, res);
  } else if (process.env.NODE_ENV === "production") {
    let err = { ...error };
    err.message = error.message;

    // MySQL error handling
    if (err.code === "ER_DUP_ENTRY") err = handleDuplicateErrorInDB(err);
    if (err.code === "ER_NO_REFERENCED_ROW_2")
      err = handleInvalidForeignKeyError(err);
    if (err.code === "ER_ROW_IS_REFERENCED_2")
      err = handleInvalidForeignKeyError(err);
    if (err.name === "JsonWebTokenError") err = handleJsonWebTokenError();
    if (err.name === "TokenExpiredError") err = handleTokenExpiredError();

    sendErrorProd(err, req, res);
  }
};
