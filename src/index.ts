import express, { NextFunction, Request, Response } from "express";
import path from "path";
import { config } from "dotenv";
import { AppError } from "./services/errorHandling.service";
import globalErrorHandler from "./controllers/error.controller";
import userRoutes from "./routes/user.route";
import dbConfig from "./configs/database.config";
import { dataSource } from "./configs/dataSource";

// ========== CONFIGURATIONS ========== //
config();
console.log(
  process.env.NODE_ENV,
  process.env.EMAIL_FROM,
  process.env.EMAIL_PASSWORD
);
const app = express();
const PORT = process.env.PORT || 5000;
dbConfig();

app.set("trust proxy", true);
app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());

// ========== ROUTES ========== //
app.all("/", (req: Request, res: Response) =>
  res.send("HELLO FROM OMNISTOCK SERVER")
);

dataSource
  .initialize()
  .then(() => {
    console.log("Data Source has been initialized!");
  })
  .catch((err) => {
    console.error("Error during Data Source initialization", err);
  });

app.use((req, res, next) => {
  console.log("Client IP:", req.headers["x-forwarded-for"] || req.ip);
  next();
});

app.use("/api/v2/users", userRoutes);

// ========== ERROR HANDLING ========== //
app.all("*", (req: Request, res: Response, next: NextFunction) =>
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404))
);
app.use(globalErrorHandler);

app.listen(PORT, () =>
  console.log(`SERVER STARTED ON http://localhost:${PORT}`)
);
