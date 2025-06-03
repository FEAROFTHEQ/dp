const rateLimit = require("express-rate-limit");
const dotenv = require("dotenv");
dotenv.config();
const zxcvbn = require("zxcvbn");
const path = require("path");
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const { body, validationResult } = require("express-validator");
const cors = require("cors");
const forge = require("node-forge");
const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET;
app.use(bodyParser.json());
app.use(cors());
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB підключено"))
  .catch((err) => console.error("Помилка підключення до MongoDB:", err));
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  publicKey: { type: String, required: true },
  role: { type: String, default: "user" },
});
const User = mongoose.model("User", userSchema);
const failedLoginByUsername = {};
const failedLoginByIP = {};
const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; 
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  message: "Занадто багато запитів. Спробуйте пізніше.",
});
const allowedOrigins = [
  "http://localhost:5000",
  "https://dp-jha0.onrender.com",
];
function isBlocked(attemptInfo) {
  if (!attemptInfo) return false;
  if (attemptInfo.count < MAX_FAILED_ATTEMPTS) return false;

  const timePassed = Date.now() - attemptInfo.lastAttempt;
  if (timePassed > LOCK_TIME) {
    return false;
  }
  return true;
}
function recordFailedAttempt(storage, key) {
  if (!storage[key]) {
    storage[key] = { count: 1, lastAttempt: Date.now() };
  } else {
    storage[key].count += 1;
    storage[key].lastAttempt = Date.now();
  }
}
function resetFailedAttempts(storage, key) {
  if (storage[key]) {
    delete storage[key];
  }
}
function getRemainingAttempts(username) {
  const attemptInfo = failedLoginByUsername[username];
  if (!attemptInfo) return MAX_FAILED_ATTEMPTS;
  if (Date.now() - attemptInfo.lastAttempt > LOCK_TIME) {
    return MAX_FAILED_ATTEMPTS;
  }
  return Math.max(0, MAX_FAILED_ATTEMPTS - attemptInfo.count);
}
function checkPasswordStrength(password) {
  const result = zxcvbn(password);
  if (result.score < 4) {
    return {
      ok: false,
      message: "Пароль занадто слабкий. Спробуйте складніший.",
      feedback: result.feedback,
    };
  }
  return { ok: true };
}
function authorizeRoles(...allowedRoles) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      console.log("Немає токена або невірний формат заголовку");
      return res.status(401).json({ message: "Немає токена" });
    }
    const token = authHeader.split(" ")[1];
    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      const user = await User.findOne({ username: decoded.username });
      if (!user || !allowedRoles.includes(user.role)) {
        return res
          .status(403)
          .json({ message: "Доступ заборонено: недостатньо прав" });
      }
      req.user = user; // прикріпимо користувача до запиту
      next();
    } catch (err) {
      console.error("Помилка авторизації:", err);
      res
        .status(403)
        .json({ message: "Недійсний токен або помилка перевірки" });
    }
  };
}
function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // тут user має role
    next();
  });
}
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);
app.post(
  "/register",
  [
    body("username")
      .isLength({ min: 3 })
      .withMessage("Ім’я користувача має містити щонайменше 3 символи"),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Пароль має містити щонайменше 8 символів"),
    body("role")
      .optional()
      .isIn(["user", "admin"])
      .withMessage("Невідома роль"),
    body("publicKey").notEmpty().withMessage("Public key is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, password, publicKey } = req.body;
    const role = "user";
    const check = checkPasswordStrength(password);
    if (!check.ok) {
      return res
        .status(400)
        .json({ error: check.message, feedback: check.feedback });
    }
    try {
      const userExists = await User.findOne({ username });
      if (userExists) {
        return res.status(400).json({ message: "Користувач вже існує" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        username,
        password: hashedPassword,
        publicKey,
        role: "user",
      });
      await newUser.save();
      res.json({ message: "Реєстрація успішна" });
    } catch (err) {
      console.error("Помилка під час реєстрації:", err);
      res.status(500).json({ message: "Помилка сервера" });
    }
  }
);
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  if (isBlocked(failedLoginByUsername[username])) {
    return res.status(429).json({
      message: `Користувач тимчасово заблокований. Спробуйте пізніше.`,
    });
  }
  if (isBlocked(failedLoginByIP[ip])) {
    return res.status(429).json({
      message: `З вашої IP-адреси заблоковано надто багато спроб. Спробуйте пізніше.`,
    });
  }
  try {
    const user = await User.findOne({ username });
    if (!user) {
      recordFailedAttempt(failedLoginByUsername, username);
      recordFailedAttempt(failedLoginByIP, ip);
      const remaining = getRemainingAttempts(username);
      return res.status(400).json({
        message: "Користувача не знайдено",
        remainingAttempts: remaining,
      });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      recordFailedAttempt(failedLoginByUsername, username);
      recordFailedAttempt(failedLoginByIP, ip);
      const remaining = getRemainingAttempts(username);
      return res
        .status(401)
        .json({ message: "Неправильний пароль", remainingAttempts: remaining });
    }
    resetFailedAttempts(failedLoginByUsername, username);
    resetFailedAttempts(failedLoginByIP, ip);
    const payload = { username: user.username, role: user.role };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: "1h" });
    res.json({ message: "Успішний вхід", token, role: user.role });
  } catch (err) {
    console.error("Помилка під час входу:", err);
    res.status(500).json({ message: "Помилка сервера" });
  }
});
app.get("/admin", authorizeRoles("admin"), (req, res) => {
  res.json({ message: `Ласкаво просимо, адміністраторе ${req.user.username}` });
});
app.get("/users", authorizeRoles("admin", "user"), async (req, res) => {
  try {
    const users = await User.find({}, "username role").exec();
    res.json(users);
  } catch (err) {
    console.error("Помилка отримання користувачів:", err);
    res.status(500).json({ message: "Помилка сервера" });
  }
});
app.delete("/users/:id", authenticateToken, async (req, res) => {
  const currentUser = req.user; 
  if (currentUser.role !== "admin") {
    return res.status(403).json({ message: "Доступ заборонено" });
  }
  const id = req.params.id;
  if (req.user.id === id) {
    return res.status(400).json({ message: "Неможливо видалити самого себе" });
  }
  if (req.user.role !== "admin") {
    return res
      .status(403)
      .json({ message: "Доступ заборонено. Ви не адміністратор" });
  }
  try {
    const result = await User.deleteOne({ _id: id });
    if (result.deletedCount === 0) {
      return res.status(404).send("Користувача не знайдено");
    }
    res.status(200).send("Користувач видалений");
  } catch (err) {
    console.error(err);
    res.status(500).send("Помилка сервера");
  }
});
app.post("/logout", (req, res) => {
  res.json({ message: "Вихід успішний" });
});
app.use(limiter);
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});
app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});
