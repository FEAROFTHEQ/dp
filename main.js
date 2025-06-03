// Зчитування .env змінних 
// (дозволяє використовувати змінні середовища з файлу `.env`)
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
dotenv.config();
// перевірка паролів
const zxcvbn = require('zxcvbn');

// Робота з файловими шляхами 
// (вбудований модуль Node.js для коректної роботи з шляхами)
const path = require('path');

// Веб-сервер
// (Express — популярний фреймворк для створення веб-серверів у Node.js)
const express = require('express');

// Хешування паролів 
// (bcrypt — бібліотека для безпечного хешування паролів)
const bcrypt = require('bcrypt');

// Токени для авторизації
// (jsonwebtoken — для створення і перевірки JWT-токенів)
const jwt = require('jsonwebtoken');

// Обробка тіла HTTP-запитів
// (body-parser розбирає JSON-тіла POST-запитів)
const bodyParser = require('body-parser');

// Робота з MongoDB
// (mongoose — ORM для роботи з MongoDB через об’єкти JavaScript)
const mongoose = require('mongoose');

// Валідація вхідних даних
// (express-validator для перевірки даних із запитів)
const { body, validationResult } = require('express-validator');

// Доступ до API з інших доменів/портів
// (cors middleware для прийому запитів із інших джерел)
const cors = require('cors');

// Генерація криптографічних ключів
// (node-forge — бібліотека для криптографії, RSA ключів і т.п.)
const forge = require('node-forge');

// Ініціалізація Express-застосунку
const app = express();

// Порт, на якому запускатиметься сервер
const PORT = process.env.PORT || 5000;

// Секретний ключ для підпису JWT-токенів
const SECRET_KEY = process.env.JWT_SECRET;

// Middleware для парсингу JSON-тіл у запитах
app.use(bodyParser.json());

// Middleware CORS для дозволу запитів з інших доменів/портів
app.use(cors());

// Підключення до MongoDB
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB підключено'))
  .catch(err => console.error('Помилка підключення до MongoDB:', err));

// Схема користувача
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  publicKey: { type: String, required: true },
  role: { type: String, default: 'user' }
});

// Модель користувача на основі схеми
const User = mongoose.model('User', userSchema);
const failedLoginByUsername = {};
const failedLoginByIP = {};

const MAX_FAILED_ATTEMPTS = 5;
const LOCK_TIME = 15 * 60 * 1000; // 15 хвилин

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 хв
  max: 100, // максимум 100 запитів за вікно
  message: 'Занадто багато запитів. Спробуйте пізніше.'
});
const allowedOrigins = ['http://localhost:5000', 'https://dp-jha0.onrender.com/'];
// Функція генерації пари RSA-ключів (2048 біт)
// function generateRSAKeyPair() {
//   const keypair = forge.pki.rsa.generateKeyPair(2048);
//   return {
//     publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
//     privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
//   };
// }

function isBlocked(attemptInfo) {
  if (!attemptInfo) return false;
  if (attemptInfo.count < MAX_FAILED_ATTEMPTS) return false;

  const timePassed = Date.now() - attemptInfo.lastAttempt;
  if (timePassed > LOCK_TIME) {
    // Зняти блокування після таймауту
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

// Скидання лічильника після успішного входу
function resetFailedAttempts(storage, key) {
  if (storage[key]) {
    delete storage[key];
  }
}
function getRemainingAttempts(username) {
  const attemptInfo = failedLoginByUsername[username];
  if (!attemptInfo) return MAX_FAILED_ATTEMPTS;
  if (Date.now() - attemptInfo.lastAttempt > LOCK_TIME) {
    // Якщо час блокування минув — "скидаємо" лічильник
    return MAX_FAILED_ATTEMPTS;
  }
  return Math.max(0, MAX_FAILED_ATTEMPTS - attemptInfo.count);
}

function checkPasswordStrength(password) {

  const result = zxcvbn(password);
  if (result.score < 4) {
    return {
      ok: false,
      message: 'Пароль занадто слабкий. Спробуйте складніший.',
      feedback: result.feedback,
    };
  }
  return { ok: true };
}

function authorizeRoles(...allowedRoles) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
// console.log(authHeader);
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      console.log('Немає токена або невірний формат заголовку');
      return res.status(401).json({ message: 'Немає токена' });
    }

    const token = authHeader.split(' ')[1];

    try {
      const decoded = jwt.verify(token, SECRET_KEY);
      const user = await User.findOne({ username: decoded.username });

      if (!user || !allowedRoles.includes(user.role)) {
        return res.status(403).json({ message: 'Доступ заборонено: недостатньо прав' });
      }

      req.user = user; // прикріпимо користувача до запиту
      next();
    } catch (err) {
      console.error('Помилка авторизації:', err);
      res.status(403).json({ message: 'Недійсний токен або помилка перевірки' });
    }
  };
}

function authenticateToken(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user; // тут user має role
    next();
  });
}

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
// Маршрут для реєстрації користувача
app.post('/register', [
  body('username').isLength({ min: 3 }).withMessage('Ім’я користувача має містити щонайменше 3 символи'),
  body('password').isLength({ min: 8 }).withMessage('Пароль має містити щонайменше 8 символів'),
body('role').optional().isIn(['user', 'admin']).withMessage('Невідома роль'),
 body('publicKey').notEmpty().withMessage('Public key is required')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password, publicKey } = req.body;
  const role = 'user';
  console.log('Перед перевіркою пароля');
  const check = checkPasswordStrength(password);
  if (!check.ok) {
    return res.status(400).json({ error: check.message, feedback: check.feedback });
  }
  console.log('Після перевірки пароля:', check);
  try {
    // Перевірка, чи існує користувач із таким username
    const userExists = await User.findOne({ username });
    if (userExists) {
      return res.status(400).json({ message: 'Користувач вже існує' });
    }

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Генерація RSA ключів
    // const rsaKeys = generateRSAKeyPair();

    // Створення нового користувача
    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey,
      role: 'user'
    });

    await newUser.save();

    // Відповідь із приватним ключем, який потрібно зберегти на клієнті
    res.json({ message: 'Реєстрація успішна' });
  } catch (err) {
    console.error('Помилка під час реєстрації:', err);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// Маршрут для входу користувача
app.post('/login', async (req, res) => {
    console.log('Отримано запит /login');
  const { username, password } = req.body;
  const ip = req.ip;
   if (isBlocked(failedLoginByUsername[username])) {
    return res.status(429).json({ message: `Користувач тимчасово заблокований. Спробуйте пізніше.` });
  }

  // Перевірка блокування по IP
  if (isBlocked(failedLoginByIP[ip])) {
    return res.status(429).json({ message: `З вашої IP-адреси заблоковано надто багато спроб. Спробуйте пізніше.` });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
        console.log('Користувача не знайдено для', username);
      recordFailedAttempt(failedLoginByUsername, username);
      recordFailedAttempt(failedLoginByIP, ip);
      const remaining = getRemainingAttempts(username);
      console.log(remaining);
      return res.status(400).json({ message: 'Користувача не знайдено',remainingAttempts: remaining});
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      console.log('неправ пароль', username);
      recordFailedAttempt(failedLoginByUsername, username);
      recordFailedAttempt(failedLoginByIP, ip);
      const remaining = getRemainingAttempts(username);
      console.log(remaining);
      return res.status(401).json({ message: 'Неправильний пароль', remainingAttempts: remaining });
    }

    resetFailedAttempts(failedLoginByUsername, username);
    resetFailedAttempts(failedLoginByIP, ip);

    const payload = { username: user.username, role: user.role };
    const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '1h' });

    res.json({ message: 'Успішний вхід', token, role: user.role });
  } catch (err) {
    console.error('Помилка під час входу:', err);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

app.get('/admin', authorizeRoles('admin'), (req, res) => {
  res.json({ message: `Ласкаво просимо, адміністраторе ${req.user.username}` });
});


app.get('/users', authorizeRoles('admin', 'user'), async (req, res) => {
   try {
    const users = await User.find({}, 'username role').exec();
    // console.log('Список користувачів:', users);
    res.json(users);
  } catch (err) {
    console.error('Помилка отримання користувачів:', err);
    res.status(500).json({ message: 'Помилка сервера' });
  }
  //   console.log('Маршрут /users виконується');
  // res.json({ test: 'ok' });
});

app.delete('/users/:id', authenticateToken, async (req, res) => {
  const currentUser = req.user; // тут буде role
  if (currentUser.role !== 'admin') {
    return res.status(403).json({ message: 'Доступ заборонено' });
  }
  const id  = req.params.id;
  if (req.user.id === id) {
    return res.status(400).json({ message: 'Неможливо видалити самого себе' });
  }
    if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Доступ заборонено. Ви не адміністратор' });
  }
   try {
    const result = await User.deleteOne({ _id: id });

    if (result.deletedCount === 0) {
      return res.status(404).send('Користувача не знайдено');
    }

    res.status(200).send('Користувач видалений');
  } catch (err) {
    console.error(err);
    res.status(500).send('Помилка сервера');
  }
  


  // виконуємо видалення
});

// Маршрут для виходу (логіки не має, просто повідомлення)
app.post('/logout', (req, res) => {
  res.json({ message: 'Вихід успішний' });
});
app.use(limiter);

// Статичні файли з папки 'public'
app.use(express.static(path.join(__dirname, 'public')));

// Головна сторінка — віддає index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});
