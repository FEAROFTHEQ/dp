// Зчитування .env змінних 
// (дозволяє використовувати змінні середовища з файлу `.env`)
const dotenv = require('dotenv');
dotenv.config();

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

// Функція генерації пари RSA-ключів (2048 біт)
function generateRSAKeyPair() {
  const keypair = forge.pki.rsa.generateKeyPair(2048);
  return {
    publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
    privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
  };
}


function authorizeRoles(...allowedRoles) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
console.log(authHeader);
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

// Маршрут для реєстрації користувача
app.post('/register', [
  body('username').isLength({ min: 3 }).withMessage('Ім’я користувача має містити щонайменше 3 символи'),
  body('password').isLength({ min: 6 }).withMessage('Пароль має містити щонайменше 6 символів'),
body('role').optional().isIn(['user', 'admin']).withMessage('Невідома роль')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;
  const role = 'user';
  try {
    // Перевірка, чи існує користувач із таким username
    const userExists = await User.findOne({ username });
    if (userExists) {
      return res.status(400).json({ message: 'Користувач вже існує' });
    }

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    // Генерація RSA ключів
    const rsaKeys = generateRSAKeyPair();

    // Створення нового користувача
    const newUser = new User({
      username,
      password: hashedPassword,
      publicKey: rsaKeys.publicKey,
      role: 'user'
    });

    await newUser.save();

    // Відповідь із приватним ключем, який потрібно зберегти на клієнті
    res.json({ message: 'Реєстрація успішна', privateKey: rsaKeys.privateKey });
  } catch (err) {
    console.error('Помилка під час реєстрації:', err);
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// Маршрут для входу користувача
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Користувача не знайдено' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Неправильний пароль' });
    }

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
  // try {
  //   // Отримуємо список користувачів, повертаючи лише username і role
  //   const users = await User.find({}, 'username role').exec();

  //   // Вивід у консоль сервера
  //   console.log('Список користувачів:', users);

  //   res.json(users);
  // } catch (err) {
  //   console.error('Помилка отримання користувачів:', err);
  //   res.status(500).json({ message: 'Помилка сервера' });
  // }
    console.log('Маршрут /users виконується');
  res.json({ test: 'ok' });
});

// Маршрут для виходу (логіки не має, просто повідомлення)
app.post('/logout', (req, res) => {
  res.json({ message: 'Вихід успішний' });
});


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
