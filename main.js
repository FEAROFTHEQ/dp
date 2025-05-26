const dotenv = require('dotenv');
dotenv.config();
const path = require('path');
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const { body, validationResult } = require('express-validator');
const cors = require('cors');
const forge = require('node-forge');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(bodyParser.json());
app.use(cors());

console.log('MONGO_URI:', process.env.MONGO_URI);
// Підключення до MongoDB через змінну середовища
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB підключено'))
  .catch(err => console.error(err));

// Схема користувача
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  publicKey: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Генерація пари RSA-ключів
function generateRSAKeyPair() {
  const keypair = forge.pki.rsa.generateKeyPair(2048);
  return {
    publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
    privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
  };
}

// Реєстрація
app.post('/register', [
  body('username').isLength({ min: 3 }).withMessage('Ім’я користувача має містити щонайменше 3 символи'),
  body('password').isLength({ min: 6 }).withMessage('Пароль має містити щонайменше 6 символів')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { username, password } = req.body;
  try {
    const userExists = await User.findOne({ username });
    if (userExists) return res.status(400).json({ message: 'Користувач вже існує' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const rsaKeys = generateRSAKeyPair();
    const newUser = new User({ username, password: hashedPassword, publicKey: rsaKeys.publicKey });
    await newUser.save();

    res.json({ message: 'Реєстрація успішна', privateKey: rsaKeys.privateKey });
  } catch (err) {
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// Вхід
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Користувача не знайдено' });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ message: 'Невірний пароль' });

    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Успішний вхід', token });
  } catch (err) {
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// Профіль
app.get('/profile', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Немає токена' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET_KEY, async (err, user) => {
    if (err) return res.status(403).json({ message: 'Невірний токен' });

    const dbUser = await User.findOne({ username: user.username });
    if (!dbUser) return res.status(404).json({ message: 'Користувача не знайдено' });

    res.json({ message: `Привіт, ${dbUser.username}`, publicKey: dbUser.publicKey });
  });
});
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});
