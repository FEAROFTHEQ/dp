
//Зчитування .env змінних 
// (дозволяє використовувати змінні середовища з `.env` файлу)
const dotenv = require('dotenv');
//(завантажує змінні з .env файлу у process.env)
dotenv.config();
// Робота з файловими шляхами 
// (Імпортує вбудований модуль Node.js для роботи з файловими шляхами. Наприклад, щоб коректно скласти абсолютний шлях до файлу
const path = require('path');
//	Веб-сервер
// (Імпортує `Express` — популярний фреймворк для створення веб-серверів у Node.js. Він спрощує обробку HTTP-запитів і маршрутів.)
const express = require('express');
//Хешування паролів 
// ( Імпортує бібліотеку bcrypt для хешування паролів)
const bcrypt = require('bcrypt');
//Токени для авторизації
// (Імпортує бібліотеку `jsonwebtoken` для створення і перевірки JWT-токенів)
const jwt = require('jsonwebtoken');
// 	Обробка тіла HTTP-запитів
// ( Імпортує body-parser — проміжне ПЗ, яке розбирає JSON-тіла POST-запитів)
const bodyParser = require('body-parser');
// 	Робота з MongoDB
// (Імпортує `mongoose` — ORM (обгортка для MongoDB), яка дозволяє працювати з документами MongoDB як з об'єктами JavaScript)
const mongoose = require('mongoose');
//	Валідація вхідних даних
// (Імпортує функції для валідації вхідних даних )
const { body, validationResult } = require('express-validator');
// 	Доступ до API з інших доменів/портів
// (Імпортує middleware `cors`, який дозволяє серверу приймати запити з інших доменів або портів 
// (наприклад, коли фронтенд на `localhost:5173`, а бекенд — на `localhost:5000`).)
const cors = require('cors');
// Генерація криптографічних ключів
// (Імпортує node-forge — криптографічну бібліотеку для генерації ключів RSA, шифрування, хешування та іншої криптографії.)
const forge = require('node-forge');

//Створює екземпляр застосунку Express. `app` — це ваш сервер, 
// на який ви будете "навішувати" маршрути, middleware, обробники запитів тощо.
const app = express();
//становлює порт, на якому буде запускатись сервер:
const PORT = process.env.PORT || 5000;
// Зчитує секретний ключ з `.env` для підпису JWT-токенів. 
const SECRET_KEY = process.env.JWT_SECRET;

// Додає middleware, який дозволяє Express розуміти `JSON` у запитах (наприклад, при POST реєстрації).
app.use(bodyParser.json());
//Додає middleware CORS, щоб дозволити фронтенду (на іншому домені чи порту) звертатись до вашого API.

app.use(cors());

// Підключення до MongoDB через змінну середовища
//Якщо з`єднання з MongoDB пройшло успішно — виводиться повідомлення. Якщо ні — виводиться помилка у консоль.
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB підключено'))
  .catch(err => console.error(err));

// Схема користувача
// Створює схему для документа MongoDB з полями:username: обов`язкове, унікальне ім`я користувача.
//password: обов`язковий пароль (зазвичай зберігається в хешованому вигляді).
//publicKey: відкритий ключ RSA, який зберігається для кожного користувача.
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  publicKey: { type: String, required: true }
});
//Створює модель `User` на основі схеми.Тепер можна виконувати операції типу:
//const user = await User.findOne({ username: 'admin' });
const User = mongoose.model('User', userSchema);

// Генерація пари RSA-ключів
// Генерує пару ключів RSA (відкритий і приватний) розміром 2048 біт:
function generateRSAKeyPair() {
  //створює об`єкт з двома ключами.
  const keypair = forge.pki.rsa.generateKeyPair(2048);
  return {
    // перетворює ключи у формат PEM (звичний для зберігання в базі).
    publicKey: forge.pki.publicKeyToPem(keypair.publicKey),
    privateKey: forge.pki.privateKeyToPem(keypair.privateKey)
  };
}

// Реєстрація
//маршрут POST для обробки реєстрації нового користувача.
app.post('/register', [
  //body(...) — це валидація даних:
  //Перевіряє, що username має хоча б 3 символи.
  //І що password має хоча б 6 символів.
  body('username').isLength({ min: 3 }).withMessage('Ім’я користувача має містити щонайменше 3 символи'),
  body('password').isLength({ min: 6 }).withMessage('Пароль має містити щонайменше 6 символів')],
   async (req, res) => {
    // Перевірка, чи є помилки валідації.
    // Якщо так — відправляє клієнту масив з помилками у форматі JSON.
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
    //Витягує username і password із тіла запиту.
  const { username, password } = req.body;
  // Перевіряє, чи є вже користувач із таким іменем у базі.
  // Якщо є — повертає помилку.
  try {
    const userExists = await User.findOne({ username });
    if (userExists) return res.status(400).json({ message: 'Користувач вже існує' });
    const hashedPassword = await bcrypt.hash(password, 10);
    //Генерує пару RSA-ключів: відкритий (піде в базу) і приватний (віддається користувачу).
    const rsaKeys = generateRSAKeyPair();
    //Створює нового користувача в базі з:іменем,хешованим паролем,відкритим RSA-ключем.
    const newUser = new User({ username, password: hashedPassword, publicKey: rsaKeys.publicKey });
    await newUser.save();
//Відповідь клієнту:повідомлення про успішну реєстрацію, приватний ключ, який має бути збережений на боці клієнта 
    res.json({ message: 'Реєстрація успішна', privateKey: rsaKeys.privateKey });
    //Якщо під час реєстрації трапилась помилка — відправляється помилка 500 (внутрішня помилка сервера).
  } catch (err) {
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// Вхід
//маршрут POST /login, який приймає ім`я користувача і пароль із тіла запиту.
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
   //Шукає користувача з таким ім`ям у базі. 
    const user = await User.findOne({ username });
  //Якщо не знайдено — повертає помилку 400 (bad request).
    if (!user) return res.status(400).json({ message: 'Користувача не знайдено' });

    //bcrypt.compare(...) — перевіряє, чи введений пароль відповідає хешу в базі.
    const isPasswordValid = await bcrypt.compare(password, user.password);
    //Якщо пароль неправильний — повертає помилку 401 (unauthorized).
    if (!isPasswordValid) return res.status(401).json({ message: 'Неправильний пароль' });

    //Якщо все добре — генерується JWT-токен із username, який підписується SECRET_KEY. expiresIn: '1h' — токен діє 1 годину.
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    //Відповідь: повідомлення та токен.
    res.json({ message: 'Успішний вхід', token });
  } catch (err) {
    res.status(500).json({ message: 'Помилка сервера' });
  }
});

// Профіль

app.get('/profile', async (req, res) => {
const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: 'Немає токена' });

  //Витягує сам токен (друга частина після "Bearer").
  const token = authHeader.split(' ')[1];
  //Перевіряє справжність токена за допомогою SECRET_KEY.
  jwt.verify(token, SECRET_KEY, async (err, user) => {
    // Якщо токен невалідний або застарів — повертає помилку 403.
    if (err) return res.status(403).json({ message: 'Невірний токен' });

    // Знову шукає користувача по username, який був у токені.
    const dbUser = await User.findOne({ username: user.username });
    if (!dbUser) return res.status(404).json({ message: 'Користувача не знайдено' });

    // Якщо знайдено — повертає привітання та відкритий ключ користувача.
    res.json({ message: `Привіт, ${dbUser.username}`, publicKey: dbUser.publicKey });
  });
});

app.post('/logout', (req, res) => {

  res.json({ message: 'Вихід успішний' });
});
//Вказує Express-у, що всі статичні файли (HTML, CSS, JS, зображення) розміщено у папці public.
app.use(express.static(path.join(__dirname, 'public')));

//При GET-запиті на корінь сайту /, сервер повертає файл index.html з папки public.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//апускає сервер на вказаному порту (з .env або 5000 за замовчуванням) Виводить повідомлення у консоль, що сервер працює.
app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});
