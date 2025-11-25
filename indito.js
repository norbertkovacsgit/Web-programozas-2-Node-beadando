const fs = require('fs');
const path = require('path');
const express = require('express');
const compression = require('compression');
const session = require('express-session');
const MySQLStoreFactory = require('express-mysql-session');
const mysql = require('mysql2');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
require('dotenv').config();
const hashPw = (pw) => crypto.createHash('sha512').update(String(pw)).digest('hex');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = path.resolve(__dirname);

app.set('view engine', 'ejs');
app.set('views', path.join(ROOT, 'views'));

function findStaticDir() {
  const hasAssetsOrIndex = (dir) =>
    fs.existsSync(path.join(dir, 'assets')) ||
    fs.existsSync(path.join(dir, 'index.ejs'));

  const envDir = process.env.STATIC_DIR;
  if (envDir) {
    const abs = path.resolve(ROOT, envDir);
    if (hasAssetsOrIndex(abs)) return abs;
    console.warn(`[warn] STATIC_DIR='${envDir}' nem érvényes (nincs assets/ vagy index.html). Autodetekció következik.`);
  }

  const cand = ['template', 'public', 'site', 'web', 'www', 'static', 'dist', 'build', 'docs', '.'];
  for (const c of cand) {
    const abs = path.resolve(ROOT, c);
    if (hasAssetsOrIndex(abs)) return abs;
  }
  return ROOT;
}
const STATIC_ROOT = findStaticDir();

const denyList = new Set(['server', 'node_modules', '.git']);
app.use((req, res, next) => {
  const seg = decodeURI(req.path).split('/').filter(Boolean);
  if (seg.length > 0 && denyList.has(seg[0])) return res.status(404).end();
  next();
});

app.use(compression());
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(express.static(STATIC_ROOT));
app.use('/assets', express.static(path.join(STATIC_ROOT, 'assets')));
app.use('/images', express.static(path.join(STATIC_ROOT, 'images')));
if (!fs.existsSync(path.join(STATIC_ROOT, 'assets'))) {
  const tplAssets = path.join(ROOT, 'template', 'assets');
  const tplImages = path.join(ROOT, 'template', 'images');
  if (fs.existsSync(tplAssets)) app.use('/assets', express.static(tplAssets));
  if (fs.existsSync(tplImages)) app.use('/images', express.static(tplImages));
}

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'user',
  waitForConnections: true,
  connectionLimit: 10,
  multipleStatements: true
});

const MySQLStore = MySQLStoreFactory(session);
const sessionStore = new MySQLStore({}, db.promise());

app.use(session({
  key: 'sid',
  secret: process.env.SESSION_SECRET || 'dev_secret',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

passport.use(new LocalStrategy(
  { usernameField: 'email', passwordField: 'pw' },
  async (email, password, done) => {
    try {
      const emailN = String(email).trim().toLowerCase();
      const [rows] = await db.promise().query(
        'SELECT * FROM users WHERE email = ? LIMIT 1',
        [emailN]
      );
      if (!rows || rows.length === 0) {
        return done(null, false, { message: 'Nincs ilyen email.' });
      }
      const user = rows[0];
      if (user.hash !== hashPw(password)) {
        return done(null, false, { message: 'Hibás jelszó.' });
      }
      return done(null, { id: user.id, username: user.username, role: user.role, email: user.email });
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  if (!user || typeof user.id === 'undefined') {
    return done(new Error('No user id to serialize'));
  }
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [rows] = await db.promise().query(
      'SELECT id, username, role, email, first_name AS firstName, last_name AS lastName FROM users WHERE id = ? LIMIT 1',
      [id]
    );
    if (!rows || rows.length === 0) {
      return done(new Error('User not found'));
    }
    done(null, rows[0]);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
  res.locals.isAuth = req.isAuthenticated();
  res.locals.user = req.user || null;
  res.locals.isAdmin = !!(req.user && req.user.role === 'admin');
  next();
});

const ensureAuth = (req, res, next) => req.isAuthenticated() ? next() : res.redirect('/login');

const ensureRole = (roles) => (req, res, next) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  const ok = Array.isArray(roles) ? roles.includes(req.user.role) : req.user.role === roles;
  return ok ? next() : res.status(403).send('<h1>403 - Nincs jogosultság</h1><p><a href="/">Vissza</a></p>');
};

app.get('/healthz', (req, res) => res.json({ ok: true, staticRoot: path.relative(ROOT, STATIC_ROOT) || '.', port: PORT }));

app.get('/login', (req, res) => {
  const nextUrl = req.query.next || req.session.returnTo || '/';
  if (req.query.next) req.session.returnTo = req.query.next;
  if (req.isAuthenticated()) return res.redirect(nextUrl === '/login' ? '/' : nextUrl);
  return res.render('login', { next: nextUrl });
});

app.get('/register', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/');
  return res.render('register');
});

app.post('/register', async (req, res) => {
  const { uname, firstName, lastName, email, pw } = req.body;

  if (!uname || !firstName || !lastName || !email || !pw) {
    return res.status(400).send('Hiányzó adatok. <a href="/register">Vissza</a>');
  }
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).send('Hibás email formátum. <a href="/register">Vissza</a>');
  }
  if (pw.length < 6) {
    return res.status(400).send('A jelszó legalább 6 karakter legyen. <a href="/register">Vissza</a>');
  }

  const unameN = String(uname).trim();
  const firstN = String(firstName).trim();
  const lastN = String(lastName).trim();
  const emailN = String(email).trim().toLowerCase();

  try {
    const [exists] = await db.promise().query(
      'SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1',
      [unameN, emailN]
    );
    if (exists && exists.length) {
      return res.status(409).send('A felhasználónév vagy az email már foglalt. <a href="/register">Vissza</a>');
    }

    const hash = hashPw(pw);
    const [result] = await db.promise().query(
      'INSERT INTO users (username, first_name, last_name, email, hash, role) VALUES (?,?,?,?,?,?)',
      [unameN, firstN, lastN, emailN, hash, 'user']
    );

    const newUser = {
      id: result.insertId,
      username: unameN,
      role: 'user',
      email: emailN,
      firstName: firstN,
      lastName: lastN
    };

    req.session.regenerate((regenErr) => {
      if (regenErr) console.warn('Session regenerate error:', regenErr);

      req.login(newUser, (err) => {
        if (err) {
          console.error('Auto-login error:', err);
          return res.redirect('/login');
        }
        return res.redirect('/');
      });
    });

  } catch (e) {
    console.error('REGISTER DB ERROR:', e.code, e.sqlMessage || e.message);
    return res.status(500).send('Adatbázis hiba. <a href="/register">Vissza</a>');
  }
});

app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user) => {
    if (err) return next(err);
    if (!user) return res.redirect('/login?err=1');

    req.logIn(user, (err2) => {
      if (err2) return next(err2);
      const dest = req.body.next || req.session.returnTo || '/';
      delete req.session.returnTo;
      return res.redirect(dest === '/login' ? '/' : dest);
    });
  })(req, res, next);
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.redirect('/');
  });
});

app.get('/protected-route', ensureAuth, (req, res) => {
  res.render('protected', { username: req.user.username });
});
