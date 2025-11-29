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

app.get('/devices_page', async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT 
        g.id,
        g.gyarto, g.tipus, g.kijelzo, g.memoria, g.merevlemez,
        g.videovezerlo, g.ar, g.db,
        p.gyarto AS cpu_gyarto, p.tipus AS cpu_tipus,
        o.nev     AS os_nev
      FROM gep g
      LEFT JOIN processzor p ON p.id = g.processzorid
      LEFT JOIN oprendszer o ON o.id = g.oprendszerid
      ORDER BY g.id
    `);

    res.render('devices_page', { list: rows, error: null });
  } catch (e) {
    console.error('Devices query error:', e);
    res.render('devices_page', { list: [], error: 'Hiba történt a készülékek lekérdezésekor.' });
  }
});

async function resolveOsId(db, selectedId, customName) {
  const n = Number(selectedId);
  if (Number.isFinite(n) && n > 0) return n;

  if (String(selectedId) !== 'other') return null;

  const name = String(customName || '').trim();
  if (!name) throw new Error('OS custom name is empty while "other" selected');

  const [found] = await db.promise().query(
    'SELECT id FROM oprendszer WHERE TRIM(nev) = ? LIMIT 1',
    [name]
  );
  if (found && found.length) return found[0].id;

  const [ins] = await db.promise().query(
    'INSERT INTO oprendszer (nev) VALUES (?)',
    [name]
  );
  return ins.insertId;
}

async function resolveCpuId(db, processzorid, cpu_custom_gyarto, cpu_custom_tipus) {
  if (String(processzorid) !== 'other') return Number(processzorid) || null;

  const gyarto = String(cpu_custom_gyarto || '').trim();
  const tipus = String(cpu_custom_tipus || '').trim();

  if (!gyarto || !tipus) return null;

  const [ins] = await db.promise().query(
    'INSERT INTO processzor (gyarto, tipus) VALUES (?, ?)',
    [gyarto, tipus]
  );
  return ins.insertId;
}

app.get(['/crud_page', '/crud_page/:id'], async (req, res) => {
  const editId = req.params.id ? Number(req.params.id) : null;

  try {
    const [rows] = await db.promise().query(`
      SELECT 
        g.*,
        CONCAT(p.gyarto,' ',p.tipus) AS cpu_label,
        o.nev AS os_nev
      FROM gep g
      LEFT JOIN processzor p ON p.id = g.processzorid
      LEFT JOIN oprendszer  o ON o.id = g.oprendszerid
      ORDER BY g.id DESC
    `);

    const [cpus] = await db.promise().query(`
      SELECT id, CONCAT(gyarto,' ',tipus) AS label
      FROM processzor
      ORDER BY gyarto, tipus
    `);
    const [oses] = await db.promise().query(`
      SELECT id, nev
      FROM oprendszer
      ORDER BY nev
    `);

    const editing = editId ? (rows.find(r => r.id === editId) || null) : null;

    return res.render('crud_page', { rows, cpus, oses, editing, error: null });
  } catch (e) {
    console.error('CRUD list error:', e);
    return res.render('crud_page', { rows: [], cpus: [], oses: [], editing: null, error: 'Hiba történt a lista betöltésekor.' });
  }
});

app.post('/crud/create', async (req, res) => {
  try {
    const {
      gyarto, tipus, kijelzo, memoria, merevlemez, videovezerlo, ar,
      processzorid, oprendszerid, db: dbqty,
      os_custom,
      cpu_custom_gyarto, cpu_custom_tipus
    } = req.body;

    const osId = await resolveOsId(db, oprendszerid, os_custom);
    const cpuId = await resolveCpuId(db, processzorid, cpu_custom_gyarto, cpu_custom_tipus);

    await db.promise().query(
      `INSERT INTO gep
       (gyarto, tipus, kijelzo, memoria, merevlemez, videovezerlo, ar, processzorid, oprendszerid, db)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [
        String(gyarto || '').trim(),
        String(tipus || '').trim(),
        Number(kijelzo) || 0,
        Number(memoria) || 0,
        Number(merevlemez) || 0,
        String(videovezerlo || '').trim(),
        Number(ar) || 0,
        (cpuId ?? (Number(processzorid) || null)),
        (osId ?? (Number(oprendszerid) || null)),
        Number(dbqty) || 0
      ]
    );
    res.redirect('/crud_page');
  } catch (e) {
    console.error('CRUD create error:', e);
    res.redirect('/crud_page?err=1');
  }
});

app.post('/crud/update/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    const {
      gyarto, tipus, kijelzo, memoria, merevlemez, videovezerlo, ar,
      processzorid, oprendszerid, db: dbqty,
      os_custom,
      cpu_custom_gyarto, cpu_custom_tipus
    } = req.body;

    const osId = await resolveOsId(db, oprendszerid, os_custom);
    const cpuId = await resolveCpuId(db, processzorid, cpu_custom_gyarto, cpu_custom_tipus);

    await db.promise().query(
      `UPDATE gep
       SET gyarto=?, tipus=?, kijelzo=?, memoria=?, merevlemez=?, videovezerlo=?, ar=?, processzorid=?, oprendszerid=?, db=?
       WHERE id=?`,
      [
        String(gyarto || '').trim(),
        String(tipus || '').trim(),
        Number(kijelzo) || 0,
        Number(memoria) || 0,
        Number(merevlemez) || 0,
        String(videovezerlo || '').trim(),
        Number(ar) || 0,
        (cpuId ?? (Number(processzorid) || null)),
        (osId ?? (Number(oprendszerid) || null)),
        Number(dbqty) || 0,
        id
      ]
    );
    res.redirect('/crud_page');
  } catch (e) {
    console.error('CRUD update error:', e);
    res.redirect('/crud_page?err=1');
  }
});


app.post('/crud/delete/:id', async (req, res) => {
  try {
    const id = Number(req.params.id);
    await db.promise().query(`DELETE FROM gep WHERE id = ?`, [id]);
    res.redirect('/crud_page');
  } catch (e) {
    console.error('CRUD delete error:', e);
    res.redirect('/crud_page?err=1');
  }

  async function resolveCpuId(db, processzorid, cpu_custom_tipus) {
    if (String(processzorid) !== 'other') return Number(processzorid) || null;

    const raw = String(cpu_custom_tipus || '').trim();
    if (!raw) return null;

    const parts = raw.split(/\s+/);
    const gyarto = parts.shift() || 'Egyéb';
    const tipus = parts.length ? parts.join(' ') : raw;

    const [ins] = await db.promise().query(
      'INSERT INTO processzor (gyarto, tipus) VALUES (?, ?)',
      [gyarto, tipus]
    );
    return ins.insertId;
  }
});

app.post('/contact_page', async (req, res) => {
  const { name, email, subject, message } = req.body;

  if (!name || !email || !subject || !message) {
    return res.status(400).render('contact_page', {
      sent: false,
      error: 'Kérjük tölts ki minden mezőt.',
      form: { name, email, subject, message }
    });
  }
  if (!/^\S+@\S+\.\S+$/.test(String(email))) {
    return res.status(400).render('contact_page', {
      sent: false,
      error: 'Hibás email cím.',
      form: { name, email, subject, message }
    });
  }

  try {
    const userId = req.user?.id || null;
    await db.promise().query(
      'INSERT INTO contact_messages (user_id, name, email, subject, message) VALUES (?,?,?,?,?)',
      [userId, String(name).trim(), String(email).trim(), String(subject).trim(), String(message).trim()]
    );
    return res.redirect('/contact_page?sent=1');
  } catch (e) {
    console.error('CONTACT SAVE ERROR:', e);
    return res.status(500).render('contact_page', {
      sent: false,
      error: 'Váratlan hiba történt. Próbáld újra később.',
      form: { name, email, subject, message }
    });
  }
});

app.get('/messages_page', ensureRole(['user', 'admin']), async (req, res) => {
  try {
    const [rows] = await db.promise().query(`
      SELECT 
        id, user_id, name, email, subject, message,
        DATE_FORMAT(created_at, '%Y.%m.%d %H:%i:%s') AS sent_at
      FROM contact_messages
      ORDER BY created_at DESC, id DESC
    `);
    res.render('messages_page', { rows, error: null });
  } catch (e) {
    console.error('LIST MESSAGES ERROR:', e);
    res.render('messages_page', { rows: [], error: 'Nem sikerült lekérdezni az üzeneteket.' });
  }
});

app.get('/contact_page', (req, res) => {
  return res.render('contact_page', {
    sent: req.query.sent === '1',
    error: null,
    form: {}
  });
});

app.get('/admin', ensureRole('admin'), (req, res) => {
  return res.render('admin', { userName: req.user.username });
});

app.get('/', (req, res) => res.render('index'));

app.get('/:page', (req, res, next) => {
  const reserved = new Set([
    'login', 'register', 'logout', 'protected-route', 'admin-route', 'healthz',
    'login-failure', 'userAlreadyExists', 'notAuthorized', 'notAuthorizedAdmin',
    'messages_page', 'devices_page', 'crud_page'
  ]);
  const page = req.params.page;
  if (reserved.has(page)) return next();

  const viewPath = path.join(app.get('views'), page + '.ejs');
  if (fs.existsSync(viewPath)) return res.render(page);
  return next();
});

app.use((req, res) => res.status(404).send('404 - Nem található'));

app.listen(PORT, () => {
  console.log(`Szerver fut: http://localhost:${PORT}`);
  console.log(`Statikus gyökér: ${STATIC_ROOT}`);
});
