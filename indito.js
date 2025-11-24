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


