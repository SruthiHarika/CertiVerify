#!/usr/bin/env node
'use strict';
/*
 CertVerify Cloud - single-file website + backend.
 Run:  node server.js     (needs Node.js 18 or newer, no npm packages)
 Open: http://localhost:3000

 Environment variables (all optional):
   PORT           port to listen on (hosts like Render set this automatically)
   DATA_DIR       folder for database + uploaded certificate files (use a persistent disk in production)
   SECRET         long random string used to sign login cookies (auto-generated and saved if missing)
   DEMO_PASSWORD  password for the demo university logins created on first start (random if missing)
*/
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const PORT = process.env.PORT || 3000;
const DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const FILES = path.join(DIR, 'files'), DBF = path.join(DIR, 'db.json');
fs.mkdirSync(FILES, { recursive: true });

// ---------- helpers ----------
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const rb = n => crypto.randomBytes(n).toString('hex').toUpperCase();
const now = () => new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
const SECRET = process.env.SECRET || (() => {
  const f = path.join(DIR, 'secret.key');
  try { return fs.readFileSync(f, 'utf8'); } catch { const k = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(f, k, { mode: 0o600 }); return k; }
})();

// ---------- database (JSON file; swap these few functions for PostgreSQL/MySQL in production) ----------
const COLS = ['accts', 'unis', 'studs', 'certs', 'vlogs', 'alogs', 'vrec', 'mycerts'];
let db; try { db = JSON.parse(fs.readFileSync(DBF, 'utf8')); } catch { db = null; }
const fresh = !db; if (!db) db = {};
COLS.forEach(c => db[c] = db[c] || {});
let dirty = false; const save = () => { dirty = true; };
const flush = () => { if (!dirty) return; dirty = false; fs.writeFileSync(DBF + '.tmp', JSON.stringify(db)); fs.renameSync(DBF + '.tmp', DBF); };
setInterval(flush, 1000).unref();
['SIGINT', 'SIGTERM'].forEach(s => process.on(s, () => { flush(); process.exit(0); }));
const list = c => Object.entries(db[c]).map(([id, d]) => ({ id, ...d }));
const aid = e => sha(e).slice(0, 24);

// ---------- passwords & sessions ----------
const hashPw = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');
const samePw = (p, u) => { const a = Buffer.from(hashPw(p, u.salt)), b = Buffer.from(u.ph); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const mkAcct = (email, name, role, pass, extra = {}) => { const salt = rb(8); return { email, name, role, salt, ph: hashPw(pass, salt), on: true, at: now(), ...extra }; };
const sign = o => { const b = Buffer.from(JSON.stringify(o)).toString('base64url'); return b + '.' + crypto.createHmac('sha256', SECRET).update(b).digest('base64url'); };
const unsign = t => {
  if (!t) return null; const [b, s] = t.split('.'); if (!s) return null;
  const e = crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
  if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
  try { const o = JSON.parse(Buffer.from(b, 'base64url')); return o.exp > Date.now() ? o : null; } catch { return null; }
};
const cookie = (req, v, age) => `tok=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}` + ((req.socket.encrypted || req.headers['x-forwarded-proto'] === 'https') ? '; Secure' : '');
const getUser = req => {
  const m = /(?:^|; )tok=([^;]+)/.exec(req.headers.cookie || ''), s = unsign(m && m[1]), u = s && db.accts[s.id];
  return u && u.on ? { id: s.id, ...u } : null;
};
const pub = u => u && { id: u.id, email: u.email, name: u.name, role: u.role, uni: u.uni };
const session = (req, res, id) => res.setHeader('Set-Cookie', cookie(req, sign({ id, exp: Date.now() + 288e5 }), 28800));

// ---------- validation, errors, rate limits ----------
const E = (status, msg) => Object.assign(new Error(msg), { status });
const str = (v, min, max, name) => { v = String(v ?? '').trim(); if (v.length < min || v.length > max) throw E(400, name + ' is invalid'); return v; };
const email = v => { v = str(v, 5, 120, 'Email').toLowerCase(); if (!/^\S+@\S+\.\S+$/.test(v)) throw E(400, 'Email is invalid'); return v; };
const pass = v => { v = String(v ?? ''); if (v.length < 8 || v.length > 100) throw E(400, 'Password must be 8-100 characters'); return v; };
const newKey = () => rb(8) + '-' + rb(8);
const fl = new Map(), rl = new Map();
const blocked = k => { const t = Date.now(), a = (fl.get(k) || []).filter(x => t - x < 9e5); fl.set(k, a); return a.length >= 8; };
const fail = k => { const a = fl.get(k) || []; a.push(Date.now()); fl.set(k, a); };
const rate = (k, max, ms) => { const t = Date.now(), a = (rl.get(k) || []).filter(x => t - x < ms); a.push(t); rl.set(k, a); if (a.length > max) throw E(429, 'Too many requests, please slow down'); };
setInterval(() => { fl.clear(); rl.clear(); }, 36e5).unref();
const aud = (u, a, rel = '-', res = 'OK') => { db.alogs[rb(8)] = { a, u: u ? u.email : 'public', r: u ? u.role : 'public', rel, res, at: now(), ts: Date.now() }; save(); };

// ---------- demo data (first start only) ----------
const SEED = {
 "unis": {
  "NECN": {
   "name": "Narayana Engineering College, Nellore",
   "on": true,
   "at": "06/10/2026, 15:00:00"
  },
  "NECG": {
   "name": "Narayana Engineering College, Gudur",
   "on": true,
   "at": "06/10/2026, 15:00:00"
  },
  "GIST": {
   "name": "Geethanjali Institute of Science and Technology",
   "on": true,
   "at": "06/10/2026, 15:00:00"
  },
  "NBKR": {
   "name": "NBKR Institute of Science and Technology",
   "on": true,
   "at": "06/10/2026, 15:00:00"
  },
  "SVCN": {
   "name": "Sree Venkateswara College of Engineering",
   "on": true,
   "at": "06/10/2026, 15:00:00"
  }
 },
 "studs": {
  "52ef46e563cd7c08532e": {
   "uni": "GIST",
   "name": "Ananya Reddy",
   "roll": "24GI1A0512",
   "email": "ananya512@example.com",
   "course": "CSE"
  },
  "d59e2cf663b6cb9b5b1a": {
   "uni": "GIST",
   "name": "Karthik Naidu",
   "roll": "24GI1A0527",
   "email": "karthik527@example.com",
   "course": "ECE"
  },
  "06f74db7f39f745013e5": {
   "uni": "NBKR",
   "name": "Pavan Kalyan Yadav",
   "roll": "23KB1A0431",
   "email": "pavan431@example.com",
   "course": "CSE"
  },
  "89d01875f9dfaf1c41fa": {
   "uni": "NBKR",
   "name": "Divya Sree Chowdary",
   "roll": "23KB1A0446",
   "email": "divya446@example.com",
   "course": "IT"
  },
  "773d95a7053b556ef139": {
   "uni": "NECG",
   "name": "Harsha Vardhan",
   "roll": "24NG1A0518",
   "email": "harsha518@example.com",
   "course": "CSE"
  },
  "07cdd4a400e0ae20d86a": {
   "uni": "NECG",
   "name": "Meghana Rao",
   "roll": "24NG1A0532",
   "email": "meghana532@example.com",
   "course": "AIML"
  },
  "5f89da533fbe9beed1ff": {
   "uni": "SVCN",
   "name": "Suresh Babu",
   "roll": "23SV1A0415",
   "email": "suresh415@example.com",
   "course": "EEE"
  },
  "2b9d0e6da50e9058dffd": {
   "uni": "SVCN",
   "name": "Keerthi Priya",
   "roll": "23SV1A0429",
   "email": "keerthi429@example.com",
   "course": "CSE"
  },
  "1z4z2ean3pif9pr0le0o": {
   "uni": "NECN",
   "name": "Blessy Sathvika",
   "roll": "24711A33224",
   "email": "blessy@gmail.com",
   "course": "AIML"
  },
  "60kqnfihfug684arwmmb": {
   "uni": "NECN",
   "name": "Sruthi Harika",
   "roll": "25715A3302",
   "email": "sruthiharika1726@gmail.com",
   "course": "AIML"
  },
  "jqv1vwzvfqgc3mjdmrha": {
   "uni": "NECN",
   "name": "Bhavitha Kumari",
   "roll": "24711A3306",
   "email": "bhavithakumari@gmail.com",
   "course": "AIML"
  },
  "vkc4bjzq4bkl8qtnxhwn": {
   "uni": "NECN",
   "name": "Asritha",
   "roll": "24711A3321",
   "email": "asrithagarika@gmail.com",
   "course": "AIML"
  }
 },
 "certs": {
  "CERT-2026-32998D": {
   "cid": "CERT-2026-32998D",
   "studId": "1z4z2ean3pif9pr0le0o",
   "name": "Blessy Sathvika",
   "roll": "24711A33224",
   "course": "Machine Learning Fundamentals",
   "degree": "B.Tech - AIML",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NECN",
   "uniName": "Narayana Engineering College, Nellore",
   "hash": "7d84bf7a8517c21aefc43bec1b4e5826859b7c38e1a0a2b04a9787e7205cbac6",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-204FD1": {
   "cid": "CERT-2026-204FD1",
   "studId": "60kqnfihfug684arwmmb",
   "name": "Sruthi Harika",
   "roll": "25715A3302",
   "course": "Python for Data Science",
   "degree": "B.Tech - AIML",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NECN",
   "uniName": "Narayana Engineering College, Nellore",
   "hash": "ebb085c3c26c4e813713e91e23cb9af23380ccf649c435f1a5e1fe717c79d74c",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-512687": {
   "cid": "CERT-2026-512687",
   "studId": "jqv1vwzvfqgc3mjdmrha",
   "name": "Bhavitha Kumari",
   "roll": "24711A3306",
   "course": "Deep Learning Essentials",
   "degree": "B.Tech - AIML",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NECN",
   "uniName": "Narayana Engineering College, Nellore",
   "hash": "2308b15a9bec9a3ba6f84643f358ec50d33ee22e904517efde30ddf0e47ec25a",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-5FFAC7": {
   "cid": "CERT-2026-5FFAC7",
   "studId": "vkc4bjzq4bkl8qtnxhwn",
   "name": "Asritha",
   "roll": "24711A3321",
   "course": "Artificial Intelligence Workshop",
   "degree": "B.Tech - AIML",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NECN",
   "uniName": "Narayana Engineering College, Nellore",
   "hash": "86c76cd7316db7850b894409d1763e92442cab7eff6419471c60d13efff79e86",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-C563B0": {
   "cid": "CERT-2026-C563B0",
   "studId": "52ef46e563cd7c08532e",
   "name": "Ananya Reddy",
   "roll": "24GI1A0512",
   "course": "Full Stack Web Development",
   "degree": "B.Tech - CSE",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "GIST",
   "uniName": "Geethanjali Institute of Science and Technology",
   "hash": "e541331d3bf6ad81d3980374c76ee9eab5357747ff837a7f51c39fcc5926bab5",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-1D26D9": {
   "cid": "CERT-2026-1D26D9",
   "studId": "d59e2cf663b6cb9b5b1a",
   "name": "Karthik Naidu",
   "roll": "24GI1A0527",
   "course": "Embedded Systems Design",
   "degree": "B.Tech - ECE",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "GIST",
   "uniName": "Geethanjali Institute of Science and Technology",
   "hash": "313128107a5d49a815362bb2651b72dfe5a5265fbf258e39f1ab66c9a0bb7c70",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-A70B4A": {
   "cid": "CERT-2026-A70B4A",
   "studId": "06f74db7f39f745013e5",
   "name": "Pavan Kalyan Yadav",
   "roll": "23KB1A0431",
   "course": "Cloud Computing Foundations",
   "degree": "B.Tech - CSE",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NBKR",
   "uniName": "NBKR Institute of Science and Technology",
   "hash": "67678a14df9bf1928f72e6807d71d9c3ad4a5e31bd386dc1a88a1627c7ef3263",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-EBBBB6": {
   "cid": "CERT-2026-EBBBB6",
   "studId": "89d01875f9dfaf1c41fa",
   "name": "Divya Sree Chowdary",
   "roll": "23KB1A0446",
   "course": "Cyber Security Basics",
   "degree": "B.Tech - IT",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NBKR",
   "uniName": "NBKR Institute of Science and Technology",
   "hash": "5cd9fd4aed84e44565fa48d89e30403b3858618edfe0a3a9838be08b56447985",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-F3C420": {
   "cid": "CERT-2026-F3C420",
   "studId": "773d95a7053b556ef139",
   "name": "Harsha Vardhan",
   "roll": "24NG1A0518",
   "course": "Data Structures and Algorithms",
   "degree": "B.Tech - CSE",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NECG",
   "uniName": "Narayana Engineering College, Gudur",
   "hash": "b078399b0750a34846b792fddc7e46e64e8fb37046cfa5c23a197867c068b91a",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-1B6393": {
   "cid": "CERT-2026-1B6393",
   "studId": "07cdd4a400e0ae20d86a",
   "name": "Meghana Rao",
   "roll": "24NG1A0532",
   "course": "Natural Language Processing",
   "degree": "B.Tech - AIML",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "NECG",
   "uniName": "Narayana Engineering College, Gudur",
   "hash": "040a2ccb4607b9395745e1811f19c095587a48e68180e7520661d50a043ea263",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-9D908F": {
   "cid": "CERT-2026-9D908F",
   "studId": "5f89da533fbe9beed1ff",
   "name": "Suresh Babu",
   "roll": "23SV1A0415",
   "course": "Power Systems Internship",
   "degree": "B.Tech - EEE",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "SVCN",
   "uniName": "Sree Venkateswara College of Engineering",
   "hash": "3619a02aaddff9c50e652819dbd8af950bfcbbc7e95ea921530990dd3c910172",
   "fileId": "",
   "fileUrl": "",
   "status": "Verified",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  },
  "CERT-2026-833BD0": {
   "cid": "CERT-2026-833BD0",
   "studId": "2b9d0e6da50e9058dffd",
   "name": "Keerthi Priya",
   "roll": "23SV1A0429",
   "course": "IoT Project Certification",
   "degree": "B.Tech - CSE",
   "year": "2026",
   "date": "15-08-2026",
   "uni": "SVCN",
   "uniName": "Sree Venkateswara College of Engineering",
   "hash": "63d55d7fe2e27c291183c967e83f16d592e7575a8ba8c12f5d449111ebb98f5f",
   "fileId": "",
   "fileUrl": "",
   "status": "Revoked",
   "at": "06/10/2026, 15:30:00",
   "ts": 1759764600000
  }
 }
};
if (fresh) {
  Object.assign(db.unis, SEED.unis); Object.assign(db.studs, SEED.studs); Object.assign(db.certs, SEED.certs);
  console.log('\nDemo university logins (change or deactivate them in Admin Panel > Users):');
  for (const code in SEED.unis) {
    const em = code.toLowerCase() + '@university.demo', pw = process.env.DEMO_PASSWORD || rb(5);
    db.accts[aid(em)] = mkAcct(em, SEED.unis[code].name, 'university', pw, { uni: code });
    console.log('  ' + code.padEnd(5) + ' ' + em + '   password: ' + pw);
  }
  save(); flush();
}

// ---------- website (HTML is stored at the bottom of this same file) ----------
const SRC = fs.readFileSync(__filename, 'utf8'), A = '/*==HTML' + '_START==\n', Z = '\n==HTML' + '_END==*/';
const HTML = SRC.slice(SRC.lastIndexOf(A) + A.length, SRC.lastIndexOf(Z));
const CSP = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
const json = (res, code, o) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
const body = req => new Promise((ok, no) => {
  let n = 0; const c = [];
  req.on('data', d => { n += d.length; if (n > 8.5e6) { no(E(413, 'Request too large')); req.destroy(); } else c.push(d); });
  req.on('end', () => { try { ok(c.length ? JSON.parse(Buffer.concat(c)) : {}); } catch { no(E(400, 'Bad JSON')); } });
  req.on('error', no);
});
const MAGIC = { pdf: b => b.slice(0, 4).toString() === '%PDF', png: b => b.slice(0, 4).toString('hex') === '89504e47', jpg: b => b.slice(0, 3).toString('hex') === 'ffd8ff' };

// ---------- API ----------
async function api(M, p, b, me, req, res, ip) {
  const need = (...r) => { if (!me) throw E(401, 'Please login'); if (r.length && !r.includes(me.role)) throw E(403, 'Not allowed'); return me; };
  const mine = () => db.accts[me.id]; let m;
  const chkPw = () => { if (!samePw(String(b.current ?? b.password ?? ''), mine())) throw E(403, 'Current password is wrong'); };

  if (M === 'GET' && p === '/api/me') return { user: pub(me), adminExists: list('accts').some(a => a.role === 'admin') };

  // --- authentication ---
  if (M === 'POST' && p === '/api/auth/login') {
    const em = str(b.email, 3, 120, 'Email').toLowerCase(), k = ip + em;
    if (blocked(k)) throw E(429, 'Too many failed attempts. Try again in 15 minutes.');
    const id = aid(em), a = db.accts[id];
    if (!a || a.role !== b.role || !a.on || !samePw(String(b.password || ''), a)) { fail(k); aud(null, 'Login failed', em, 'Failed'); throw E(401, 'Invalid credentials for this portal'); }
    session(req, res, id); aud({ email: em, role: a.role }, 'Login', em); return { user: pub({ id, ...a }) };
  }
  if (M === 'POST' && p === '/api/auth/logout') { res.setHeader('Set-Cookie', cookie(req, '', 0)); return { ok: 1 }; }
  if (M === 'POST' && p === '/api/auth/register') {
    const em = email(b.email), name = str(b.name, 1, 80, 'Name'), pw = pass(b.password), id = aid(em);
    if (db.accts[id]) throw E(409, 'Email already registered');
    db.accts[id] = mkAcct(em, name, 'user', pw); save(); aud(null, 'User registration', em); return { ok: 1 };
  }
  if (M === 'POST' && p === '/api/auth/setup') {
    if (list('accts').some(a => a.role === 'admin')) throw E(403, 'Admin already exists');
    const em = email(b.email), name = str(b.name, 1, 80, 'Name'), pw = pass(b.password), k = newKey();
    if (db.accts[aid(em)]) throw E(409, 'That email is already in use');
    db.accts[aid(em)] = mkAcct(em, name, 'admin', pw, { rk: sha(k) }); save(); aud(null, 'Admin created', em); return { key: k };
  }
  if (M === 'POST' && p === '/api/auth/forgot') {
    const em = email(b.email), k = ip + 'f' + em;
    if (blocked(k)) throw E(429, 'Too many failed attempts. Try again in 15 minutes.');
    const a = db.accts[aid(em)], key = sha(String(b.key || '').trim().toUpperCase());
    if (!a || a.role !== 'admin' || !a.rk || a.rk !== key) { fail(k); aud(null, 'Admin recovery failed', em, 'Failed'); throw E(401, 'Email or recovery key is wrong'); }
    const pw = pass(b.password), nk = newKey(); a.salt = rb(8); a.ph = hashPw(pw, a.salt); a.rk = sha(nk); save();
    aud({ email: em, role: 'admin' }, 'Admin password recovered', em); return { key: nk };
  }

  // --- own account ---
  if (M === 'POST' && p === '/api/me/update') {
    need(); chkPw(); const a = mine(), em = email(b.email), name = str(b.name, 1, 80, 'Name'), nid = aid(em);
    if (nid !== me.id) {
      if (db.accts[nid]) throw E(409, 'That email is already in use');
      db.accts[nid] = { ...a, email: em, name }; delete db.accts[me.id];
      for (const c of ['vrec', 'mycerts']) for (const d of Object.values(db[c])) if (d.owner === a.email) d.owner = em;
    } else { a.name = name; a.email = em; }
    save(); aud({ email: em, role: me.role }, 'Account details edited', em); session(req, res, nid);
    return { user: pub({ id: nid, ...db.accts[nid] }) };
  }
  if (M === 'POST' && p === '/api/me/password') {
    need(); chkPw(); const a = mine(), pw = pass(b.new); a.salt = rb(8); a.ph = hashPw(pw, a.salt); save(); aud(me, 'Password changed', me.email); return { ok: 1 };
  }
  if (M === 'POST' && p === '/api/me/recovery') {
    need('admin'); chkPw(); const k = newKey(); mine().rk = sha(k); save(); aud(me, 'Recovery key regenerated', me.email); return { key: k };
  }
  if (M === 'POST' && p === '/api/me/reset') {
    need('admin'); chkPw(); delete db.accts[me.id]; save(); aud(me, 'Admin account reset', me.email); res.setHeader('Set-Cookie', cookie(req, '', 0)); return { ok: 1 };
  }

  // --- admin: accounts and universities ---
  if (M === 'GET' && p === '/api/admin/accts') { need('admin'); return list('accts').map(({ id, email, name, role, on, at }) => ({ id, email, name, role, on, at })); }
  if (M === 'POST' && (m = /^\/api\/admin\/accts\/(\w+)\/toggle$/.exec(p))) {
    need('admin'); const a = db.accts[m[1]]; if (!a || a.role === 'admin') throw E(404, 'Not found'); a.on = !a.on; save(); aud(me, 'User status', a.email); return { ok: 1 };
  }
  if (M === 'POST' && (m = /^\/api\/admin\/accts\/(\w+)\/reset$/.exec(p))) {
    need('admin'); const a = db.accts[m[1]]; if (!a || a.role === 'admin') throw E(404, 'Not found'); const pw = pass(b.password);
    a.salt = rb(8); a.ph = hashPw(pw, a.salt); save(); aud(me, 'Password reset by admin', a.email); return { ok: 1 };
  }
  if (M === 'POST' && p === '/api/admin/unis') {
    need('admin'); const name = str(b.name, 2, 120, 'University name'), code = str(b.code, 2, 10, 'Code').toUpperCase(), em = email(b.email), pw = pass(b.password);
    if (!/^[A-Z0-9]+$/.test(code)) throw E(400, 'Code must be letters/numbers'); if (db.accts[aid(em)]) throw E(409, 'That email is already in use');
    db.unis[code] = { ...(db.unis[code] || { on: true, at: now() }), name };
    db.accts[aid(em)] = mkAcct(em, name, 'university', pw, { uni: code }); save(); aud(me, 'University added', code); return { ok: 1 };
  }
  if (M === 'POST' && (m = /^\/api\/admin\/unis\/([\w-]+)\/toggle$/.exec(p))) {
    need('admin'); const u = db.unis[m[1]]; if (!u) throw E(404, 'Not found'); u.on = !u.on; save(); aud(me, 'University status', m[1]); return { ok: 1 };
  }
  if (M === 'GET' && p === '/api/unis') {
    need('admin', 'university'); return list('unis').filter(u => me.role === 'admin' || u.id === me.uni);
  }

  // --- students (university) ---
  if (p === '/api/studs' && M === 'GET') { need('admin', 'university'); return list('studs').filter(s => me.role === 'admin' || s.uni === me.uni); }
  if (p === '/api/studs' && M === 'POST') {
    need('university'); if (!db.unis[me.uni]?.on) throw E(403, 'University is deactivated');
    const s = { uni: me.uni, name: str(b.name, 1, 80, 'Name'), roll: str(b.roll, 1, 30, 'Roll number'), email: String(b.email || '').trim().slice(0, 120), course: String(b.course || '').trim().slice(0, 60) };
    db.studs[rb(10)] = s; save(); aud(me, 'Student added', s.roll); return { ok: 1 };
  }
  if (M === 'DELETE' && (m = /^\/api\/studs\/(\w+)$/.exec(p))) {
    need('university'); const s = db.studs[m[1]]; if (!s || s.uni !== me.uni) throw E(404, 'Not found'); delete db.studs[m[1]]; save(); aud(me, 'Student deleted', s.roll); return { ok: 1 };
  }

  // --- certificates ---
  if (M === 'GET' && p === '/api/certs') {
    need();
    if (me.role === 'user') return list('mycerts').filter(x => x.owner === me.email).map(x => {
      const c = db.certs[x.cid]; if (!c) return null; const { fileId, fileUrl, ...rest } = c; return { id: x.cid, ...rest, mid: x.id, savedAt: x.at, sts: x.ts };
    }).filter(Boolean);
    return list('certs').filter(c => me.role === 'admin' || c.uni === me.uni);
  }
  if (M === 'POST' && p === '/api/certs/issue') {
    need('university'); const u = db.unis[me.uni]; if (!u?.on) throw E(403, 'University is deactivated');
    const s = db.studs[b.studId]; if (!s || s.uni !== me.uni) throw E(400, 'Select a student');
    const course = str(b.course, 1, 120, 'Course'), degree = String(b.degree || '').trim().slice(0, 80), year = String(b.year || '').trim().slice(0, 10), d = String(b.date || '');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) throw E(400, 'Issue date is invalid');
    const ext = (/\.(pdf|png|jpe?g)$/i.exec(String(b.fileName || '')) || [])[1]; if (!ext) throw E(400, 'Only PDF, JPG or PNG files are allowed');
    const buf = Buffer.from(String(b.fileB64 || ''), 'base64'); if (!buf.length || buf.length > 5e6) throw E(400, 'File must be under 5 MB');
    const kind = ext.toLowerCase().replace('jpeg', 'jpg'); if (!MAGIC[kind](buf)) throw E(400, 'File content does not match its type');
    const hash = crypto.createHash('sha256').update(buf).digest('hex'), dup = list('certs').find(c => c.hash === hash);
    if (dup) throw E(409, 'This file is already registered as ' + dup.cid);
    let cid; do cid = 'CERT-' + new Date().getFullYear() + '-' + rb(3); while (db.certs[cid]);
    const fileId = rb(16) + '.' + kind; fs.writeFileSync(path.join(FILES, fileId), buf);
    const c = { cid, studId: b.studId, name: s.name, roll: s.roll, course, degree, year, date: d.split('-').reverse().join('-'), uni: me.uni, uniName: u.name, hash, fileId, fileUrl: '/files/' + fileId, status: 'Verified', at: now(), ts: Date.now() };
    db.certs[cid] = c; save(); aud(me, 'Certificate issued', cid); return { c: { id: cid, ...c } };
  }
  if (M === 'POST' && (m = /^\/api\/certs\/([\w-]+)\/toggle$/.exec(p))) {
    need('admin', 'university'); const c = db.certs[m[1]]; if (!c || (me.role === 'university' && c.uni !== me.uni)) throw E(404, 'Not found');
    c.status = c.status === 'Revoked' ? 'Verified' : 'Revoked'; save(); aud(me, 'Certificate ' + (c.status === 'Revoked' ? 'revoked' : 'restored'), c.cid); return { ok: 1 };
  }
  if (M === 'DELETE' && (m = /^\/api\/certs\/([\w-]+)$/.exec(p))) {
    need('admin'); const c = db.certs[m[1]]; if (!c) throw E(404, 'Not found');
    if (c.fileId) fs.rm(path.join(FILES, c.fileId), () => { }); delete db.certs[m[1]]; save(); aud(me, 'Certificate deleted', m[1]); return { ok: 1 };
  }

  // --- user history, logs ---
  if (M === 'GET' && p === '/api/vrec') { need('user'); return list('vrec').filter(x => x.owner === me.email); }
  if (M === 'DELETE' && (m = /^\/api\/mycerts\/(\w+)$/.exec(p))) {
    need('user'); const d = db.mycerts[m[1]]; if (!d || d.owner !== me.email) throw E(404, 'Not found'); delete db.mycerts[m[1]]; save(); return { ok: 1 };
  }
  if (M === 'GET' && p === '/api/vlogs') { need('admin'); return list('vlogs').sort((a, b) => b.ts - a.ts).slice(0, 500); }
  if (M === 'GET' && p === '/api/alogs') { need('admin'); return list('alogs').sort((a, b) => b.ts - a.ts).slice(0, 500); }

  // --- public verification engine ---
  if (M === 'POST' && p === '/api/verify') {
    rate('v' + ip, 60, 6e4);
    const id = String(b.id || '').trim(), h = String(b.hash || '').toLowerCase();
    if (id && !/^[\w-]{3,40}$/.test(id)) throw E(400, 'Invalid ID'); if (h && !/^[0-9a-f]{64}$/.test(h)) throw E(400, 'Invalid file hash');
    if (!id && !h) throw E(400, 'Enter an ID or choose a file');
    const meth = ['ID', 'QR', 'Upload'].includes(b.method) ? b.method : 'ID', cs = list('certs');
    let c = id && cs.find(x => x.cid.toLowerCase() === id.toLowerCase()); if (!c && h) c = cs.find(x => x.hash === h);
    const s = !c ? 'NOTFOUND' : c.status === 'Revoked' ? 'REVOKED' : (h && h !== c.hash) ? 'INTEGRITY' : 'VERIFIED', t = now();
    const rec = { cid: c ? c.cid : id || '-', m: meth, res: s, at: t, ts: Date.now(), u: me ? me.role : 'public', who: me ? me.email : '', ip, name: c ? c.name : '', course: c ? c.course : '' };
    db.vlogs[rb(8)] = rec;
    if (me && me.role === 'user') {
      db.vrec[rb(8)] = { ...rec, owner: me.email };
      if (s === 'VERIFIED') db.mycerts[sha(me.email + c.cid).slice(0, 24)] = { owner: me.email, cid: c.cid, at: t, ts: Date.now() };
    }
    save(); return { s, t, h: h || null, c: c && s !== 'NOTFOUND' ? { cid: c.cid, name: c.name, course: c.course, uniName: c.uniName, date: c.date, status: c.status } : null };
  }
  throw E(404, 'Not found');
}

// ---------- stored certificate files (admin / owning university only) ----------
function sendFile(req, res, id) {
  const me = getUser(req); if (!me || !['admin', 'university'].includes(me.role)) throw E(401, 'Login required');
  if (!/^[A-F0-9]{32}\.(pdf|png|jpg)$/.test(id)) throw E(404, 'Not found');
  const c = list('certs').find(x => x.fileId === id); if (!c || (me.role === 'university' && c.uni !== me.uni)) throw E(404, 'Not found');
  const t = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg' }[id.split('.').pop()];
  res.writeHead(200, { 'Content-Type': t, 'Content-Security-Policy': 'sandbox', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(path.join(FILES, id)).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const p = new URL(req.url, 'http://x').pathname, M = req.method;
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'same-origin');
  try {
    if (M === 'GET' && (p === '/' || p === '/index.html')) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Security-Policy': CSP }); return res.end(HTML); }
    if (M === 'GET' && p === '/healthz') return json(res, 200, { ok: 1 });
    if (M === 'GET' && p.startsWith('/files/')) return sendFile(req, res, p.slice(7));
    if (!p.startsWith('/api/')) throw E(404, 'Not found');
    if (M !== 'GET') { const o = req.headers.origin; if (o && new URL(o).host !== req.headers.host) throw E(403, 'Bad origin'); }
    const me = getUser(req), b = (M === 'GET' || M === 'DELETE') ? {} : await body(req);
    const ip = sha(String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim() + SECRET).slice(0, 10);
    json(res, 200, await api(M, p, b, me, req, res, ip));
  } catch (e) {
    if (res.headersSent) return res.end();
    json(res, e.status || 500, { error: e.status ? e.message : 'Server error' }); if (!e.status) console.error(e);
  }
});
server.listen(PORT, () => console.log('\nCertVerify Cloud is running -> http://localhost:' + PORT));

/*==HTML_START==
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>CertVerify Cloud</title>
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jsQR/1.4.0/jsQR.min.js"></script>
<style>
:root{--a:#2563eb;--t:#1e1b4b;--m:#64748b;--g:#059669;--y:#d97706;--r:#e11d48;box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
*{box-sizing:border-box}html{height:100%}body{margin:0;min-height:100%;color:var(--t);font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;background:radial-gradient(circle at 12% 18%,#f472b6aa,transparent 40%),radial-gradient(circle at 88% 12%,#22d3eeaa,transparent 38%),radial-gradient(circle at 70% 90%,#a78bfaaa,transparent 45%),linear-gradient(135deg,#4f46e5,#2563eb 50%,#0ea5e9);background-attachment:fixed}
a{color:var(--a)}.top{display:flex;flex-wrap:wrap;align-items:center;gap:6px;padding:12px 20px;color:#fff}.top b{font-size:19px;margin-right:auto}.top a{color:#fff;text-decoration:none;padding:6px 12px;border-radius:99px;background:#ffffff26}
.wrap{max-width:1050px;margin:0 auto;padding:14px 16px 40px}.card{background:#fffffff0;backdrop-filter:blur(10px);border-radius:18px;padding:20px;box-shadow:0 10px 30px #1e1b4b33;margin-bottom:14px;animation:f .35s}@keyframes f{from{opacity:0;transform:translateY(8px)}}
.hero{text-align:center;color:#fff;padding:34px 10px}.hero h1{font-size:clamp(28px,5vw,46px);margin:0}.hero p{opacity:.92}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.cc{text-align:center}.ic{font-size:38px}
.btn{display:inline-block;background:var(--a);color:#fff!important;border:0;padding:9px 18px;border-radius:12px;font-weight:700;cursor:pointer;text-decoration:none;font-size:14px;transition:.2s}.btn:hover{transform:translateY(-2px);box-shadow:0 6px 14px #0003}.btn.o{background:none;border:2px solid var(--a);color:var(--a)!important}.btn.s{padding:4px 10px;font-size:12px}.btn.r{background:var(--r)}.btn.g{background:var(--g)}
label{display:block;font-size:12px;font-weight:700;margin:10px 0 3px}input,select{width:100%;padding:10px;border:1.5px solid #c7d2fe;border-radius:10px;background:#fff;color:var(--t);font:inherit}input:focus,select:focus{outline:3px solid #a5b4fc}
.lay{display:flex;gap:14px;padding:0 16px 30px;max-width:1250px;margin:0 auto}.side{width:210px;flex:none;background:#fffffff0;border-radius:18px;padding:14px;align-self:flex-start;box-shadow:0 10px 30px #1e1b4b33}.side h4{margin:0 0 8px;color:var(--a)}
.side a{display:block;padding:9px 10px;border-radius:10px;color:var(--t);text-decoration:none;margin-bottom:3px}.side a.on,.side a:hover{background:var(--a);color:#fff}.main{flex:1;min-width:0}.main h2{color:#fff;margin:6px 0 12px}
@media(max-width:760px){.lay{flex-direction:column}.side{width:100%;display:flex;flex-wrap:wrap;gap:4px}.side h4{width:100%}}
.sc{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px;border-bottom:1px solid #e0e7ff;white-space:nowrap}
.bd{padding:2px 10px;border-radius:99px;font-size:11px;font-weight:700;color:#fff}.Verified,.Active{background:var(--g)}.Revoked,.Inactive{background:var(--r)}
.num{font-size:34px;font-weight:800;color:var(--a);margin:0}.res{text-align:center;border-top:8px solid}.res.G{border-color:var(--g)}.res.Y{border-color:var(--y)}.res.R{border-color:var(--r)}.res .ic{font-size:56px}.dl{text-align:left;max-width:440px;margin:10px auto}.dl div{display:flex;justify-content:space-between;gap:10px;padding:5px 0;border-bottom:1px dashed #c7d2fe}
.bar{height:14px;border-radius:7px;margin:4px 0;background:var(--a)}code{font-size:11px;word-break:break-all}#toast{position:fixed;right:14px;bottom:14px;background:var(--t);color:#fff;padding:10px 16px;border-radius:12px;display:none;z-index:9}
.md{position:fixed;inset:0;background:#0009;display:flex;align-items:center;justify-content:center;z-index:8;padding:14px}.md .card{max-width:520px;width:100%;max-height:90vh;overflow:auto}
body{background:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1200 800' preserveAspectRatio='xMidYMid slice'%3E%3Cdefs%3E%3Cfilter id='b'%3E%3CfeGaussianBlur stdDeviation='50'/%3E%3C/filter%3E%3Cpattern id='d' width='28' height='28' patternUnits='userSpaceOnUse'%3E%3Ccircle cx='2' cy='2' r='1.4' fill='%236366f1' opacity='.18'/%3E%3C/pattern%3E%3C/defs%3E%3Cg filter='url(%23b)' opacity='.55'%3E%3Ccircle cx='140' cy='120' r='190' fill='%23f9a8d4'/%3E%3Ccircle cx='1080' cy='90' r='210' fill='%2367e8f9'/%3E%3Ccircle cx='980' cy='700' r='230' fill='%23c4b5fd'/%3E%3Ccircle cx='200' cy='720' r='200' fill='%2386efac'/%3E%3Ccircle cx='620' cy='380' r='170' fill='%23fde68a'/%3E%3C/g%3E%3Crect width='1200' height='800' fill='url(%23d)'/%3E%3Cpath d='M0 640 C200 580 360 700 600 650 S1000 580 1200 640 V800 H0Z' fill='%23fff' opacity='.45'/%3E%3Cpath d='M0 700 C240 650 420 760 700 710 S1050 660 1200 700 V800 H0Z' fill='%23fff' opacity='.5'/%3E%3Cg fill='none' stroke='%236366f1' stroke-width='3' opacity='.22'%3E%3Cg transform='translate(70 330)'%3E%3Cpath d='M0 30L60 0L120 30L60 60Z'/%3E%3Cpath d='M25 42V78C45 98 75 98 95 78V42'/%3E%3Cpath d='M120 30V75'/%3E%3C/g%3E%3Cg transform='translate(1000 500)'%3E%3Cpath d='M0 30L60 0L120 30L60 60Z'/%3E%3Cpath d='M25 42V78C45 98 75 98 95 78V42'/%3E%3Cpath d='M120 30V75'/%3E%3C/g%3E%3Cg transform='translate(930 230)'%3E%3Crect width='110' height='80' rx='8'/%3E%3Cpath d='M18 24H92M18 42H70'/%3E%3Ccircle cx='84' cy='60' r='10'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E") center/cover no-repeat fixed,linear-gradient(135deg,#e0f2fe,#fae8ff 50%,#dcfce7)}
.top{color:var(--t)}.top a{color:var(--t);background:#ffffffb8;box-shadow:0 2px 8px #6366f122}.hero{color:var(--t)}.main h2{color:var(--t)}
.card{background:#ffffffe8;box-shadow:0 8px 28px #818cf826}.side{background:linear-gradient(180deg,var(--tint,#e0f2fe),#fffffff0)}
.card.lg,.card.rl{border-top:6px solid var(--a);background:linear-gradient(180deg,var(--tint),#fff)}
.auth{min-height:560px;display:flex;flex-direction:column}.auth h2{text-align:center;margin:4px 0}.auth .sub{text-align:center;color:var(--m);margin:0 0 6px;min-height:22px}.lnk{display:flex;justify-content:space-between;gap:10px;font-size:13px;padding-top:12px}.auth .push{margin-top:auto}
</style></head><body>
<div class="top" id="top"></div><div id="app"></div><div id="toast"></div><div id="modal"></div>
<script>
const $=s=>document.querySelector(s),app=$('#app');
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async d=>hex(await crypto.subtle.digest('SHA-256',typeof d==='string'?new TextEncoder().encode(d):d));
const toast=m=>{const t=$('#toast');t.textContent=m;t.style.display='block';setTimeout(()=>t.style.display='none',2800)};
const now=()=>new Date().toLocaleString();
let me=null,adminExists=true,viaQR=false;
const api=async(m,u,b)=>{const r=await fetch(u,{method:m,headers:b?{'Content-Type':'application/json'}:{},body:b?JSON.stringify(b):undefined,credentials:'same-origin'});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error||'Request failed');return j};
const all=c=>api('GET',c=='accts'?'/api/admin/accts':'/api/'+c);
const vurl=id=>location.href.split('#')[0]+'#/v/'+encodeURIComponent(id);
const fileOk=f=>f&&f.size<=5e6&&/\.(pdf|png|jpe?g)$/i.test(f.name);
const stat=s=>`<span class="bd ${s}">${s}</span>`;
const tbl=(h,r)=>`<div class="sc"><table><tr>${h.map(x=>`<th>${x}</th>`).join('')}</tr>${r.map(x=>`<tr>${x.map(y=>`<td>${y}</td>`).join('')}</tr>`).join('')}</table></div>`;
const stats=a=>`<div class="grid">${a.map(x=>`<div class="card cc"><p class="num">${x[1]}</p>${x[0]}</div>`).join('')}</div>`;
// ---- Verification engine ----
const MS={VERIFIED:['G','✔','Certificate Verified','Found in the official university database and the file matches the registered hash.'],NOTFOUND:['Y','?','Not Verified','No matching record exists in the database. This does not prove it is fake — confirm with the issuing university.'],INTEGRITY:['R','✖','Integrity Failed','A record exists, but this file does not match the registered hash. It may have been modified.'],REVOKED:['R','⛔','Certificate Revoked','The issuing university has revoked this certificate.']};
async function engine(id,file,method){const h=file?await sha(await file.arrayBuffer()):null;return api('POST','/api/verify',{id,hash:h,method})}
const result=({s,c,t,h})=>{const[k,i,hd,m]=MS[s];return`<div class="card res ${k}"><div class="ic">${i}</div><h2 style="color:inherit;margin:4px">${hd}</h2><p>${m}</p>${s=='NOTFOUND'&&h?`<p style="max-width:460px;margin:8px auto"><small>No registered file has this SHA-256 hash:<br><code>${h}</code><br>A copy, scan, screenshot or re-saved PDF always has a different hash. If this is a copy of a valid certificate, also type its Certificate ID.</small></p>`:''}${c&&s!='NOTFOUND'?`<div class="dl">${[['Certificate ID',c.cid],['Student',c.name],['Course',c.course],['University',c.uniName],['Issued',c.date],['Integrity',h?(s=='INTEGRITY'?'Failed':'Hash matched'):'ID check only'],['Checked',t]].map(x=>`<div><span>${x[0]}</span><b>${esc(x[1])}</b></div>`).join('')}</div>`:''}</div>`};
const vbox=id=>`<div class="card"><h3>Verify Certificate</h3><label for="vid">Certificate ID</label><input id="vid" value="${esc(id||'')}" placeholder="CERT-2026-AB12CD or paste QR link"><label>Scan QR code</label><p style="margin:4px 0"><button class="btn o" id="qs">📷 Scan with camera</button> <label class="btn o" for="qf" style="display:inline-block;margin:0;font-size:14px">Upload QR image</label><input id="qf" type="file" accept="image/*" hidden></p><video id="vd" playsinline style="display:none;width:100%;max-width:340px;border-radius:12px"></video><label for="vf">…or upload certificate (PDF/JPG/PNG, ≤5 MB)</label><input id="vf" type="file" accept=".pdf,.png,.jpg,.jpeg"><p><button class="btn" id="vgo">Verify Now</button></p><small>Uploads are only checked — never added as official certificates.</small></div><div id="out"></div>`;
// ---- Views ----
const MENU={user:[['dash','Dashboard'],['verify','Verify Certificate'],['mine','My Certificates'],['hist','My Verifications']],university:[['dash','Dashboard'],['studs','Students'],['issue','Issue Certificate'],['certs','Manage Certificates']],admin:[['dash','Dashboard'],['unis','Universities'],['users','Users'],['certs','All Certificates'],['logs','Logs'],['profile','Profile']]};
const TINT={user:'#dbeafe',university:'#d1fae5',admin:'#ede9fe'},COL={user:'#3b82f6',university:'#10b981',admin:'#8b5cf6'},TT={user:'User Portal',university:'University Portal',admin:'Admin Panel'};
const shell=(p,pg,b)=>`<div class="lay" style="--a:${COL[p]};--tint:${TINT[p]}"><div class="side"><h4>${TT[p]}</h4><small>${esc(me.name)}</small><br><br>${MENU[p].map(m=>`<a class="${m[0]==pg?'on':''}" href="#/${p}/${m[0]}">${m[1]}</a>`).join('')}<a href="#/logout">Logout</a></div><div class="main">${b}</div></div>`;
const bars=L=>{const k=['VERIFIED','NOTFOUND','INTEGRITY','REVOKED'],mx=Math.max(1,...k.map(x=>L.filter(l=>l.res==x).length));return`<div class="card"><h3>Verification Results</h3>${k.map(x=>{const n=L.filter(l=>l.res==x).length;return`${x} (${n})<div class="bar" style="width:${n/mx*100}%;min-width:4px"></div>`}).join('')}</div>`};
const cview=c=>{$('#modal').innerHTML=`<div class="md" data-x><div class="card"><h3>${esc(c.course)}</h3>${stat(c.status)}<div class="dl" style="max-width:none">${[['ID',c.cid],['Student',c.name],['Roll',c.roll],['Degree',c.degree],['University',c.uniName],['Issued',c.date]].map(x=>`<div><span>${x[0]}</span><b>${esc(x[1])}</b></div>`).join('')}</div><p>SHA-256 <code>${c.hash}</code></p><div id="q"></div><code>${esc(vurl(c.cid))}</code><p>${c.fileUrl?`<a class="btn s" href="${esc(c.fileUrl)}" target="_blank">Open stored file</a> `:''}<button class="btn s" data-cp="${esc(c.cid)}">Copy ID</button> <button class="btn s o" data-x>Close</button></p></div></div>`;new QRCode($('#q'),{text:vurl(c.cid),width:120,height:120})};
const certTbl=(a,adm)=>tbl(['ID','Student','Course','University','Status','Action'],a.map(c=>[c.cid,esc(c.name),esc(c.course),esc(c.uniName),stat(c.status),`<button class="btn s" data-v="${c.id}">View</button> <button class="btn s ${c.status=='Revoked'?'g':'r'}" data-rv="${c.id}">${c.status=='Revoked'?'Restore':'Revoke'}</button>${adm?` <button class="btn s o" data-dc="${c.id}">Delete</button>`:''}`]));
const PG={user:{dash:async()=>{const v=(await all('vrec')).filter(x=>x.owner==me.email);return`<h2>Dashboard</h2>${stats([['Checks',v.length],['Verified',v.filter(x=>x.res=='VERIFIED').length],['Not verified',v.filter(x=>x.res=='NOTFOUND').length],['Revoked / Failed',v.filter(x=>['REVOKED','INTEGRITY'].includes(x.res)).length]])}`},
 verify:async()=>`<h2>Verify Certificate</h2>${vbox()}`,
 mine:async()=>{const C=(await all('certs')).sort((a,b)=>b.sts-a.sts);return`<h2>My Certificates</h2><div class="card">${C.length?tbl(['ID','Course','University','Issued','Status','Saved','Action'],C.map(c=>[c.cid,esc(c.course),esc(c.uniName),c.date,stat(c.status),c.savedAt,`<button class="btn s" data-v="${c.id}">View</button> <button class="btn s r" data-rm="${c.mid}">Remove</button>`])):'Certificates you verify successfully are saved here automatically. Go to Verify Certificate to add one.'}</div>`},
 hist:async()=>`<h2>My Verifications</h2><div class="card">${tbl(['Time','Certificate','Student','Course','Method','Result'],(await all('vrec')).filter(x=>x.owner==me.email).sort((a,b)=>b.ts-a.ts).map(x=>[x.at,esc(x.cid),esc(x.name),esc(x.course),x.m,x.res]))}</div>`},
university:{dash:async()=>{const c=(await all('certs')).filter(x=>x.uni==me.uni);return`<h2>Dashboard</h2>${stats([['Certificates',c.length],['Active',c.filter(x=>x.status=='Verified').length],['Revoked',c.filter(x=>x.status=='Revoked').length],['Students',(await all('studs')).filter(x=>x.uni==me.uni).length]])}`},
 studs:async()=>`<h2>Students</h2><div class="card"><div class="grid">${[['sn','Name'],['sr','Roll / ID'],['se','Email'],['sc','Course']].map(x=>`<div><label for="${x[0]}">${x[1]}</label><input id="${x[0]}"></div>`).join('')}</div><p><button class="btn" id="sadd">Add Student</button></p></div><div class="card">${tbl(['Name','Roll','Email','Course',''],(await all('studs')).filter(x=>x.uni==me.uni).map(s=>[esc(s.name),esc(s.roll),esc(s.email),esc(s.course),`<button class="btn s r" data-ds="${s.id}">Delete</button>`]))}</div>`,
 issue:async()=>`<h2>Issue Certificate</h2><div class="card"><label for="is">Student</label><select id="is"><option value="">Select…</option>${(await all('studs')).filter(x=>x.uni==me.uni).map(s=>`<option value="${s.id}">${esc(s.name)} (${esc(s.roll)})</option>`).join('')}</select><div class="grid">${[['ic','Course'],['id','Degree'],['iy','Graduation year']].map(x=>`<div><label for="${x[0]}">${x[1]}</label><input id="${x[0]}"></div>`).join('')}<div><label for="it">Issue date</label><input id="it" type="date"></div></div><label for="if">Certificate file (PDF/JPG/PNG ≤5 MB)</label><input id="if" type="file" accept=".pdf,.png,.jpg,.jpeg"><p><button class="btn" id="igo">Issue & Store in Cloud</button></p></div><div id="out"></div>`,
 certs:async()=>`<h2>Manage Certificates</h2><div class="card">${certTbl((await all('certs')).filter(x=>x.uni==me.uni))}</div>`},
admin:{dash:async()=>{const c=await all('certs'),L=await all('vlogs');return`<h2>Dashboard</h2>${stats([['Universities',(await all('unis')).length],['Users',(await all('accts')).filter(x=>x.role=='user').length],['Certificates',c.length],['Revoked',c.filter(x=>x.status=='Revoked').length],['Verifications',L.length]])}${bars(L)}`},
 unis:async()=>{const C=await all('certs'),U=await all('unis');return`<h2>Universities</h2><div class="card"><h3>Add university + login</h3><div class="grid">${[['un','University name'],['uc','Code (e.g. NECN)'],['ue','Login email'],['up','Temp password (min 8)']].map(x=>`<div><label for="${x[0]}">${x[1]}</label><input id="${x[0]}" ${x[0]=='up'?'type="password"':''}></div>`).join('')}</div><p><button class="btn" id="uadd">Add University</button></p></div><div class="card">${tbl(['Name','Code','Certificates','Status',''],U.map(u=>[esc(u.name),esc(u.id),C.filter(c=>c.uni==u.id).length,stat(u.on?'Active':'Inactive'),`<button class="btn s" data-tu="${u.id}">${u.on?'Deactivate':'Activate'}</button>`]))}</div>`},
 users:async()=>`<h2>Users</h2><div class="card">${tbl(['Name','Email','Role','Status','Created',''],(await all('accts')).map(u=>[esc(u.name),esc(u.email),u.role,stat(u.on?'Active':'Inactive'),u.at,u.role=='admin'?'—':`<button class="btn s" data-ta="${u.id}">${u.on?'Deactivate':'Activate'}</button> <button class="btn s o" data-rp="${u.id}">Reset password</button>`]))}</div>`,
 certs:async()=>`<h2>All Certificates</h2><div class="card">${certTbl(await all('certs'),1)}</div>`,
 profile:async()=>`<h2>Admin Profile</h2><div class="card"><h3>Edit details</h3><label for="pn">Name</label><input id="pn" value="${esc(me.name)}"><label for="pe">Email</label><input id="pe" type="email" value="${esc(me.email)}"><label for="pc">Current password</label><input id="pc" type="password" autocomplete="current-password"><p><button class="btn" id="pedit">Save Details</button></p></div><div class="card"><h3>Password & recovery key</h3><label for="p1">Current password</label><input id="p1" type="password" autocomplete="current-password"><label for="p2">New password (min 8, only for Change Password)</label><input id="p2" type="password" autocomplete="new-password"><p><button class="btn" id="pchg">Change Password</button> <button class="btn o" id="pkey">Generate New Recovery Key</button></p></div><div class="card"><h3>Reset admin account</h3><p>Deletes this admin account so the Setup screen appears again (use if the details are wrong).</p><label for="p3">Current password</label><input id="p3" type="password"><p><button class="btn r" id="preset">Reset & Setup Again</button></p></div>`,
 logs:async()=>`<h2>Logs</h2><div class="card"><h3>Verification logs</h3>${tbl(['Time','Certificate','Method','Result','By'],(await all('vlogs')).sort((a,b)=>b.ts-a.ts).slice(0,40).map(l=>[l.at,esc(l.cid),l.m,l.res,esc(l.who||l.u)]))}</div><div class="card"><h3>Audit logs</h3>${tbl(['Time','Action','User','Role','Related','Result'],(await all('alogs')).sort((a,b)=>b.ts-a.ts).slice(0,40).map(l=>[l.at,l.a,esc(l.u),l.r,esc(l.rel),l.res]))}</div>`}};
const home=()=>`<div class="wrap"><div class="hero"><h1>🎓 Verify Your Academic Certificate</h1><p>Secure | Reliable | Fast — certificates issued by authorized universities, stored in the cloud.</p></div>${vbox()}<div class="grid">${[['user','🎓','User','Verify certificates & keep history'],['university','🏛','University','Issue & manage certificates'],['admin','🛡','Admin','Manage universities, users & database']].map(x=>`<div class="card cc rl" style="--a:${COL[x[0]]};--tint:${TINT[x[0]]}"><div class="ic">${x[1]}</div><h3>${x[2]}</h3><p>${x[3]}</p><a class="btn" href="#/login/${x[0]}">${x[2]} Login</a></div>`).join('')}</div></div>`;
async function loginPg(r){const setup=r=='admin'&&!adminExists;const I={user:'🎓',university:'🏛',admin:'🛡'},sub=setup?'First run: create the administrator account.':{user:'Verify certificates and view your history.',university:'Accounts are created by the admin.',admin:'Manage universities, users and certificates.'}[r],side={user:'New here? <a href="#/register">Register</a>',university:'Need access? Ask your admin.',admin:'<a href="#/">Back to home</a>'}[r];
return`<div class="wrap" style="max-width:430px"><div class="card lg auth" style="--a:${COL[r]};--tint:${TINT[r]}"><div class="ic" style="text-align:center">${I[r]}</div><h2>${TT[r]} ${setup?'Setup':'Login'}</h2><p class="sub">${sub}</p>${setup?'<label for="nm">Name</label><input id="nm">':''}<label for="em">Email</label><input id="em" type="email" autocomplete="username"><label for="pw">Password ${setup?'(min 8)':''}</label><input id="pw" type="password" autocomplete="current-password"><p><button class="btn" id="lg" data-r="${r}" data-setup="${setup?1:''}" style="width:100%">${setup?'Create Admin':'Login'}</button></p><div class="push lnk"><a href="#/forgot/${r}">Forgot password?</a><span>${side}</span></div></div></div>`}
const qrDecode=(src,w,h)=>{const c=document.createElement('canvas');c.width=w;c.height=h;const x=c.getContext('2d',{willReadFrequently:true});x.drawImage(src,0,0,w,h);return jsQR(x.getImageData(0,0,w,h).data,w,h)?.data};
function qrDone(raw){const m=raw.match(/\/v\/([^/?#\s]+)/),id=decodeURIComponent(m?m[1]:raw.trim());viaQR=true;$('#vid').value=id;$('#vgo').click()}
document.addEventListener('change',async e=>{if(e.target.id!='qf')return;const f=e.target.files[0];if(!f)return;try{const im=await createImageBitmap(f),r=qrDecode(im,im.width,im.height);r?qrDone(r):toast('No QR code found in that image')}catch{toast('Could not read that image')}});
const showKey=k=>{$('#modal').innerHTML=`<div class="md"><div class="card"><h3>🔑 Recovery key</h3><p>Save this now. It is shown only once and resets your admin password if you forget it.</p><code style="font-size:18px">${k}</code><p><button class="btn s" data-cp="${k}">Copy</button> <button class="btn s o" data-x>I saved it</button></p></div></div>`};
// ---- Router ----
function nav(){$('#top').innerHTML=`<b>🎓 CertVerify Cloud</b><a href="#/">Home</a>${me?`<a href="#/${me.role}/dash">Portal</a><a href="#/logout">Logout</a>`:'<a href="#/login/user">Login</a>'}`}
async function route(){nav();const[,a,b]=location.hash.slice(1).split('/');
 if(a=='logout'){await api('POST','/api/auth/logout').catch(()=>{});me=null;return location.hash='#/'}
 if(a=='login'&&COL[b])return app.innerHTML=await loginPg(b);
 if(a=='forgot')return app.innerHTML=`<div class="wrap" style="max-width:430px"><div class="card lg auth" style="--a:${COL[b||'user']};--tint:${TINT[b||'user']}"><h2>Forgot Password</h2>${b=='admin'?'<label for="fe">Admin email</label><input id="fe" type="email"><label for="fk">Recovery key</label><input id="fk" placeholder="XXXXXXXXXXXXXXXX-XXXXXXXXXXXXXXXX"><label for="fp">New password (min 8)</label><input id="fp" type="password"><p><button class="btn" id="frg">Reset Password</button></p><small>No recovery key? Log in and create one under Profile, or ask the project owner to reset the admin account.</small>':'<p>Please ask your administrator to reset your password (Admin Panel → Users → Reset password).</p>'}<p><a href="#/login/${b||'user'}">Back to login</a></p></div></div>`;
 if(a=='register')return app.innerHTML=`<div class="wrap" style="max-width:430px"><div class="card lg auth" style="--a:${COL.user};--tint:${TINT.user}"><h2>User Registration</h2><label for="rn">Name</label><input id="rn"><label for="re">Email</label><input id="re" type="email"><label for="rp">Password (min 8)</label><input id="rp" type="password"><p><button class="btn" id="rg">Register</button></p><small>University and admin accounts cannot be self-registered.</small></div></div>`;
 if(a=='v'){app.innerHTML=`<div class="wrap">${vbox(decodeURIComponent(b||''))}</div>`;viaQR=true;return $('#vgo').click()}
 if(COL[a]){if(!me||me.role!=a){toast('Please login to the '+TT[a]);return location.hash='#/login/'+a}const pg=PG[a][b]?b:'dash';return app.innerHTML=shell(a,pg,await PG[a][pg]())}
 app.innerHTML=home()}
addEventListener('hashchange',route);
document.addEventListener('click',async e=>{const t=e.target,D=t.dataset,v=k=>$('#'+k).value.trim(),g=async(c,id)=>(await all(c)).find(x=>x.id==id);
 try{
 if('x' in D&&(t.classList.contains('md')||t.tagName=='BUTTON'))$('#modal').innerHTML='';
 if(D.cp){navigator.clipboard?.writeText(D.cp);toast('ID copied')}
 if(D.v)cview(await g('certs',D.v));
 if(D.rv){await api('POST','/api/certs/'+encodeURIComponent(D.rv)+'/toggle');route()}
 if(D.dc&&confirm('Delete permanently?')){await api('DELETE','/api/certs/'+encodeURIComponent(D.dc));route()}
 if(t.id=='qs'){if(typeof jsQR=='undefined'||!navigator.mediaDevices)return toast('Camera scan not available here. Use Upload QR image.');try{const st=await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}}),vd=$('#vd');vd.srcObject=st;vd.style.display='block';await vd.play();const tick=()=>{if(!vd.isConnected)return st.getTracks().forEach(x=>x.stop());if(vd.videoWidth){const r=qrDecode(vd,vd.videoWidth,vd.videoHeight);if(r){st.getTracks().forEach(x=>x.stop());vd.style.display='none';return qrDone(r)}}setTimeout(tick,250)};tick()}catch{toast('Camera blocked or denied. Use Upload QR image.')}}
 if(D.rm){await api('DELETE','/api/mycerts/'+D.rm);route()}
 if(D.ds){await api('DELETE','/api/studs/'+D.ds);route()}
 if(D.tu){await api('POST','/api/admin/unis/'+D.tu+'/toggle');route()}
 if(D.ta){await api('POST','/api/admin/accts/'+D.ta+'/toggle');route()}
 if(t.id=='vgo'){let id=v('vid');const mm=id.match(/\/v\/([^/?#\s]+)/);if(mm)id=decodeURIComponent(mm[1]);const f=$('#vf').files[0];if(!id&&!f)return toast('Enter an ID or choose a file');if(id&&!/^[\w-]{3,40}$/.test(id))return toast('Invalid ID');if(f&&!fileOk(f))return toast('PDF/JPG/PNG under 5 MB only');$('#out').innerHTML='<div class="card cc">Checking database…</div>';const mth=viaQR?'QR':f?'Upload':'ID';viaQR=false;const r=await engine(id,f,mth);$('#out').innerHTML=result(r);if(me?.role=='user'&&r.s=='VERIFIED')toast('Saved to My Certificates')}
 if(t.id=='lg'){const r=D.r,em=v('em').toLowerCase(),p=$('#pw').value;
  if(D.setup){if(p.length<8||!em||!v('nm'))return toast('Fill all fields (password min 8)');const j=await api('POST','/api/auth/setup',{name:v('nm'),email:em,password:p});adminExists=true;showKey(j.key);toast('Admin created — login now');return route()}
  const j=await api('POST','/api/auth/login',{email:em,password:p,role:r});me=j.user;location.hash='#/'+r+'/dash'}
 if(D.rp){const np=prompt('New temporary password (min 8)');if(np&&np.length>=8){await api('POST','/api/admin/accts/'+D.rp+'/reset',{password:np});toast('Password reset')}else if(np)toast('Min 8 characters')}
 if(t.id=='pedit'){const j=await api('POST','/api/me/update',{name:v('pn'),email:v('pe'),password:$('#pc').value});me=j.user;toast('Details saved');route()}
 if(t.id=='pchg'){await api('POST','/api/me/password',{current:$('#p1').value,new:$('#p2').value});toast('Password changed')}
 if(t.id=='pkey'){const j=await api('POST','/api/me/recovery',{current:$('#p1').value});showKey(j.key)}
 if(t.id=='preset'){if(!confirm('Delete this admin account and set up again?'))return;await api('POST','/api/me/reset',{current:$('#p3').value});me=null;adminExists=false;toast('Admin removed — set up again');location.hash='#/login/admin';route()}
 if(t.id=='frg'){const j=await api('POST','/api/auth/forgot',{email:v('fe'),key:v('fk'),password:$('#fp').value});showKey(j.key);toast('Password reset — login now');location.hash='#/login/admin'}
 if(t.id=='rg'){await api('POST','/api/auth/register',{name:v('rn'),email:v('re'),password:$('#rp').value});toast('Registered! Please login');location.hash='#/login/user'}
 if(t.id=='uadd'){await api('POST','/api/admin/unis',{name:v('un'),code:v('uc'),email:v('ue'),password:$('#up').value});toast('University added');route()}
 if(t.id=='sadd'){if(!v('sn')||!v('sr'))return toast('Name and roll required');await api('POST','/api/studs',{name:v('sn'),roll:v('sr'),email:v('se'),course:v('sc')});route()}
 if(t.id=='igo'){const f=$('#if').files[0];if(!$('#is').value||!v('ic')||!v('it')||!fileOk(f))return toast('Select student, course, date and a valid file');
  const b64=await new Promise(ok=>{const fr=new FileReader();fr.onload=()=>ok(fr.result.split(',')[1]);fr.readAsDataURL(f)});
  const j=await api('POST','/api/certs/issue',{studId:$('#is').value,course:v('ic'),degree:v('id'),year:v('iy'),date:v('it'),fileName:f.name,fileB64:b64}),c=j.c,cid=c.cid;
  $('#out').innerHTML=`<div class="card res G"><div class="ic">✔</div><h2 style="color:inherit">Certificate Issued &amp; Stored</h2><div id="q" style="display:inline-block"></div><p><b>${cid}</b><br>${esc(c.name)}<br><code>${esc(vurl(cid))}</code></p></div>`;new QRCode($('#out #q'),{text:vurl(cid),width:120,height:120})}
 }catch(err){toast('Error: '+(err.message||err.code||err))}});
(async()=>{try{const j=await api('GET','/api/me');me=j.user;adminExists=j.adminExists}catch{}route()})();
</script></body></html>

==HTML_END==*/
