'use strict';
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const PDFDocument = require('pdfkit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const dbPath = process.env.DB_PATH || path.join(__dirname, 'ledger.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new SQLiteStore(dbPath);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS generations (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
 demo_name TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
 entry_count INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);
if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
  const exists = db.prepare('SELECT id FROM users WHERE username=?').get(process.env.ADMIN_USERNAME);
  if (!exists) db.prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)').run(
    process.env.ADMIN_USERNAME, bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12), 'admin');
}
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'data:'] } }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(express.json({ limit: '20kb' }));
app.use(session({ secret: process.env.SESSION_SECRET || 'local-dev-only-change-this-secret', resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000*60*60*8 } }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/login', rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: true, legacyHeaders: false }));
const safe = s => String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function requireAuth(req,res,next){ if(!req.session.user) return res.status(401).json({error:'Please log in again.'}); next(); }
function requireAdmin(req,res,next){ if(!req.session.user || req.session.user.role!=='admin') return res.status(403).json({error:'Admin access required.'}); next(); }
app.get('/health',(req,res)=>res.json({ok:true}));
app.get('/api/me',(req,res)=>res.json({user:req.session.user || null}));
app.post('/login', async (req,res)=>{
 const username=String(req.body.username||'').trim(); const password=String(req.body.password||'');
 const user=db.prepare('SELECT id,username,password_hash,role,active FROM users WHERE username=?').get(username);
 if(!user || !user.active || !await bcrypt.compare(password,user.password_hash)) return res.status(401).json({error:'Invalid username or password.'});
 req.session.regenerate(err=>{ if(err) return res.status(500).json({error:'Could not create session.'}); req.session.user={id:user.id,username:user.username,role:user.role}; res.json({ok:true,user:req.session.user}); });
});
app.post('/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/users',requireAdmin,(req,res)=>{
 const rows=db.prepare('SELECT id,username,role,active,created_at FROM users ORDER BY id DESC').all(); res.json({users:rows});
});
app.post('/api/admin/users',requireAdmin,async(req,res)=>{
 const username=String(req.body.username||'').trim(); const password=String(req.body.password||''); const role=req.body.role==='admin'?'admin':'user';
 if(!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({error:'Username must be 3–32 letters, numbers, dot, dash or underscore.'});
 if(password.length<12) return res.status(400).json({error:'Use a password of at least 12 characters.'});
 try { const info=db.prepare('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)').run(username,await bcrypt.hash(password,12),role); res.json({ok:true,id:info.lastInsertRowid}); }
 catch(e){ if(String(e.code).includes('SQLITE_CONSTRAINT')) return res.status(409).json({error:'That username already exists.'}); res.status(500).json({error:'Could not create user.'}); }
});
app.post('/api/admin/users/:id/toggle',requireAdmin,(req,res)=>{
 const id=Number(req.params.id); if(id===req.session.user.id) return res.status(400).json({error:'You cannot deactivate your own account.'});
 const user=db.prepare('SELECT id,active FROM users WHERE id=?').get(id); if(!user) return res.status(404).json({error:'User not found.'});
 db.prepare('UPDATE users SET active=? WHERE id=?').run(user.active?0:1,id); res.json({ok:true});
});
app.get('/api/history',requireAuth,(req,res)=>{
 const rows=req.session.user.role==='admin' ? db.prepare(`SELECT g.id,u.username,g.demo_name,g.start_date,g.end_date,g.entry_count,g.created_at FROM generations g JOIN users u ON u.id=g.user_id ORDER BY g.id DESC LIMIT 300`).all() : db.prepare(`SELECT id,demo_name,start_date,end_date,entry_count,created_at FROM generations WHERE user_id=? ORDER BY id DESC LIMIT 100`).all(req.session.user.id);
 res.json({history:rows});
});
function isoDate(s){ if(!/^\d{4}-\d{2}-\d{2}$/.test(String(s||''))) return false; const d=new Date(s+'T00:00:00Z'); return !Number.isNaN(d.getTime())&&d.toISOString().slice(0,10)===s; }
function createEntries(start,end,opening){
 const entries=[]; let balance=opening; const from=new Date(start+'T12:00:00Z'), to=new Date(end+'T12:00:00Z');
 // Explicitly fictional sample activity: never represented as a real bank record.
 const salaryNames=['FICTIONAL SAMPLE PAYROLL','DEMO SALARY CREDIT','SAMPLE EMPLOYER PAYMENT'];
 let month=new Date(Date.UTC(from.getUTCFullYear(),from.getUTCMonth(),1,12));
 while(month<=to){ const day=Math.min(5,new Date(Date.UTC(month.getUTCFullYear(),month.getUTCMonth()+1,0)).getUTCDate()); const date=new Date(Date.UTC(month.getUTCFullYear(),month.getUTCMonth(),day,12));
  if(date>=from&&date<=to){ const credit=25000 + ((month.getUTCMonth()*137)%5000); balance+=credit; entries.push({date:date.toISOString().slice(0,10),description:salaryNames[month.getUTCMonth()%salaryNames.length],credit,debit:0,balance});
   const count=2+(month.getUTCMonth()%3); for(let i=0;i<count;i++){ const dd=8+i*5; const tx=new Date(Date.UTC(month.getUTCFullYear(),month.getUTCMonth(),dd,12)); if(tx<from||tx>to) continue; const debit=500+((month.getUTCMonth()*911+i*673)%4200); balance-=debit; entries.push({date:tx.toISOString().slice(0,10),description:['DEMO PURCHASE','SAMPLE BILL PAYMENT','FICTIONAL TRANSFER','DEMO DAILY EXPENSE'][i%4],credit:0,debit,balance}); }
  } month=new Date(Date.UTC(month.getUTCFullYear(),month.getUTCMonth()+1,1,12)); }
 return entries.sort((a,b)=>a.date.localeCompare(b.date));
}
app.post('/api/generate',requireAuth,(req,res)=>{
 const name=String(req.body.name||'').trim().slice(0,80); const start=String(req.body.startDate||''); const end=String(req.body.endDate||''); const opening=Number(req.body.openingBalance||0);
 if(!name) return res.status(400).json({error:'Enter a demo name.'});
 if(!isoDate(start)||!isoDate(end)||start>end) return res.status(400).json({error:'Choose a valid date range.'});
 if(!Number.isFinite(opening)||opening<0||opening>100000000) return res.status(400).json({error:'Enter a valid opening demo balance.'});
 const months=(new Date(end+'T00:00:00Z').getUTCFullYear()-new Date(start+'T00:00:00Z').getUTCFullYear())*12+(new Date(end+'T00:00:00Z').getUTCMonth()-new Date(start+'T00:00:00Z').getUTCMonth());
 if(months>24) return res.status(400).json({error:'Choose a range of up to 24 months.'});
 const entries=createEntries(start,end,opening); if(entries.length>200) return res.status(400).json({error:'Too many entries in this range.'});
 const info=db.prepare('INSERT INTO generations(user_id,demo_name,start_date,end_date,entry_count) VALUES(?,?,?,?,?)').run(req.session.user.id,name,start,end,entries.length);
 const doc=new PDFDocument({size:'A4',margin:40,info:{Title:'Fictional Demo Ledger',Author:'Demo Ledger Simulator',Subject:'FICTIONAL DEMO - NOT A REAL BANK STATEMENT'}});
 const filename=`fictional-demo-ledger-${info.lastInsertRowid}.pdf`;
 res.setHeader('Content-Type','application/pdf'); res.setHeader('Content-Disposition',`attachment; filename="${filename}"`); doc.pipe(res);
 const w=doc.page.width-80;
 doc.save(); doc.rotate(-32,{origin:[doc.page.width/2,doc.page.height/2]}); doc.fillColor('#f3d7d7').fontSize(31).opacity(0.6).text('FICTIONAL DEMO - NOT REAL',{x:40,y:350,width:520,align:'center'}); doc.restore(); doc.opacity(1);
 doc.fillColor('#8b1e1e').fontSize(19).text('FICTIONAL DEMO LEDGER',{align:'center'});
 doc.moveDown(0.3).fontSize(10).fillColor('#333').text('NOT A BANK STATEMENT • NOT ISSUED BY ANY BANK',{align:'center'});
 doc.moveDown(1).fontSize(10).text(`Demo name: ${name}`); doc.text(`Period: ${start} to ${end}`); doc.text(`Opening demo balance: ${opening.toFixed(2)}`); doc.moveDown();
 const cols=[40,118,320,385,450, w+40]; const headers=['Date','Description','Credit','Debit','Balance'];
 doc.rect(40,doc.y,w,23).fill('#eeeeee'); doc.fillColor('#111').font('Helvetica-Bold').fontSize(9);
 headers.forEach((h,i)=>doc.text(h,cols[i]+4,doc.y+7,{width:cols[i+1]-cols[i]-8,align:i>1?'right':'left'}));
 let y=doc.y+25; doc.font('Helvetica').fontSize(8);
 for(const e of entries){ if(y>735){doc.addPage(); y=55; doc.fillColor('#8b1e1e').font('Helvetica-Bold').fontSize(12).text('FICTIONAL DEMO — NOT A REAL BANK STATEMENT',40,y,{width:w,align:'center'}); y+=25; doc.font('Helvetica').fontSize(8).fillColor('#111');}
  doc.moveTo(40,y+14).lineTo(40+w,y+14).strokeColor('#dddddd').stroke(); const vals=[e.date,e.description,e.credit?e.credit.toFixed(2):'—',e.debit?e.debit.toFixed(2):'—',e.balance.toFixed(2)];
  vals.forEach((v,i)=>doc.fillColor('#222').text(v,cols[i]+4,y,{width:cols[i+1]-cols[i]-8,align:i>1?'right':'left',ellipsis:true})); y+=20;
 }
 doc.moveDown(2); doc.fillColor('#8b1e1e').font('Helvetica-Bold').fontSize(10).text('FICTIONAL DEMO — NOT A REAL BANK STATEMENT',40,doc.page.height-50,{width:w,align:'center'});
 doc.end();
});
app.use((err,req,res,next)=>{ console.error(err); if(res.headersSent) return next(err); res.status(500).json({error:'Unexpected server error.'}); });
app.listen(PORT,()=>console.log(`Fictional Demo Ledger listening on ${PORT}`));
