'use strict';
const express=require('express'),Database=require('better-sqlite3'),crypto=require('crypto'),path=require('path'),fs=require('fs'),webpush=require('web-push');
const app=express(),port=Number(process.env.PORT||3000),dataDir=path.join(__dirname,'data');fs.mkdirSync(dataDir,{recursive:true});
const db=new Database(path.join(dataDir,'shiftmaster.sqlite'));db.pragma('journal_mode = WAL');db.pragma('foreign_keys = ON');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS shifts(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,starts_at TEXT NOT NULL,ends_at TEXT NOT NULL,kind TEXT NOT NULL CHECK(kind IN ('day','night','other')),note TEXT NOT NULL DEFAULT '',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_shifts_user_date ON shifts(user_id,starts_at);
CREATE TABLE IF NOT EXISTS settings(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,reminder_minutes INTEGER NOT NULL DEFAULT 60,hourly_rate REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS subscriptions(id INTEGER PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,endpoint TEXT NOT NULL UNIQUE,subscription_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sent_reminders(shift_id INTEGER NOT NULL REFERENCES shifts(id) ON DELETE CASCADE,minutes INTEGER NOT NULL,PRIMARY KEY(shift_id,minutes));`);
// Non-destructive schema migration: existing accounts and shifts remain intact.
for (const [table, column, ddl] of [
  ['users', 'avatar', 'avatar TEXT'],
  ['users','birthday','birthday TEXT'],
  ['users','birthday_visible','birthday_visible INTEGER NOT NULL DEFAULT 0'],
  ['users', 'first_name', "first_name TEXT NOT NULL DEFAULT ''"],
  ['users', 'last_name', "last_name TEXT NOT NULL DEFAULT ''"],
  ['users', 'position', "position TEXT NOT NULL DEFAULT 'forecourt'"],
  ['settings', 'night_credit', 'night_credit REAL NOT NULL DEFAULT 13.5'],
  ['settings', 'holiday_mode', "holiday_mode TEXT NOT NULL DEFAULT 'multiplier'"],
  ['settings', 'holiday_value', 'holiday_value REAL NOT NULL DEFAULT 2'],
]) {
  if (!db.prepare(`PRAGMA table_info(${table})`).all().some((c) => c.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
  }
}
db.exec(`CREATE TABLE IF NOT EXISTS admins(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, granted_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP); CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY,actor_id INTEGER,action TEXT NOT NULL,target_id INTEGER,details TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);`);
app.disable('x-powered-by');app.use(express.json({limit:'512kb'}));app.use(express.static(path.join(__dirname,'public'),{index:'index.html'}));
const vapidPublic=process.env.VAPID_PUBLIC_KEY||'',vapidPrivate=process.env.VAPID_PRIVATE_KEY||'';
if(vapidPublic&&vapidPrivate)webpush.setVapidDetails(process.env.VAPID_SUBJECT||'mailto:admin@example.com',vapidPublic,vapidPrivate);
function fail(res,status,message){return res.status(status).json({error:message})}
function hash(s){return crypto.createHash('sha256').update(s).digest('hex')}
function passHash(password){const salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(password,salt,64).toString('hex')}
function checkPass(password,stored){const [salt,expected]=stored.split(':');if(!salt||!expected)return false;const actual=crypto.scryptSync(password,salt,64);return crypto.timingSafeEqual(actual,Buffer.from(expected,'hex'))}
function cookies(req){return Object.fromEntries((req.headers.cookie||'').split(';').map(v=>v.trim().split('=').map(decodeURIComponent)).filter(v=>v.length===2))}
function auth(req,res,next){const token=cookies(req).sm_session;if(!token)return fail(res,401,'Влез в профила си.');const session=db.prepare('SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>?').get(hash(token),Date.now());if(!session)return fail(res,401,'Сесията е изтекла.');req.userId=session.user_id;next()}
function setSession(res,userId){const token=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(hash(token),userId,Date.now()+30*86400000);res.cookie('sm_session',token,{httpOnly:true,sameSite:'strict',secure:process.env.NODE_ENV==='production',maxAge:30*86400000,path:'/'})}
const attempts=new Map();function limit(req,res,next){const ip=req.ip||'unknown',now=Date.now(),item=attempts.get(ip)||{count:0,until:now+15*60000};if(now>item.until){item.count=0;item.until=now+15*60000}item.count++;attempts.set(ip,item);if(item.count>30)return fail(res,429,'Твърде много опити. Опитай по-късно.');next()}
function validUsername(v){return typeof v==='string'&&/^[\p{L}\p{N}_.-]{3,32}$/u.test(v)}
function validName(v){return typeof v==='string'&&v.trim().length<=60&&(!v.trim()||/^[\p{L}\p{M} .'-]+$/u.test(v.trim()))}
const POSITIONS=['cashier','forecourt','manager','deputy_manager'];
function validPosition(v){return POSITIONS.includes(v)}
function validPassword(v){return typeof v==='string'&&v.length>=8&&v.length<=128}
app.use('/api',(req,res,next)=>{if(['POST','PUT','PATCH','DELETE'].includes(req.method)){const origin=req.get('origin');const host=req.get('host');if(origin){try{if(new URL(origin).host!==host)return fail(res,403,'Невалиден произход.')}catch{return fail(res,403,'Невалиден произход.')}}}next()});
app.post('/api/register',limit,(req,res)=>{const {username,password,first_name='',last_name='',position='forecourt'}=req.body;if(!['cashier','forecourt'].includes(position))return fail(res,400,'Можеш да избереш само касиер или форкорт.');if(!validName(first_name)||!validName(last_name))return fail(res,400,'Невалидно име или фамилия.');if(!validUsername(username)||!validPassword(password))return fail(res,400,'Потребител: 3–32 знака; парола: поне 8 знака.');try{const result=db.prepare('INSERT INTO users(username,password_hash,first_name,last_name,position) VALUES(?,?,?,?,?)').run(username,passHash(password),first_name.trim(),last_name.trim(),position);db.prepare('INSERT INTO settings(user_id) VALUES(?)').run(result.lastInsertRowid);setSession(res,result.lastInsertRowid);res.json({username})}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return fail(res,409,'Този потребител вече съществува.');throw e}});
app.post('/api/login',limit,(req,res)=>{const {username,password}=req.body;const user=typeof username==='string'?db.prepare('SELECT * FROM users WHERE username=?').get(username):null;if(!user||typeof password!=='string'||!checkPass(password,user.password_hash))return fail(res,401,'Грешно потребителско име или парола.');setSession(res,user.id);res.json({username:user.username})});
app.post('/api/logout',auth,(req,res)=>{const token=cookies(req).sm_session;db.prepare('DELETE FROM sessions WHERE token_hash=?').run(hash(token));res.clearCookie('sm_session',{path:'/'});res.json({ok:true})});
// Public birthdays are opt-in, and never expose birth years to colleagues.
app.get('/api/birthdays',auth,(req,res)=>{
 const rows=db.prepare("SELECT id,first_name,last_name,username,birthday,avatar FROM users WHERE birthday_visible=1 AND birthday IS NOT NULL").all();
 res.json(rows.map(u=>({id:u.id,name:[u.first_name,u.last_name].filter(Boolean).join(' ')||u.username,day:u.birthday.slice(5),avatar:u.avatar})));
});
app.put('/api/profile/birthday',auth,(req,res)=>{
 const {birthday,visible}=req.body||{};
 if(typeof visible!=='boolean'||(birthday!==null&&(typeof birthday!=='string'||!/^(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(birthday)||Number.isNaN(Date.parse(birthday))||new Date(birthday).toISOString().slice(0,10)!==birthday)))return fail(res,400,'Невалидна дата.');
 db.prepare('UPDATE users SET birthday=?,birthday_visible=? WHERE id=?').run(birthday,visible?1:0,req.userId);res.json({ok:true});
});
app.post('/api/shifts/bulk',auth,(req,res)=>{
 const {dates,preset,replace=false}=req.body||{};
 if(!Array.isArray(dates)||dates.length<1||dates.length>62||new Set(dates).size!==dates.length||!['day','night','regular8','regular9'].includes(preset)||typeof replace!=='boolean')return fail(res,400,'Избери до 62 уникални дати и вид смяна.');
 const shiftsToAdd=[];
 for(const date of dates){if(typeof date!=='string'||!/^(20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(date)||Number.isNaN(Date.parse(date))||new Date(date).toISOString().slice(0,10)!==date)return fail(res,400,'Невалидна дата.');
 const next=new Date(date+'T12:00:00Z');next.setUTCDate(next.getUTCDate()+1);
 const start=preset==='night'?'19:00':preset==='day'?'07:00':preset==='regular8'?'08:00':'09:00';
 const end=preset==='night'?'07:00':preset==='day'?'19:00':preset==='regular8'?'17:00':'18:00';
 shiftsToAdd.push({date,starts_at:date+'T'+start,ends_at:(preset==='night'?next.toISOString().slice(0,10):date)+'T'+end,kind:preset==='night'?'night':preset==='day'?'day':'other'});
 }
 const insert=db.prepare('INSERT INTO shifts(user_id,starts_at,ends_at,kind,note) VALUES(?,?,?,?,?)');
 const clear=db.prepare('DELETE FROM shifts WHERE user_id=? AND substr(starts_at,1,10)=?');
 const existing=db.prepare('SELECT COUNT(*) n FROM shifts WHERE user_id=? AND substr(starts_at,1,10)=?');
 const count=db.transaction(()=>{let added=0,skipped=0;for(const x of shiftsToAdd){if(replace)clear.run(req.userId,x.date);else if(existing.get(req.userId,x.date).n){skipped++;continue;}insert.run(req.userId,x.starts_at,x.ends_at,x.kind,'');added++;}return {added,skipped};})();
 res.json(count);
});
app.get('/api/me',auth,(req,res)=>{const u=db.prepare('SELECT username,avatar,first_name,last_name,position,birthday,birthday_visible FROM users WHERE id=?').get(req.userId);res.json({...u,is_admin:isAdmin(req.userId)})});
app.put('/api/account',auth,limit,(req,res)=>{const {username,currentPassword,newPassword}=req.body;const u=db.prepare('SELECT * FROM users WHERE id=?').get(req.userId);if(typeof currentPassword!=='string'||!checkPass(currentPassword,u.password_hash))return fail(res,403,'Текущата парола е грешна.');if(!validUsername(username))return fail(res,400,'Невалидно потребителско име.');if(newPassword&&!validPassword(newPassword))return fail(res,400,'Новата парола трябва да е поне 8 знака.');try{db.prepare('UPDATE users SET username=?,password_hash=? WHERE id=?').run(username,newPassword?passHash(newPassword):u.password_hash,req.userId);if(newPassword)db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').run(req.userId,hash(cookies(req).sm_session));res.json({username})}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return fail(res,409,'Потребителското име е заето.');throw e}});
// Administrator is configured explicitly in .env / environment and has read-only overview.
// Never grant admin privileges based on a username chosen by a new registrant alone.
const adminId = Number(process.env.ADMIN_USER_ID || 0);
function isAdmin(userId) { return (adminId > 0 && userId === adminId) || !!db.prepare('SELECT 1 FROM admins WHERE user_id=?').get(userId); }
function requireAdmin(req,res,next){if(!isAdmin(req.userId))return fail(res,403,'Нямаш администраторски достъп.');next()}
function audit(actor,action,target,details=''){db.prepare('INSERT INTO audit_log(actor_id,action,target_id,details) VALUES(?,?,?,?)').run(actor,action,target,details)}
function validId(v){return /^[1-9]\d*$/.test(String(v))&&Number.isSafeInteger(Number(v))}

// Official Bulgarian holidays: fixed dates plus Orthodox Easter Friday–Monday.
// Substitute non-working days and ad-hoc government decisions are not inferred.
function orthodoxEaster(year){
  const a=year%4,b=year%7,c=year%19,d=(19*c+15)%30,e=(2*a+4*b-d+34)%7;
  const julian=new Date(Date.UTC(year,2,22+d+e));
  julian.setUTCDate(julian.getUTCDate()+Math.floor(year/100)-Math.floor(year/400)-2);
  return julian;
}
function holidayDates(year){
  const dates=new Set(['01-01','03-03','05-01','05-06','05-24','09-06','09-22','12-24','12-25','12-26'].map(x=>`${year}-${x}`));
  const easter=orthodoxEaster(year);
  for(const offset of [-2,-1,0,1]){const d=new Date(easter);d.setUTCDate(d.getUTCDate()+offset);dates.add(d.toISOString().slice(0,10));}
  return dates;
}
function isHoliday(date){const y=Number(date.slice(0,4));return holidayDates(y).has(date)}
function shiftAccounting(shift,settings){
  // Local wall-clock times as entered; split at midnight for overnight shifts.
  const start=new Date(shift.starts_at),end=new Date(shift.ends_at);
  const elapsed=(end-start)/3600000;
  if(!Number.isFinite(elapsed)||elapsed<=0)return {hours:0,holidayHours:0,pay:0};
  const hours=shift.kind==='night'?(settings.night_credit??13.5):elapsed;
  let holidayElapsed=0,cursor=new Date(start);
  while(cursor<end){const midnight=new Date(cursor);midnight.setHours(24,0,0,0);const boundary=new Date(Math.min(midnight.getTime(),end.getTime()));
    if(isHoliday(`${cursor.getFullYear()}-${String(cursor.getMonth()+1).padStart(2,'0')}-${String(cursor.getDate()).padStart(2,'0')}`))holidayElapsed+=(boundary-cursor)/3600000;
    cursor=boundary;
  }
  const holidayHours=hours*holidayElapsed/elapsed;
  const rate=settings.hourly_rate||0,mode=settings.holiday_mode||'multiplier',value=settings.holiday_value??2;
  const bonus=mode==='multiplier'?holidayHours*rate*(value-1):mode==='add_hour'?holidayHours*value:holidayHours*value;
  return {hours,holidayHours,pay:hours*rate+bonus};
}
function summaryFor(userId) {
  const entries=db.prepare('SELECT starts_at,ends_at,kind FROM shifts WHERE user_id=?').all(userId);
  const config=db.prepare('SELECT hourly_rate,night_credit,holiday_mode,holiday_value FROM settings WHERE user_id=?').get(userId);
  const now=new Date(),currentMonth=`${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}`;
  const calc=(rows)=>{let hours=0,holidayHours=0,pay=0;for(const s of rows){const x=shiftAccounting(s,config);hours+=x.hours;holidayHours+=x.holidayHours;pay+=x.pay;}
    return {shifts:rows.length,hours:Math.round(hours*100)/100,holiday_hours:Math.round(holidayHours*100)/100,estimated_earnings:Math.round(pay*100)/100};};
  return {month:currentMonth,monthly:calc(entries.filter(s=>s.starts_at.slice(0,7)===currentMonth)),total:calc(entries),rate:config.hourly_rate,night_credit:config.night_credit};
}
app.get('/api/profile',auth,(req,res)=>{
  const user=db.prepare('SELECT username,avatar,first_name,last_name,position,created_at FROM users WHERE id=?').get(req.userId);
  res.json({...user,birthday:db.prepare("SELECT birthday,birthday_visible FROM users WHERE id=?").get(req.userId).birthday,birthday_visible:db.prepare("SELECT birthday_visible FROM users WHERE id=?").get(req.userId).birthday_visible,summary:summaryFor(req.userId)});
});
app.put('/api/profile/name',auth,(req,res)=>{
  const {first_name,last_name}=req.body;
  if(!validName(first_name)||!validName(last_name))return fail(res,400,'Името и фамилията трябва да са до 60 символа.');
  db.prepare('UPDATE users SET first_name=?,last_name=? WHERE id=?').run(first_name.trim(),last_name.trim(),req.userId);
  res.json({first_name:first_name.trim(),last_name:last_name.trim()});
});
app.put('/api/profile/avatar',auth,(req,res)=>{
  const {avatar}=req.body;
  if(avatar!==null && (typeof avatar!=='string'||avatar.length>400000||!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/.test(avatar)))return fail(res,400,'Избери PNG, JPG или WebP до 280 KB.');
  if(avatar!==null){
    const raw=Buffer.from(avatar.split(',')[1],'base64');
    const png=raw.subarray(0,8).equals(Buffer.from('89504e470d0a1a0a','hex'));
    const jpg=raw.subarray(0,3).equals(Buffer.from('ffd8ff','hex'));
    const webp=raw.subarray(0,4).toString()==='RIFF'&&raw.subarray(8,12).toString()==='WEBP';
    const declared=avatar.slice(5,avatar.indexOf(';'));
    if(raw.length>280000||raw.length<12||!(declared==='image/png'&&png||declared==='image/jpeg'&&jpg||declared==='image/webp'&&webp))return fail(res,400,'Невалидна снимка.');
  }
  db.prepare('UPDATE users SET avatar=? WHERE id=?').run(avatar,req.userId);
  res.json({ok:true});
});
app.get('/api/admin/overview',auth,(req,res)=>{
  if(!isAdmin(req.userId))return fail(res,403,'Нямаш администраторски достъп.');
  const users=db.prepare('SELECT id,username,first_name,last_name,position,avatar,created_at FROM users ORDER BY id').all();
  res.json({users:users.map(u=>({...u,is_admin:isAdmin(u.id),summary:summaryFor(u.id)})),audit:db.prepare('SELECT a.*,u.username AS actor FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 100').all()});
});
// Full admin operations. All authorization checks are performed server-side.
app.get('/api/admin/users/:id',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id))return fail(res,400,'Невалиден ID.');
 const u=db.prepare('SELECT id,username,first_name,last_name,position,avatar,created_at FROM users WHERE id=?').get(req.params.id);
 if(!u)return fail(res,404,'Потребителят не е намерен.');
 res.json({...u,is_admin:isAdmin(u.id),summary:summaryFor(u.id),settings:db.prepare('SELECT * FROM settings WHERE user_id=?').get(u.id),shifts:db.prepare('SELECT id,starts_at,ends_at,kind,note FROM shifts WHERE user_id=? ORDER BY starts_at DESC').all(u.id)});
});
app.post('/api/admin/users',auth,requireAdmin,limit,(req,res)=>{
 const {username,password,first_name='',last_name='',position='forecourt'}=req.body;
 if(!validPosition(position))return fail(res,400,'Невалидна длъжност.');
 if(!validUsername(username)||!validPassword(password)||!validName(first_name)||!validName(last_name))return fail(res,400,'Невалидни данни.');
 try{const r=db.transaction(()=>{const x=db.prepare('INSERT INTO users(username,password_hash,first_name,last_name,position) VALUES(?,?,?,?,?)').run(username,passHash(password),first_name.trim(),last_name.trim(),position);db.prepare('INSERT INTO settings(user_id) VALUES(?)').run(x.lastInsertRowid);return x})();audit(req.userId,'create_user',Number(r.lastInsertRowid));res.json({id:Number(r.lastInsertRowid)});}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return fail(res,409,'Името е заето.');throw e}
});
app.patch('/api/admin/users/:id',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id))return fail(res,400,'Невалиден ID.');const id=Number(req.params.id),u=db.prepare('SELECT * FROM users WHERE id=?').get(id);if(!u)return fail(res,404,'Потребителят липсва.');
 const {username=u.username,first_name=u.first_name,last_name=u.last_name,position=u.position,password}=req.body;
 if(!validPosition(position))return fail(res,400,'Невалидна длъжност.');
 if(!validUsername(username)||!validName(first_name)||!validName(last_name)||(password!==undefined&&!validPassword(password)))return fail(res,400,'Невалидни данни.');
 try{db.prepare('UPDATE users SET username=?,first_name=?,last_name=?,position=?,password_hash=? WHERE id=?').run(username,first_name.trim(),last_name.trim(),position,password?passHash(password):u.password_hash,id);if(password)db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(req.userId,'edit_user',id,password?'password_reset':'profile');res.json({ok:true})}catch(e){if(e.code==='SQLITE_CONSTRAINT_UNIQUE')return fail(res,409,'Потребителското име е заето.');throw e}
});
app.post('/api/admin/users/:id/admin',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id)||typeof req.body.enabled!=='boolean')return fail(res,400,'Невалидни данни.');const id=Number(req.params.id);
 if(!db.prepare('SELECT 1 FROM users WHERE id=?').get(id))return fail(res,404,'Няма такъв потребител.');
 if(id===adminId)return fail(res,400,'Главният администратор се управлява от ADMIN_USER_ID.');
 if(id===req.userId&&!req.body.enabled)return fail(res,400,'Не можеш да премахнеш собствените си права.');
 if(req.body.enabled)db.prepare('INSERT OR IGNORE INTO admins(user_id,granted_by) VALUES(?,?)').run(id,req.userId);else db.prepare('DELETE FROM admins WHERE user_id=?').run(id);
 audit(req.userId,req.body.enabled?'grant_admin':'revoke_admin',id);res.json({ok:true});
});
app.delete('/api/admin/users/:id',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id))return fail(res,400,'Невалиден ID.');const id=Number(req.params.id);
 if(id===req.userId||id===adminId)return fail(res,403,'Не можеш да изтриеш този администратор.');
 if(!db.prepare('SELECT 1 FROM users WHERE id=?').get(id))return fail(res,404,'Потребителят липсва.');
 db.prepare('DELETE FROM users WHERE id=?').run(id);audit(req.userId,'delete_user',id);res.json({ok:true});
});
app.post('/api/admin/users/:id/shifts',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id)||!db.prepare('SELECT 1 FROM users WHERE id=?').get(req.params.id))return fail(res,404,'Потребителят липсва.');
 const shift=parseShift(req.body);if(!shift)return fail(res,400,'Невалидна смяна.');const r=db.prepare('INSERT INTO shifts(user_id,starts_at,ends_at,kind,note) VALUES(?,?,?,?,?)').run(req.params.id,shift.starts_at,shift.ends_at,shift.kind,shift.note);audit(req.userId,'add_shift',Number(req.params.id),String(r.lastInsertRowid));res.json({id:Number(r.lastInsertRowid)});
});
app.put('/api/admin/users/:id/shifts/:shiftId',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id)||!validId(req.params.shiftId))return fail(res,400,'Невалиден ID.');const shift=parseShift(req.body);if(!shift)return fail(res,400,'Невалидна смяна.');
 const r=db.prepare('UPDATE shifts SET starts_at=?,ends_at=?,kind=?,note=? WHERE id=? AND user_id=?').run(shift.starts_at,shift.ends_at,shift.kind,shift.note,req.params.shiftId,req.params.id);if(!r.changes)return fail(res,404,'Смяната липсва.');db.prepare('DELETE FROM sent_reminders WHERE shift_id=?').run(req.params.shiftId);audit(req.userId,'edit_shift',Number(req.params.id),req.params.shiftId);res.json({ok:true});
});
app.delete('/api/admin/users/:id/shifts/:shiftId',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id)||!validId(req.params.shiftId))return fail(res,400,'Невалиден ID.');const r=db.prepare('DELETE FROM shifts WHERE id=? AND user_id=?').run(req.params.shiftId,req.params.id);if(!r.changes)return fail(res,404,'Смяната липсва.');audit(req.userId,'delete_shift',Number(req.params.id),req.params.shiftId);res.json({ok:true});
});
app.put('/api/admin/users/:id/settings',auth,requireAdmin,(req,res)=>{
 if(!validId(req.params.id))return fail(res,400,'Невалиден ID.');const {hourly_rate,night_credit,reminder_minutes,holiday_mode='multiplier',holiday_value=2}=req.body;
 if(!Number.isFinite(hourly_rate)||hourly_rate<0||hourly_rate>10000||!Number.isFinite(night_credit)||night_credit<0||night_credit>24||![0,15,30,60,120,720,1440].includes(reminder_minutes)||!validHolidaySettings(holiday_mode,holiday_value))return fail(res,400,'Невалидни настройки.');
 const r=db.prepare('UPDATE settings SET hourly_rate=?,night_credit=?,reminder_minutes=?,holiday_mode=?,holiday_value=? WHERE user_id=?').run(hourly_rate,night_credit,reminder_minutes,holiday_mode,holiday_value,req.params.id);if(!r.changes)return fail(res,404,'Потребителят липсва.');audit(req.userId,'edit_settings',Number(req.params.id));res.json({ok:true});
});
app.get('/api/holiday-dates/:year',auth,(req,res)=>{const year=Number(req.params.year);if(!Number.isInteger(year)||year<2000||year>2100)return fail(res,400,'Невалидна година.');res.json([...holidayDates(year)].sort())});
app.get('/api/shifts',auth,(req,res)=>res.json(db.prepare('SELECT id,starts_at,ends_at,kind,note FROM shifts WHERE user_id=? ORDER BY starts_at').all(req.userId)));
function parseShift(body){const {starts_at,ends_at,kind,note=''}=body;if(typeof starts_at!=='string'||typeof ends_at!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(starts_at)||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(ends_at)||!['day','night','other'].includes(kind)||typeof note!=='string'||note.length>300)return null;const start=Date.parse(starts_at),end=Date.parse(ends_at);if(!Number.isFinite(start)||!Number.isFinite(end)||end<=start||end-start>24*3600000)return null;return {starts_at,ends_at,kind,note}}
app.post('/api/shifts',auth,(req,res)=>{const s=parseShift(req.body);if(!s)return fail(res,400,'Провери часовете и данните за смяната.');const r=db.prepare('INSERT INTO shifts(user_id,starts_at,ends_at,kind,note) VALUES(?,?,?,?,?)').run(req.userId,s.starts_at,s.ends_at,s.kind,s.note);res.json({id:r.lastInsertRowid,...s})});
app.put('/api/shifts/:id',auth,(req,res)=>{const s=parseShift(req.body);if(!s)return fail(res,400,'Невалидна смяна.');const r=db.prepare('UPDATE shifts SET starts_at=?,ends_at=?,kind=?,note=? WHERE id=? AND user_id=?').run(s.starts_at,s.ends_at,s.kind,s.note,req.params.id,req.userId);if(!r.changes)return fail(res,404,'Смяната не е намерена.');db.prepare('DELETE FROM sent_reminders WHERE shift_id=?').run(req.params.id);res.json({ok:true})});
app.delete('/api/shifts/:id',auth,(req,res)=>{const r=db.prepare('DELETE FROM shifts WHERE id=? AND user_id=?').run(req.params.id,req.userId);if(!r.changes)return fail(res,404,'Смяната не е намерена.');res.json({ok:true})});
function validHolidaySettings(mode,value){return ['multiplier','add_hour'].includes(mode)&&typeof value==='number'&&Number.isFinite(value)&&value>=0&&value<=10000&&(mode!=='multiplier'||value>=1)}
app.get('/api/settings',auth,(req,res)=>res.json(db.prepare('SELECT reminder_minutes,hourly_rate,night_credit,holiday_mode,holiday_value FROM settings WHERE user_id=?').get(req.userId)));
app.put('/api/settings',auth,(req,res)=>{const {reminder_minutes,hourly_rate,night_credit=13.5,holiday_mode='multiplier',holiday_value=2}=req.body;if(![0,15,30,60,120,720,1440].includes(reminder_minutes)||typeof hourly_rate!=='number'||!Number.isFinite(hourly_rate)||hourly_rate<0||hourly_rate>10000||typeof night_credit!=='number'||!Number.isFinite(night_credit)||night_credit<0||night_credit>24||!validHolidaySettings(holiday_mode,holiday_value))return fail(res,400,'Невалидни настройки.');db.prepare('UPDATE settings SET reminder_minutes=?,hourly_rate=?,night_credit=?,holiday_mode=?,holiday_value=? WHERE user_id=?').run(reminder_minutes,hourly_rate,night_credit,holiday_mode,holiday_value,req.userId);res.json({ok:true})});
app.get('/api/push/key',auth,(req,res)=>res.json({publicKey:vapidPublic||null}));
app.post('/api/push/subscribe',auth,(req,res)=>{if(!vapidPublic)return fail(res,503,'Push не е конфигуриран.');const sub=req.body;if(!sub||typeof sub.endpoint!=='string'||!sub.endpoint.startsWith('https://')||!sub.keys?.auth||!sub.keys?.p256dh)return fail(res,400,'Невалиден абонамент.');db.prepare('INSERT INTO subscriptions(user_id,endpoint,subscription_json) VALUES(?,?,?) ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id,subscription_json=excluded.subscription_json').run(req.userId,sub.endpoint,JSON.stringify(sub));res.json({ok:true})});
app.post('/api/push/test',auth,async(req,res)=>{if(!vapidPublic)return fail(res,503,'Push не е конфигуриран.');const subs=db.prepare('SELECT * FROM subscriptions WHERE user_id=?').all(req.userId);if(!subs.length)return fail(res,400,'Активирай известията първо.');await Promise.allSettled(subs.map(s=>webpush.sendNotification(JSON.parse(s.subscription_json),JSON.stringify({title:'ShiftMaster',body:'Тестовото известие работи!'}))));res.json({ok:true})});
async function sendReminders(){if(!vapidPublic)return;const now=Date.now();const rows=db.prepare(`SELECT s.id,s.starts_at,s.kind,s.user_id,t.reminder_minutes FROM shifts s JOIN settings t ON t.user_id=s.user_id WHERE t.reminder_minutes>0`).all();for(const row of rows){const start=Date.parse(row.starts_at),due=start-row.reminder_minutes*60000;if(due>now||now-due>60000)continue;const seen=db.prepare('INSERT OR IGNORE INTO sent_reminders(shift_id,minutes) VALUES(?,?)').run(row.id,row.reminder_minutes);if(!seen.changes)continue;const subs=db.prepare('SELECT * FROM subscriptions WHERE user_id=?').all(row.user_id);for(const sub of subs){try{await webpush.sendNotification(JSON.parse(sub.subscription_json),JSON.stringify({title:'Предстояща смяна',body:`Смяната ти започва след ${row.reminder_minutes} минути.`}))}catch(e){if(e.statusCode===404||e.statusCode===410)db.prepare('DELETE FROM subscriptions WHERE id=?').run(sub.id);else console.error('Push failed:',e.message)}}}}
setInterval(()=>sendReminders().catch(console.error),30000).unref();setInterval(()=>{db.prepare('DELETE FROM sessions WHERE expires_at<?').run(Date.now());attempts.clear()},3600000).unref();
app.listen(port,()=>console.log(`ShiftMaster: http://localhost:${port}`));
