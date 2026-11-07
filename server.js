'use strict';
const http=require('node:http'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {Pool}=require('pg');
const root=__dirname,PORT=Number(process.env.PORT)||3000;
const db=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:false,max:8}):null;
const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.pdf':'application/pdf','.ico':'image/x-icon'};
const blank=()=>({globalLocks:{},customCourses:[],settings:{},videoLessons:{},certificateHours:{},certificateSignature:'',announcements:[],monthlyPayments:[],orders:[]});
const ok=(res,data,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});res.end(JSON.stringify(data))};
const fail=(res,msg,status=400)=>ok(res,{error:msg},status);
const tokenHash=t=>crypto.createHash('sha256').update(t).digest('hex');
const validPassword=p=>typeof p==='string'&&p.length>=10&&p.length<=256;
const validEmail=e=>typeof e==='string'&&/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)&&e.length<255;
function hashPassword(password){const salt=crypto.randomBytes(16).toString('hex');return salt+':'+crypto.scryptSync(password,salt,64).toString('hex')}
function passwordValid(password,stored){try{const [salt,hex]=stored.split(':');const expected=Buffer.from(hex,'hex'),actual=crypto.scryptSync(password,salt,expected.length);return crypto.timingSafeEqual(expected,actual)}catch{return false}}
async function readBody(req){let value='';for await(const x of req){value+=x;if(value.length>300000)throw Error('Requisição muito grande')}return JSON.parse(value||'{}')}
async function init(){
 if(!db)return;
 await db.query('CREATE TABLE IF NOT EXISTS users(id BIGSERIAL PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL DEFAULT \'student\',plans JSONB NOT NULL DEFAULT \'[]\',grants JSONB NOT NULL DEFAULT \'{}\',progress JSONB NOT NULL DEFAULT \'{}\',notes JSONB NOT NULL DEFAULT \'{}\',certificate_dates JSONB NOT NULL DEFAULT \'{}\',created_at TIMESTAMPTZ NOT NULL DEFAULT now())');
 await db.query('CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at TIMESTAMPTZ NOT NULL)');
 await db.query('CREATE TABLE IF NOT EXISTS academy_data(id INT PRIMARY KEY CHECK(id=1), data JSONB NOT NULL DEFAULT \'{}\')');
 await db.query('INSERT INTO academy_data(id,data) VALUES (1,$1) ON CONFLICT (id) DO NOTHING',[JSON.stringify(blank())]);
 await db.query('CREATE INDEX IF NOT EXISTS sessions_expiration ON sessions(expires_at)');
}
async function identify(req){if(!db)return null;const cookies=Object.fromEntries((req.headers.cookie||'').split(';').map(x=>x.trim().split('=').map(decodeURIComponent)));const token=cookies.vra_sid;if(!token||! /^[a-f0-9]{64}$/.test(token))return null;const r=await db.query('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[tokenHash(token)]);return r.rows[0]||null}
async function makeSession(res,user){const token=crypto.randomBytes(32).toString('hex');await db.query("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '14 days')",[tokenHash(token),user.id]);res.setHeader('Set-Cookie','vra_sid='+token+'; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=1209600')}
function publicUser(u){return {name:u.name,email:u.email,role:u.role,plans:u.plans||[],grants:u.grants||{},progress:u.progress||{},notes:u.notes||{},certificateDates:u.certificate_dates||{}}}
const asObj=v=>v&&typeof v==='object'&&!Array.isArray(v)?v:{};
const asArr=v=>Array.isArray(v)?v:[];
const safeStr=(v,max=1000)=>typeof v==='string'?v.slice(0,max):'';
async function stateFor(user){const [data,users]=await Promise.all([db.query('SELECT data FROM academy_data WHERE id=1'),user.role==='admin'?db.query('SELECT * FROM users ORDER BY id'):Promise.resolve({rows:[user]})]);const source={...blank(),...asObj(data.rows[0].data)};if(user.role!=='admin'){delete source.monthlyPayments;delete source.orders;source.announcements=asArr(source.announcements);source.videoLessons={}}return {...source,users:users.rows.map(publicUser)}}
async function updateState(user,payload){
 const client=await db.connect();try{
  await client.query('BEGIN');
  if(user.role==='admin'){
   await client.query('SELECT data FROM academy_data WHERE id=1 FOR UPDATE');
   const previous=(await client.query('SELECT data FROM academy_data WHERE id=1')).rows[0].data;
   const next={...previous};
   for(const key of ['globalLocks','settings','videoLessons','certificateHours']){if(payload[key]!==undefined)next[key]=asObj(payload[key])}
   for(const key of ['customCourses','announcements','monthlyPayments','orders']){if(payload[key]!==undefined)next[key]=asArr(payload[key]).slice(0,3000)}
   if(payload.certificateSignature!==undefined)next.certificateSignature=safeStr(payload.certificateSignature,200);
   await client.query('UPDATE academy_data SET data=$1 WHERE id=1',[JSON.stringify(next)]);
  }else{
   const own=asArr(payload.users).find(x=>x?.email===user.email);
   if(!own)throw Error('Usuário não encontrado');
   await client.query('UPDATE users SET notes=$1 WHERE id=$2',[JSON.stringify(asObj(own.notes)),user.id]);
  }
  await client.query('COMMIT');
 }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
}
const failedLogins=new Map();
async function api(req,res,url){
 if(!db)return fail(res,'Banco não configurado',503);
 const route=url.pathname,method=req.method;
 if(method!=='GET'&&method!=='HEAD'){const origin=req.headers.origin;if(origin&&origin!==('https://'+req.headers.host)&&origin!==('http://'+req.headers.host))return fail(res,'Origem não permitida',403)}
 if(route==='/api/health')return ok(res,{ok:true,db:true});
 if(route==='/api/setup-status'&&method==='GET'){const r=await db.query("SELECT COUNT(*)::int n FROM users WHERE role='admin'");return ok(res,{setupRequired:r.rows[0].n===0})}
 if(route==='/api/setup'&&method==='POST'){
  const x=await readBody(req);if(!process.env.ADMIN_SETUP_TOKEN)return fail(res,'Configuração do administrador indisponível',503);
  const given=Buffer.from(String(x.token||'')),expected=Buffer.from(process.env.ADMIN_SETUP_TOKEN);
  if(given.length!==expected.length||!crypto.timingSafeEqual(given,expected))return fail(res,'Código de configuração inválido',403);
  if(!validEmail(x.email)||!validPassword(x.password)||!safeStr(x.name,120))return fail(res,'Nome, e-mail e senha de pelo menos 10 caracteres são obrigatórios');
  const count=await db.query("SELECT COUNT(*)::int n FROM users WHERE role='admin'");if(count.rows[0].n>0)return fail(res,'Administrador já configurado',409);
  const u=await db.query("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'admin') RETURNING *",[safeStr(x.name,120),x.email.toLowerCase(),hashPassword(x.password)]);await makeSession(res,u.rows[0]);return ok(res,{user:publicUser(u.rows[0])},201)
 }
 if(route==='/api/register'&&method==='POST'){
  const x=await readBody(req);if(!validEmail(x.email)||!validPassword(x.password)||!safeStr(x.name,120).trim())return fail(res,'Informe nome, e-mail e senha de pelo menos 10 caracteres');
  try{const u=await db.query("INSERT INTO users(name,email,password_hash,role) VALUES($1,$2,$3,'student') RETURNING *",[safeStr(x.name,120),x.email.toLowerCase(),hashPassword(x.password)]);await makeSession(res,u.rows[0]);return ok(res,{user:publicUser(u.rows[0])},201)}catch(e){if(e.code==='23505')return fail(res,'E-mail já cadastrado',409);throw e}
 }
 if(route==='/api/login'&&method==='POST'){
  const ip=(req.socket.remoteAddress||'unknown'),r=failedLogins.get(ip)||{n:0,until:0};if(r.n>=12&&Date.now()<r.until)return fail(res,'Muitas tentativas. Tente novamente mais tarde.',429);
  const x=await readBody(req);const u=await db.query('SELECT * FROM users WHERE email=$1',[safeStr(x.email,255).toLowerCase()]);if(!u.rowCount||!passwordValid(safeStr(x.password,256),u.rows[0].password_hash)){failedLogins.set(ip,{n:r.n+1,until:Date.now()+900000});return fail(res,'E-mail ou senha incorretos',401)}
  failedLogins.delete(ip);await makeSession(res,u.rows[0]);return ok(res,{user:publicUser(u.rows[0])})
 }
 if(route==='/api/logout'&&method==='POST'){const u=await identify(req);if(u){const t=(req.headers.cookie||'').match(/vra_sid=([a-f0-9]{64})/);if(t)await db.query('DELETE FROM sessions WHERE token_hash=$1',[tokenHash(t[1])])}res.setHeader('Set-Cookie','vra_sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');return ok(res,{ok:true})}
 const user=await identify(req);if(!user)return fail(res,'Sessão expirada ou acesso não autorizado',401);
 if(route==='/api/session'&&method==='GET')return ok(res,{user:publicUser(user)});

 const isCourseAllowed=(u,id)=>u.role==='admin'||asObj(u.grants)[id]===true||asArr(u.plans).some(p=>({essencial:[1,3,7],profissional:[1,2,3,4,5,7,8],master:[1,2,3,4,5,6,7,8]})[p]?.includes(Number(id)));
 const isLessonUnlocked=async(u,id,n)=>{if(!isCourseAllowed(u,id))return false;const result=await db.query('SELECT data FROM academy_data WHERE id=1');const locks=asObj(result.rows[0]?.data?.globalLocks);return locks[id+':'+n]!==true&&asObj(u.grants)[id+':'+n]!==false};
 if(route==='/api/lesson/complete'&&method==='POST'){
  if(user.role!=='student')return fail(res,'Somente alunas podem concluir aulas',403);
  const x=await readBody(req),id=Number(x.course),n=Number(x.lesson);
  if(!Number.isInteger(id)||!Number.isInteger(n)||id<1||n<0||n>29)return fail(res,'Aula inválida');
  if(!await isLessonUnlocked(user,id,n))return fail(res,'Aula bloqueada',403);
  const client=await db.connect();
  try{
   await client.query('BEGIN');
   const c=(await client.query('SELECT data FROM academy_data WHERE id=1')).rows[0]?.data;
   const course=({1:12,2:10,3:8,4:15,5:12,6:9,7:7,8:8})[id]||asArr(c.customCourses).find(y=>Number(y.id)===id)?.count||0;
   if(n>=course)return fail(res,'Aula inexistente',404);
   const video=asObj(c.videoLessons)[id+':'+n];
   if(typeof video!=='string'||!video.startsWith('https://')){await client.query('ROLLBACK');return fail(res,'Esta aula ainda não possui vídeo cadastrado',409)}
   const current=(await client.query('SELECT progress,certificate_dates FROM users WHERE id=$1 FOR UPDATE',[user.id])).rows[0];
   const progress={...asObj(current.progress),[id+':'+n]:true};
   const dates={...asObj(current.certificate_dates)};
   if(Array.from({length:course},(_,i)=>progress[id+':'+i]===true).every(Boolean)&&!dates[id])dates[id]=new Date().toISOString().slice(0,10);
   await client.query('UPDATE users SET progress=$1,certificate_dates=$2 WHERE id=$3',[JSON.stringify(progress),JSON.stringify(dates),user.id]);
   await client.query('COMMIT');return ok(res,{ok:true,progress,certificateDates:dates});
  }catch(err){await client.query('ROLLBACK');throw err}finally{client.release()}
 }
 if(route==='/api/video'&&method==='GET'){
  const id=Number(url.searchParams.get('course')),n=Number(url.searchParams.get('lesson'));
  if(!Number.isInteger(id)||!Number.isInteger(n)||id<1||n<0||n>30)return fail(res,'Aula inválida');
  if(!await isLessonUnlocked(user,id,n))return fail(res,'Acesso à aula não autorizado',403);
  const data=(await db.query('SELECT data FROM academy_data WHERE id=1')).rows[0]?.data;
  const link=asObj(data?.videoLessons)[id+':'+n];
  if(typeof link!=='string'||!/^https:\/\/[^\s]+$/i.test(link))return fail(res,'Vídeo ainda não cadastrado',404);
  return ok(res,{url:link});
 }
 if(route==='/api/certificate/check'&&method==='GET'){
  const id=Number(url.searchParams.get('course'));
  if(!Number.isInteger(id)||id<1)return fail(res,'Curso inválido');
  if(!isCourseAllowed(user,id))return fail(res,'Curso não liberado',403);
  const n=({1:12,2:10,3:8,4:15,5:12,6:9,7:7,8:8})[id]||0;
  if(!n)return fail(res,'Curso sem certificado configurado',404);
  for(let i=0;i<n;i++)if(asObj(user.progress)[id+':'+i]!==true)return fail(res,'Curso ainda não concluído',403);
  const d=(await db.query('SELECT data FROM academy_data WHERE id=1')).rows[0]?.data;
  const hours=Number(asObj(d?.certificateHours)[id]||0);
  if(hours<=0)return fail(res,'Carga horária não configurada',409);
  return ok(res,{ok:true,name:user.name,hours,date:asObj(user.certificate_dates)[id]||new Date().toISOString().slice(0,10)});
 }
 if(route==='/api/admin/access'&&method==='POST'){
  if(user.role!=='admin')return fail(res,'Acesso reservado à administração',403);
  const x=await readBody(req),email=safeStr(x.email,255).toLowerCase(),id=Number(x.course),lesson=x.lesson;
  if(!validEmail(email)||!Number.isInteger(id)||id<1||id>999)return fail(res,'Dados inválidos');
  if(x.action==='grant'&&typeof x.value==='boolean'){
    const result=await db.query("UPDATE users SET grants=jsonb_set(grants,$1::text[],$2::jsonb,true) WHERE email=$3 AND role='student' RETURNING id",[[String(id)],JSON.stringify(x.value),email]);
    return result.rowCount?ok(res,{ok:true}):fail(res,'Aluna não encontrada',404);
  }
  if(x.action==='lesson'&&Number.isInteger(lesson)&&lesson>=0&&lesson<30&&typeof x.value==='boolean'){
    const result=await db.query("UPDATE users SET grants=jsonb_set(grants,$1::text[],$2::jsonb,true) WHERE email=$3 AND role='student' RETURNING id",[[id+':'+lesson],JSON.stringify(x.value),email]);
    return result.rowCount?ok(res,{ok:true}):fail(res,'Aluna não encontrada',404);
  }
  if(x.action==='plan'&&typeof x.value==='string'&&['essencial','profissional','master','none'].includes(x.value)){
    const plans=x.value==='none'?[]:[x.value];const result=await db.query("UPDATE users SET plans=$1 WHERE email=$2 AND role='student' RETURNING id",[JSON.stringify(plans),email]);
    return result.rowCount?ok(res,{ok:true}):fail(res,'Aluna não encontrada',404);
  }
  return fail(res,'Operação inválida');
 }
 if(route==='/api/admin/locks'&&method==='POST'){
  if(user.role!=='admin')return fail(res,'Acesso reservado à administração',403);
  const x=await readBody(req);if(!Number.isInteger(x.course)||!Number.isInteger(x.lesson)||x.course<1||x.lesson<0||x.lesson>30||typeof x.value!=='boolean')return fail(res,'Dados inválidos');
  await db.query("UPDATE academy_data SET data=jsonb_set(data,$1::text[],$2::jsonb,true) WHERE id=1",[['globalLocks',x.course+':'+x.lesson],JSON.stringify(x.value)]);return ok(res,{ok:true});
 }
 if(route==='/api/state'&&method==='GET')return ok(res,{state:await stateFor(user)});
 if(route==='/api/state'&&method==='POST'){const x=await readBody(req);await updateState(user,x);return ok(res,{ok:true})}
 return fail(res,'Rota não encontrada',404)
}
const server=http.createServer(async(req,res)=>{try{
 const url=new URL(req.url,'http://localhost'),pathname=decodeURIComponent(url.pathname);
 if(pathname.startsWith('/api/'))return await api(req,res,url);
 const filename=path.resolve(root,'.'+(pathname==='/'?'/index.html':pathname));
 if(!filename.startsWith(root+path.sep))return res.writeHead(403).end('Forbidden');
 fs.stat(filename,(err,stat)=>{if(err||!stat.isFile())return res.writeHead(404).end('Not found');const ext=path.extname(filename).toLowerCase();res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-store':'public, max-age=300','X-Content-Type-Options':'nosniff','Content-Security-Policy':"frame-ancestors 'self'"});fs.createReadStream(filename).pipe(res)})
 }catch(e){console.error('Request error',e.message);fail(res,'Falha no servidor',500)}});
init().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log('Vitória Rossés Academy backend ativo na porta '+PORT))).catch(e=>{console.error('Database initialization error',e.message);process.exit(1)});
