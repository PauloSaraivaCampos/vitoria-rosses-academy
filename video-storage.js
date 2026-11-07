'use strict';
const crypto=require('node:crypto');
const Busboy=require('busboy');
const {S3Client,GetObjectCommand,DeleteObjectCommand}=require('@aws-sdk/client-s3');
const {Upload}=require('@aws-sdk/lib-storage');
const {getSignedUrl}=require('@aws-sdk/s3-request-presigner');
const validConfig=['VIDEO_BUCKET_ENDPOINT','VIDEO_BUCKET_NAME','VIDEO_BUCKET_ACCESS_KEY','VIDEO_BUCKET_SECRET_KEY'].every(k=>Boolean(process.env[k]));
const bucket=process.env.VIDEO_BUCKET_NAME;
const client=validConfig?new S3Client({region:process.env.VIDEO_BUCKET_REGION||'auto',endpoint:process.env.VIDEO_BUCKET_ENDPOINT,credentials:{accessKeyId:process.env.VIDEO_BUCKET_ACCESS_KEY,secretAccessKey:process.env.VIDEO_BUCKET_SECRET_KEY},forcePathStyle:false}):null;
const types={'video/mp4':'.mp4','video/webm':'.webm','video/ogg':'.ogv'};
const MAX=500*1024*1024;
function isPrivate(ref){return typeof ref==='string'&&/^private-video:classes\/\d+\/\d+\/[a-f0-9]{32}\.(mp4|webm|ogv)$/.test(ref)}
async function signed(ref){
 if(!client)throw Error('Armazenamento privado indisponível');
 return getSignedUrl(client,new GetObjectCommand({Bucket:bucket,Key:ref.slice('private-video:'.length)}),{expiresIn:3600});
}
async function upload({req,db,course,lesson}){
 if(!client)throw Object.assign(Error('Armazenamento privado não configurado'),{status:503});
 if(!Number.isInteger(course)||course<1||course>999||!Number.isInteger(lesson)||lesson<0||lesson>29)throw Object.assign(Error('Aula inválida'),{status:400});
 const row=(await db.query('SELECT data FROM academy_data WHERE id=1')).rows[0];
 const data=row?.data||{},counts={1:12,2:10,3:8,4:15,5:12,6:9,7:7,8:8};
 const count=counts[course]||((data.customCourses||[]).find(c=>Number(c.id)===course)?.count||0);
 if(!count||lesson>=count)throw Object.assign(Error('Aula não cadastrada'),{status:404});
 let bus;
 try{bus=Busboy({headers:req.headers,limits:{files:1,fields:0,parts:1,fileSize:MAX}})}
 catch{throw Object.assign(Error('Selecione um arquivo de vídeo'),{status:400})}
 let gotFile=false,limited=false,invalid=false,key=null,task=null;
 bus.on('file',(_field,file,info)=>{
  if(gotFile){file.resume();return}
  gotFile=true;
  const mime=String(info.mimeType||'').toLowerCase(),ext=types[mime],filename=String(info.filename||'');
  if(!ext||!filename.toLowerCase().endsWith(ext)){invalid=true;file.resume();return}
  key='classes/'+course+'/'+lesson+'/'+crypto.randomBytes(16).toString('hex')+ext;
  file.on('limit',()=>{limited=true});
  task=new Upload({client,params:{Bucket:bucket,Key:key,Body:file,ContentType:mime,CacheControl:'private, no-store'},queueSize:2,partSize:8*1024*1024,leavePartsOnError:false}).done();
  task.catch(()=>{});
 });
 try{
  await new Promise((resolve,reject)=>{bus.once('error',reject);bus.once('finish',resolve);req.once('aborted',()=>reject(Error('Conexão interrompida')));req.pipe(bus)});
  if(!gotFile)throw Object.assign(Error('Selecione um arquivo de vídeo'),{status:400});
  if(invalid)throw Object.assign(Error('Use somente arquivos MP4, WebM ou OGG'),{status:415});
  if(limited)throw Object.assign(Error('O tamanho máximo é 500 MB'),{status:413});
  if(!task)throw Error('Falha ao iniciar upload');
  await task;
  if(limited)throw Object.assign(Error('O tamanho máximo é 500 MB'),{status:413});
  const ref='private-video:'+key,previous=data.videoLessons?.[course+':'+lesson];
  await db.query('UPDATE academy_data SET data=jsonb_set(data,$1::text[],$2::jsonb,true) WHERE id=1',[['videoLessons',course+':'+lesson],JSON.stringify(ref)]);
  if(isPrivate(previous))client.send(new DeleteObjectCommand({Bucket:bucket,Key:previous.slice('private-video:'.length)})).catch(e=>console.warn('Cleanup failed:',e.message));
  return {ok:true,stored:true,maxSizeMB:500};
 }catch(err){
  if(key)try{await client.send(new DeleteObjectCommand({Bucket:bucket,Key:key}))}catch(e){console.warn('Upload cleanup failed:',e.message)}
  throw err;
 }
}
async function remove({db,course,lesson}){
 if(!Number.isInteger(course)||course<1||!Number.isInteger(lesson)||lesson<0||lesson>29)throw Object.assign(Error('Aula inválida'),{status:400});
 const row=(await db.query("SELECT data->'videoLessons' AS videos FROM academy_data WHERE id=1")).rows[0];
 const ref=row?.videos?.[course+':'+lesson];
 await db.query('UPDATE academy_data SET data=data #- $1::text[] WHERE id=1',[['videoLessons',course+':'+lesson]]);
 if(isPrivate(ref)&&client)try{await client.send(new DeleteObjectCommand({Bucket:bucket,Key:ref.slice('private-video:'.length)}))}catch(e){console.warn('Deletion failed:',e.message)}
 return {ok:true};
}
module.exports={isPrivate,signed,upload,remove,isReady:()=>Boolean(client)};
