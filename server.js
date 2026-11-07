const http=require('node:http');
const fs=require('node:fs');
const path=require('node:path');
const root=__dirname;
const types={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp','.svg':'image/svg+xml','.pdf':'application/pdf','.ico':'image/x-icon'};
const server=http.createServer((req,res)=>{
 let pathname;try{pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname)}catch{res.writeHead(400).end('Bad request');return}
 if(pathname==='/'||pathname==='')pathname='/index.html';
 const filename=path.resolve(root,'.'+pathname);
 if(!filename.startsWith(root+path.sep)){res.writeHead(403).end('Forbidden');return}
 fs.stat(filename,(err,stat)=>{
  if(err||!stat.isFile()){res.writeHead(404).end('Not found');return}
  const ext=path.extname(filename).toLowerCase();
  res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=300','X-Content-Type-Options':'nosniff'});
  fs.createReadStream(filename).pipe(res);
 });
});
server.listen(Number(process.env.PORT)||3000,'0.0.0.0',()=>console.log('Vitória Rossés Academy online'));
