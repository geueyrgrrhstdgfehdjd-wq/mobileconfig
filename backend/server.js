const express=require('express'),crypto=require('crypto'),fs=require('fs'),path=require('path');
const app=express(),PORT=process.env.PORT||3000,ADMIN_KEY=process.env.NEXTRA_ADMIN_KEY||'CHANGE_ME';
const dbFile=path.join(__dirname,'data','keys.json');if(!fs.existsSync(dbFile))fs.writeFileSync(dbFile,'[]');
const read=()=>JSON.parse(fs.readFileSync(dbFile,'utf8'));const write=x=>fs.writeFileSync(dbFile,JSON.stringify(x,null,2));
const tokenMap=new Map(),adminTokens=new Set();app.use(express.json());app.use(express.static(path.join(__dirname,'../frontend')));
function makeKey(){return 'NX-'+crypto.randomBytes(5).toString('hex').toUpperCase()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase()}
function auth(req,res,next){const t=(req.headers.authorization||'').replace('Bearer ','');const k=tokenMap.get(t);if(!k)return res.status(401).json({error:'Unauthorized'});const db=read().find(x=>x.id===k.id);if(!db||db.revoked)return res.status(401).json({error:'Key revoked'});req.key=db;next()}
function admin(req,res,next){const t=(req.headers.authorization||'').replace('Bearer ','');if(!adminTokens.has(t))return res.status(401).json({error:'Admin unauthorized'});next()}
app.post('/api/verify',(req,res)=>{const key=String(req.body.key||'').trim();let db=read().find(x=>x.key===key&&!x.revoked);if(!db)return res.status(401).json({error:'Invalid key'});
 if(!db.activated_at){db.activated_at=new Date().toISOString();if(db.duration_days)db.expires_at=new Date(Date.now()+db.duration_days*86400000).toISOString();let all=read();all=all.map(x=>x.id===db.id?db:x);write(all)}
 const token=crypto.randomBytes(24).toString('hex');tokenMap.set(token,{id:db.id});res.json({token,expires_at:db.expires_at||null,lifetime:!db.duration_days});
});
app.get('/api/me',auth,(req,res)=>res.json({expires_at:req.key.expires_at||null,lifetime:!req.key.duration_days}));
app.post('/api/admin/login',(req,res)=>{if(String(req.body.key||'')!==ADMIN_KEY)return res.status(401).json({error:'Invalid admin key'});const t=crypto.randomBytes(24).toString('hex');adminTokens.add(t);res.json({token:t})});
app.get('/api/admin/keys',admin,(req,res)=>{const all=read();const now=Date.now();res.json({stats:{total:all.length,active:all.filter(x=>!x.revoked&&(!x.expires_at||new Date(x.expires_at)>now)).length,users:new Set(all.filter(x=>x.activated_at).map(x=>x.device_id||x.id)).size},keys:all.map(({id,key,duration_days,activated_at,expires_at,revoked})=>({id,key,duration_days,activated_at,expires_at,status:revoked?'REVOKED':(expires_at&&new Date(expires_at)<=now?'EXPIRED':'ACTIVE')}))})});
app.post('/api/admin/generate',admin,(req,res)=>{const days=Number(req.body.days);const quantity=Math.min(100,Math.max(1,Number(req.body.quantity)||1));const all=read(),out=[];for(let i=0;i<quantity;i++){const k={id:crypto.randomUUID(),key:makeKey(),duration_days:days||0,activated_at:null,expires_at:null,revoked:false};all.push(k);out.push(k.key)}write(all);res.json({keys:out})});
app.post('/api/admin/revoke/:id',admin,(req,res)=>{const all=read().map(x=>x.id===req.params.id?{...x,revoked:true}:x);write(all);res.json({ok:true})});
app.get('/nextra.mobileconfig',(req,res)=>{
  const base=(process.env.RENDER_EXTERNAL_URL||`${req.protocol}://${req.get('host')}`).replace(/\\/$/,'');
  const profile=`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>FullScreen</key><true/><key>IsRemovable</key><true/>
<key>Label</key><string>NEXTRA</string>
<key>PayloadDescription</key><string>NEXTRA Web Clip</string>
<key>PayloadDisplayName</key><string>NEXTRA Web Clip</string>
<key>PayloadIdentifier</key><string>com.nextra.webclip</string>
<key>PayloadOrganization</key><string>NEXTRA</string>
<key>PayloadType</key><string>com.apple.webClip.managed</string>
<key>PayloadUUID</key><string>7D4F2A9C-7A4D-4F5B-9C4D-1A8A2F3E7B11</string>
<key>PayloadVersion</key><integer>1</integer>
<key>URL</key><string>${base}/</string>
</dict></array>
<key>PayloadDisplayName</key><string>NEXTRA</string>
<key>PayloadIdentifier</key><string>com.nextra.profile</string>
<key>PayloadOrganization</key><string>NEXTRA</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>9A3B8F1C-2D6E-45F7-AB8D-5C1E3F7A9B20</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>`;
  res.type('application/x-apple-aspen-config').send(profile);
});
app.listen(PORT,()=>console.log('NEXTRA backend on http://localhost:'+PORT));
