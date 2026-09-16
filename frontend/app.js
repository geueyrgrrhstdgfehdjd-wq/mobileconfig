const API = window.NEXTRA_API || '/api';
const $=id=>document.getElementById(id);
let token=localStorage.getItem('nextra_token'), expiresAt=null, timerHandle=null;
async function verify(){
 const key=$('keyInput').value.trim(); if(!key)return;
 $('verifyBtn').disabled=true; $('loginMsg').textContent='Checking...';
 try{
  const r=await fetch(API+'/verify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key})});
  const d=await r.json(); if(!r.ok)throw Error(d.error||'Invalid key');
  token=d.token; expiresAt=d.expires_at; localStorage.setItem('nextra_token',token); showPanel(d);
 }catch(e){$('loginMsg').textContent=e.message}finally{$('verifyBtn').disabled=false}
}
function showPanel(d){
 $('login').classList.add('hidden'); $('panel').classList.remove('hidden'); $('statusText').textContent=d.lifetime?'LIFETIME':'ACTIVE'; tick();
}
function tick(){
 clearInterval(timerHandle);
 const draw=()=>{
  if(!expiresAt){$('timer').textContent='LIFETIME';return}
  const ms=new Date(expiresAt)-Date.now();
  if(ms<=0){$('timer').textContent='EXPIRED';$('statusText').textContent='EXPIRED';clearInterval(timerHandle);return}
  const s=Math.floor(ms/1000), days=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60), sec=s%60;
  $('timer').textContent=`${days}d ${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
  $('expiryText').textContent='Expires: '+new Date(expiresAt).toLocaleString();
 };
 draw(); timerHandle=setInterval(draw,1000);
}
async function restore(){
 if(!token)return;
 try{const r=await fetch(API+'/me',{headers:{Authorization:'Bearer '+token}});const d=await r.json();if(!r.ok)throw Error();expiresAt=d.expires_at;showPanel(d)}catch{localStorage.removeItem('nextra_token')}
}
$('verifyBtn').onclick=verify;$('keyInput').onkeydown=e=>{if(e.key==='Enter')verify()};
$('logoutBtn').onclick=()=>{localStorage.removeItem('nextra_token');location.reload()};
document.querySelectorAll('.feature').forEach(b=>b.onclick=()=>{document.querySelectorAll('.feature').forEach(x=>x.classList.remove('active'));b.classList.add('active');$('featureMsg').textContent=b.dataset.feature+' selected.'});
restore();
