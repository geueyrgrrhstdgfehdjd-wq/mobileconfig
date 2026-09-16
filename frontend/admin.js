const API=window.NEXTRA_API||'/api';let adminToken=localStorage.getItem('nextra_admin');
const $=x=>document.getElementById(x);
async function login(){
 const r=await fetch(API+'/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:$('adminKey').value.trim()})});
 const d=await r.json();if(!r.ok){$('adminMsg').textContent=d.error||'Login failed';return}
 adminToken=d.token;localStorage.setItem('nextra_admin',adminToken);load();
}
async function load(){
 const r=await fetch(API+'/admin/keys',{headers:{Authorization:'Bearer '+adminToken}});if(!r.ok)return;
 const d=await r.json();$('dash').classList.remove('hidden');$('keyCount').textContent=d.stats.total;$('activeCount').textContent=d.stats.active;$('userCount').textContent=d.stats.users;
 $('keys').innerHTML=d.keys.map(k=>`<div class="key-row"><span>${k.key} · ${k.duration_days? k.duration_days+'d':'LIFETIME'} · ${k.status}</span><button class="ghost danger" onclick="revoke('${k.id}')">REVOKE</button></div>`).join('');
}
async function generate(){
 const r=await fetch(API+'/admin/generate',{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+adminToken},body:JSON.stringify({days:Number($('duration').value),quantity:Number($('quantity').value)})});
 const d=await r.json();$('generated').textContent=(d.keys||[]).join('\n');load();
}
async function revoke(id){await fetch(API+'/admin/revoke/'+id,{method:'POST',headers:{Authorization:'Bearer '+adminToken}});load()}
$('adminLogin').onclick=login;$('generate').onclick=generate;if(adminToken)load();
