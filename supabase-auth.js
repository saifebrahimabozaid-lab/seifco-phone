(()=>{'use strict';
const cfg=window.SEIFCO_SUPABASE;
const KEY='seifco-supabase-session-v1';
let session=null;
try{session=JSON.parse(localStorage.getItem(KEY)||'null')}catch(_){}
const save=s=>{session=s; if(s)localStorage.setItem(KEY,JSON.stringify(s));else localStorage.removeItem(KEY)};
async function request(path,{method='GET',body,token}={}){
 const headers={'apikey':cfg.anonKey,'Content-Type':'application/json'};
 if(token||session?.access_token)headers.Authorization='Bearer '+(token||session.access_token);
 const res=await fetch(cfg.url+path,{method,headers,body:body?JSON.stringify(body):undefined});
 const data=await res.json().catch(()=>({}));
 if(!res.ok)throw new Error(data.msg||data.message||data.error_description||data.error||('Supabase error '+res.status));
 return data;
}
async function signIn(email,password){
 const data=await request('/auth/v1/token?grant_type=password',{method:'POST',body:{email,password}});
 save(data);return data;
}
async function signUp(email,password,displayName){
 const data=await request('/auth/v1/signup',{method:'POST',body:{email,password,data:{display_name:displayName||'مدير المحل'}}});
 if(data.access_token)save(data);
 return data;
}
async function signOut(){
 try{if(session?.access_token)await request('/auth/v1/logout',{method:'POST'})}finally{save(null)}
}
async function profile(){
 if(!session?.user?.id)return null;
 const rows=await request('/rest/v1/profiles?select=id,shop_id,display_name,role&id=eq.'+encodeURIComponent(session.user.id));
 return rows[0]||null;
}
function status(){return session?.user?{signedIn:true,email:session.user.email||'',expiresAt:session.expires_at||null}:{signedIn:false}}
window.SeifcoBackend={signIn,signUp,signOut,profile,status,getSession:()=>session,request};
})();