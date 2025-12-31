import{connect as $c}from'cloudflare:sockets';
const $d=new TextDecoder(),$e=new TextEncoder();
let $u=null,$cfg={};

const $fn={
  g:(n,f,e)=>{
    const v=import.meta?.env?.[n]??e?.[n];
    if(!v)return f;
    if(typeof v!=='string')return v;
    const t=v.trim();
    if(t==='true')return!0;
    if(t==='false')return!1;
    if(t.includes('\n'))return t.split('\n').map(x=>x.trim()).filter(Boolean);
    const m=Number(t);
    return isNaN(m)?t:m;
  },
  h:s=>Uint8Array.from(s.replace(/-/g,'').match(/.{2}/g).map(x=>parseInt(x,16))),
  c:b=>$u.every((x,i)=>b[i]===x),
  t:ip=>'2001:67c:2960:6464::'+ip.split('.').map(x=>(+x).toString(16).padStart(2,'0')).join('').match(/.{4}/g).join(':'),
  b:s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)).buffer
};

const $i=e=>{
  if($cfg.done)return $cfg;
  const m={I:['ID','123456'],U:['UUID','89e4c6c8-88b4-4c7a-a1ed-8d2e3c4f5a6b'],P:['IP',['1.1.1.1']],T:['TXT',[]],R:['PROXYIP',''],F:['\u542f\u7528\u53cd\u4ee3\u529f\u80fd',false],N:['NAT64',false],N2:['\u6211\u7684\u8282\u70b9\u540d\u5b57','\u72c2\u66b4'],S:['SUB','vless']};
  for(const[k,[k2,d]]of Object.entries(m))$cfg[k]=$fn.g(k2,d,e);
  $cfg.B=$u=$fn.h($cfg.U);
  $cfg.done=1;
  return $cfg;
};

const $conn=async(h,p,cfg,init)=>{
  try{
    const s=await $c({hostname:h,port:p});
    await s.opened;
    return{tcpSocket:s,initialData:init};
  }catch{}
  if(cfg.N&&/^\d+\.\d+\.\d+\.\d+$/.test(h)){
    try{return await $conn($fn.t(h),p,{...cfg,N:0},init);}catch{}
  }
  if(cfg.F&&cfg.R){
    const[h2,p2]=cfg.R.split(':');
    return await $conn(h2,Number(p2||p),{...cfg,F:0},init);
  }
  throw new Error('\u8fde\u63a5\u5931\u8d25');
};

const $parse=async(buf,cfg)=>{
  const c=new Uint8Array(buf),t=c[17],p=(c[18+t+1]<<8)|c[18+t+2];
  let o=18+t+4,h='';
  switch(c[o-1]){
    case 1:h=`${c[o++]}.${c[o++]}.${c[o++]}.${c[o++]}`;break;
    case 2:{const l=c[o++];h=$d.decode(c.subarray(o,o+l));o+=l;break;}
    case 3:h=Array.from({length:8},(_,i)=>((c[o+2*i]<<8)|c[o+2*i+1]).toString(16)).join(':');o+=16;break;
  }
  return await $conn(h,p,cfg,buf.slice(o));
};

const $tun=(ws,tcp,init)=>{
  const w=tcp.writable.getWriter();
  ws.send(new Uint8Array([0,0]));
  if(init)w.write(init);
  let b=[],t;
  ws.addEventListener('message',({data:d})=>{
    const c=d instanceof ArrayBuffer?new Uint8Array(d):typeof d==='string'?$e.encode(d):d;
    b.push(c);
    if(!t)t=setTimeout(()=>{
      w.write(b.length===1?b[0]:b.reduce((a,b)=>{
        const o=new Uint8Array(a.length+b.length);
        o.set(a);o.set(b,a.length);return o;
      }));
      b=[];t=null;
    },5);
  });
  tcp.readable.pipeTo(new WritableStream({
    write:c=>ws.send(c),
    close:()=>ws.close(),
    abort:()=>ws.close()
  })).catch(()=>ws.close());
  ws.addEventListener('close',()=>{
    try{w.releaseLock();tcp.close();}catch{}
  });
};

const $gen=(h,cfg)=>cfg.P.concat([`${h}:443`]).map(x=>{
  const[raw,name=cfg.N2]=x.split('#');
  const[addr,port=443]=raw.split(':');
  return`vless://${cfg.U}@${addr}:${port}?encryption=none&security=tls&type=ws&host=${h}&sni=${h}&path=%2F%3Fed%3D2560#${encodeURIComponent(name)}`;
}).join('\n');

export default{
  async fetch(req,env){
    const cfg=$i(env),url=new URL(req.url);
    const up=req.headers.get('Upgrade'),proto=req.headers.get('sec-websocket-protocol');
    const host=req.headers.get('Host');
    
    if(up!=='websocket'){
      const sp=`/${cfg.I}/${cfg.S}`,ip=`/${cfg.I}`;
      if(url.pathname===ip){
        return new Response(`\ud83d\udce1 \u8ba2\u9605\u5730\u5740: https://${host}${sp}\n\ud83d\udd11 UUID: ${cfg.U}\n\ud83d\udcdd \u8282\u70b9\u540d\u79f0: ${cfg.N2}`,{status:200,headers:{'Content-Type':'text/plain; charset=utf-8'}});
      }
      if(url.pathname===sp){
        const c=$gen(host,cfg);
        return new Response(btoa(c),{status:200,headers:{'Content-Type':'text/plain; charset=utf-8','Content-Disposition':`attachment; filename="${cfg.N2}.txt"`}});
      }
      return new Response('\ud83d\ude80 Worker \u8fd0\u884c\u4e2d',{status:200});
    }
    
    try{
      const data=$fn.b(proto),id=new Uint8Array(data,1,16);
      if(!$fn.c(id))return new Response('\u274c \u65e0\u6548UUID',{status:403});
      const{tcpSocket,initialData}=await $parse(data,cfg);
      const[client,server]=new WebSocketPair();
      server.accept();
      $tun(server,tcpSocket,initialData);
      return new Response(null,{status:101,webSocket:client});
    }catch(e){
      return new Response(`\u274c \u8fde\u63a5\u5931\u8d25: ${e.message}`,{status:502});
    }
  }
};
