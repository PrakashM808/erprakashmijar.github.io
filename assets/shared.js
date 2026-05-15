/* shared.js — loaded by every page */

/* ── PARTICLE CANVAS ── */
(function(){
  const c=document.getElementById('bgCanvas');
  if(!c)return;
  const ctx=c.getContext('2d');
  let W,H,pts=[];
  function resize(){W=c.width=window.innerWidth;H=c.height=window.innerHeight;init()}
  function init(){
    pts=[];
    const n=Math.min(Math.floor((W*H)/22000),80);
    for(let i=0;i<n;i++) pts.push({x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.22,vy:(Math.random()-.5)*.22,r:Math.random()*1.4+.3});
  }
  function draw(){
    ctx.clearRect(0,0,W,H);
    pts.forEach(p=>{
      p.x+=p.vx;p.y+=p.vy;
      if(p.x<0)p.x=W;if(p.x>W)p.x=0;
      if(p.y<0)p.y=H;if(p.y>H)p.y=0;
      ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);
      ctx.fillStyle='rgba(0,255,136,0.45)';ctx.fill();
    });
    for(let i=0;i<pts.length;i++){
      for(let j=i+1;j<pts.length;j++){
        const a=pts[i],b=pts[j],dx=a.x-b.x,dy=a.y-b.y,d=Math.sqrt(dx*dx+dy*dy);
        if(d<110){ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.strokeStyle=`rgba(0,255,136,${.07*(1-d/110)})`;ctx.lineWidth=.5;ctx.stroke()}
      }
    }
    requestAnimationFrame(draw);
  }
  window.addEventListener('resize',resize);
  resize();draw();
})();

/* ── CURSOR ── */
(function(){
  if(!window.matchMedia('(hover:hover) and (pointer:fine)').matches)return;
  const c=document.getElementById('cur'),r=document.getElementById('cur2');
  if(!c||!r)return;
  let mx=0,my=0,rx=0,ry=0;
  document.addEventListener('mousemove',e=>{mx=e.clientX;my=e.clientY;c.style.left=mx+'px';c.style.top=my+'px'});
  (function t(){rx+=(mx-rx)*.11;ry+=(my-ry)*.11;r.style.left=rx+'px';r.style.top=ry+'px';requestAnimationFrame(t)})();
  document.addEventListener('mouseover',e=>{
    if(e.target.matches('a,button,[data-hover]')){c.style.width='18px';c.style.height='18px';r.style.width='46px';r.style.height='46px';r.style.borderColor='rgba(0,212,255,.6)'}
    else{c.style.width='8px';c.style.height='8px';r.style.width='30px';r.style.height='30px';r.style.borderColor='rgba(0,255,136,.35)'}
  });
})();

/* ── NAV TOGGLE ── */
(function(){
  const t=document.getElementById('navToggle'),l=document.getElementById('navLinks');
  if(!t||!l)return;
  t.addEventListener('click',()=>{const o=l.classList.toggle('open');t.setAttribute('aria-expanded',String(o))});
  l.querySelectorAll('a').forEach(a=>a.addEventListener('click',()=>{l.classList.remove('open');t.setAttribute('aria-expanded','false')}));
})();

/* ── SCROLL REVEAL ── */
(function(){
  const io=new IntersectionObserver(entries=>{
    entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');io.unobserve(e.target)}});
  },{threshold:.07});
  document.querySelectorAll('.reveal').forEach(el=>io.observe(el));
})();
