"""htmlreport plugin (library): one self-contained HTML file, chain re-verified
in the browser with SHA-256. No external requests."""
import json
import os

from .. import core
from . import signing


def collect(ledger):
    """Entries as {n, blob, hash} (blob = exact canonical text that is hashed)."""
    items = []
    if not os.path.exists(ledger):
        return items
    with open(ledger, "rb") as f:
        for n, raw in enumerate(f, 1):
            try:
                e = json.loads(raw.decode("utf-8"))
                if not isinstance(e, dict):
                    raise ValueError
            except Exception:
                items.append({"n": n, "bad": "line is not valid JSON"})
                continue
            body = {k: v for k, v in e.items() if k != "hash"}
            blob = json.dumps(body, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True)
            items.append({"n": n, "blob": blob, "hash": e.get("hash")})
    return items


def sig_info(ledger):
    recs = signing.read_sigs(ledger)
    _pin, _fps, enabled = signing.chain_pin(core.read(ledger))
    enabled = enabled or bool(core.read_state(ledger).get("signing"))
    if not recs and not enabled:
        return {"state": "none", "records": [], "problems": [],
                "text": "no signatures (signing was never set up)"}
    if not signing.have_ssh_keygen():
        return {"state": "bad" if enabled else "skipped", "records": [], "problems": [],
                "text": "ssh-keygen missing: signatures not checked"}
    st = signing.signature_status(ledger)
    last = st["last"]
    recs_out = [{"count": r.get("count"), "head": r.get("head"), "ts": r.get("ts"),
                 "status": s} for r, s in st["results"]]
    if st["bad"] or st["problems"]:
        text = "%d signature(s) FAILED" % st["bad"]
        if st["problems"]:
            text += "; " + "; ".join(st["problems"])
        state = "bad"
    elif last:
        text = "signed through entry %d; unsigned tail: %d" % (
            int(last["count"]), st["tail"])
        state = "ok"
    else:
        text = "no valid signatures"
        state = "bad"
    return {"state": state, "records": recs_out, "text": text,
            "problems": st["problems"],
            "last_count": int(last["count"]) if last else 0}


def build(ledger):
    entries = collect(ledger)
    heads = [e["hash"] for e in entries if e.get("hash")]
    data = {"entries": entries, "sigs": sig_info(ledger),
            "genesis": core.GENESIS, "head": heads[-1] if heads else core.GENESIS,
            "count": len(entries)}
    # escape every '<' as \u003c: valid JSON, and neither "</script>" nor "<!--" can
    # appear in the embedded blob (the old "<\\!--" escape was invalid JSON and blanked the page)
    blob = json.dumps(data).replace("<", "\\u003c")
    return TEMPLATE.replace("__DATA__", blob)


def write(ledger, out):
    with open(out, "w", encoding="utf-8") as f:
        f.write(build(ledger))


TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>agent-ledger report</title>
<style>
:root{--bg:#f6f7f9;--fg:#1b1f24;--mut:#59636e;--card:#fff;--bd:#d8dde3;--ok:#1a7f37;--okbg:#dafbe1;--bad:#cf222e;--badbg:#ffebe9;--warn:#9a6700;--warnbg:#fff8c5}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--ok:#3fb950;--okbg:#12351d;--bad:#f85149;--badbg:#3d1418;--warn:#d29922;--warnbg:#3b2e0a}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:4px 0 12px}
#banner{padding:14px 16px;border-radius:8px;font-weight:600;border:1px solid var(--bd);background:var(--card)}
#banner.ok{background:var(--okbg);color:var(--ok);border-color:var(--ok)}
.warnbox:not(:empty){margin:8px 0;padding:10px 14px;border-radius:8px;font-weight:600;border:1px solid var(--warn);background:var(--warnbg);color:var(--warn)}
#banner.warn{background:var(--warnbg);color:var(--warn);border-color:var(--warn)}
#banner.bad{background:var(--badbg);color:var(--bad);border-color:var(--bad)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:12px 0}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:20px}.card span{color:var(--mut);font-size:12px}
.card.deny b{color:var(--bad)}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
button{background:var(--card);color:var(--fg);border:1px solid var(--bd);border-radius:6px;padding:6px 10px;font:inherit;cursor:pointer}
button.on{border-color:var(--fg);font-weight:600}
.agent{border:1px solid var(--bd);border-radius:8px;background:var(--card);margin:10px 0;overflow:hidden}
.agent>summary{padding:8px 12px;cursor:pointer;font-weight:600;border-left:6px solid var(--c)}
.row{display:grid;grid-template-columns:auto 1fr auto;gap:2px 10px;padding:6px 12px;border-top:1px solid var(--bd);border-left:6px solid var(--c);word-break:break-word}
.row .n{color:var(--mut);font-variant-numeric:tabular-nums}
.row .ts{grid-column:1/-1;color:var(--mut);font-size:12px}
.row .cost{color:var(--mut);white-space:nowrap}
.row.deny{background:var(--badbg);border-left-color:var(--bad)}
.row.deny .act{color:var(--bad);font-weight:600}
.row.ask .act{color:var(--warn,#b7791f);font-weight:600}
.row.broken{outline:2px solid var(--bad)}
.tag{font-size:11px;border-radius:4px;padding:1px 6px;margin-left:6px;border:1px solid var(--ok);color:var(--ok)}
.sigs{font-size:13px;color:var(--mut)}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px}
</style></head><body><main>
<h1>agent-ledger report</h1>
<div id="banner">verifying chain...</div>
<div id="anchorwarn" class="warnbox"></div>
<div class="sigs" id="head"></div>
<div class="bar"><label>Expected head hash (from a trusted copy): <input id="expect" size="66" placeholder="paste head hash to compare"></label></div>
<div class="cards" id="cards"></div>
<div class="sigs" id="sigs"></div>
<div class="bar"><button id="vAgent" class="on">By agent</button><button id="vTime">Chronological</button></div>
<div id="out"></div>
</main>
<script id="d" type="application/json">__DATA__</script>
<script>
"use strict";
function failBanner(msg){var b=document.getElementById("banner");b.className="bad";
 b.textContent="REPORT FAILED TO RENDER - do not trust this page: "+msg}
window.onerror=function(m){failBanner(String(m));return false};
if(window.addEventListener)window.addEventListener("unhandledrejection",function(e){failBanner(String(e.reason))});
var D;try{D=JSON.parse(document.getElementById("d").textContent)}catch(x){failBanner("embedded data is unreadable ("+x+")");throw x}
function sha256Fallback(s){
 var b=[],i;for(i=0;i<s.length;i++)b.push(s.charCodeAt(i)&255);
 var K=[],p=2,n=0;function pr(x){for(var j=2;j*j<=x;j++)if(x%j==0)return false;return true}
 while(K.length<64){if(pr(p)){K.push((Math.pow(p,1/3)%1*4294967296)|0)}p++}
 var H=[],q=2;while(H.length<8){if(pr(q))H.push((Math.pow(q,.5)%1*4294967296)|0);q++}
 var l=b.length*8;b.push(128);while(b.length%64!=56)b.push(0);
 b.push(0,0,0,0,(l>>>24)&255,(l>>>16)&255,(l>>>8)&255,l&255);
 function R(x,c){return(x>>>c)|(x<<(32-c))}
 for(var o=0;o<b.length;o+=64){var w=[];
  for(i=0;i<16;i++)w[i]=(b[o+4*i]<<24)|(b[o+4*i+1]<<16)|(b[o+4*i+2]<<8)|b[o+4*i+3];
  for(i=16;i<64;i++){var s0=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>>3),s1=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>>10);w[i]=(w[i-16]+s0+w[i-7]+s1)|0}
  var a=H.slice();
  for(i=0;i<64;i++){var S1=R(a[4],6)^R(a[4],11)^R(a[4],25),ch=(a[4]&a[5])^(~a[4]&a[6]),t1=(a[7]+S1+ch+K[i]+w[i])|0,S0=R(a[0],2)^R(a[0],13)^R(a[0],22),mj=(a[0]&a[1])^(a[0]&a[2])^(a[1]&a[2]),t2=(S0+mj)|0;
   a=[(t1+t2)|0,a[0],a[1],a[2],(a[3]+t1)|0,a[4],a[5],a[6]]}
  for(i=0;i<8;i++)H[i]=(H[i]+a[i])|0}
 return Promise.resolve(H.map(function(x){return("00000000"+(x>>>0).toString(16)).slice(-8)}).join(""))
}
function sha256(s){
 if(window.crypto&&crypto.subtle){
  return crypto.subtle.digest("SHA-256",new TextEncoder().encode(s)).then(function(buf){
   return Array.prototype.map.call(new Uint8Array(buf),function(x){return("0"+x.toString(16)).slice(-2)}).join("")})
 }
 return sha256Fallback(s)
}
function verify(){
 var prev=D.genesis,chain=Promise.resolve(null);
 D.entries.forEach(function(it){
  chain=chain.then(function(bad){
   if(bad)return bad;
   if(it.bad)return{n:it.n,why:it.bad};
   var e;try{e=JSON.parse(it.blob)}catch(x){return{n:it.n,why:"unreadable entry"}}
   it.e=e;
   if(e.prev_hash!==prev)return{n:it.n,why:"prev_hash does not match the previous entry (line removed, added or reordered)"};
   return sha256(it.blob).then(function(h){
    if(h!==it.hash)return{n:it.n,why:"entry content does not match its hash (line was edited)"};
    prev=it.hash;return null})
  })});
 return chain
}
function color(a){var h=0;for(var i=0;i<a.length;i++)h=(h*31+a.charCodeAt(i))%360;return"hsl("+h+" 62% 48%)"}
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
var view="agent",broken=null;
function isDeny(e){return/^policy:DENY\b/.test(e.action||"")}
function isAsk(e){return/^policy:ASK\b/.test(e.action||"")}
function row(it){
 var e=it.e,r=el("div","row"+(isDeny(e)?" deny":"")+(isAsk(e)?" ask":"")+(broken&&it.n===broken.n?" broken":""));
 r.style.setProperty("--c",color(e.agent||"?"));
 r.appendChild(el("span","n","#"+it.n));
 var a=el("span","act",e.action||"");
 if(D.sigs.last_count&&it.n===D.sigs.last_count){a.appendChild(el("span","tag","signed point"))}
 r.appendChild(a);
 r.appendChild(el("span","cost",e.cost?"$"+Number(e.cost).toFixed(4):""));
 r.appendChild(el("span","ts",(e.ts||"")+(view==="time"?"  "+(e.agent||""):"")));
 return r
}
function render(){
 var out=document.getElementById("out");out.textContent="";
 var items=D.entries.filter(function(i){return i.e});
 if(view==="time"){items.forEach(function(i){out.appendChild(row(i))});return}
 var g=Object.create(null);items.forEach(function(i){var k=String(i.e.agent||"?");(g[k]=g[k]||[]).push(i)});
 Object.keys(g).sort().forEach(function(a){
  var d=el("details","agent");d.open=true;d.style.setProperty("--c",color(a));
  var cost=g[a].reduce(function(s,i){return s+(Number(i.e.cost)||0)},0);
  d.appendChild(el("summary","",a+"  -  "+g[a].length+" entries, $"+cost.toFixed(4)));
  g[a].forEach(function(i){d.appendChild(row(i))});out.appendChild(d)})
}
function card(v,l,c){var d=el("div","card "+(c||""));d.appendChild(el("b","",v));d.appendChild(el("span","",l));return d}
verify().then(function(bad){
 broken=bad;
 var b=document.getElementById("banner");
 if(D.entries.length===0){b.textContent="Ledger is empty";}
 else if(bad){b.className="bad";b.textContent="Chain BROKEN at line "+bad.n+": "+bad.why}
 else if(D.sigs.state==="bad"){b.className="bad";b.textContent="Chain is consistent but signatures FAILED: "+D.sigs.text}
 else{b.className="ok";b.textContent="Chain intact: "+D.entries.length+" entries re-verified in this browser (SHA-256)"}
 if(D.entries.length&&D.sigs.state!=="ok"&&D.sigs.state!=="bad")document.getElementById("anchorwarn").textContent="UNVERIFIED AGAINST A TRUSTED ANCHOR: no valid signature. A fully rewritten chain looks identical in this report. Compare the head hash below with a copy you trust, or paste it in the box.";
 var items=D.entries.filter(function(i){return i.e}),agents=Object.create(null),cost=0,deny=0;
 items.forEach(function(i){agents[String(i.e.agent)]=1;cost+=Number(i.e.cost)||0;if(isDeny(i.e))deny++});
 var c=document.getElementById("cards");
 c.appendChild(card(D.entries.length,"entries"));
 c.appendChild(card(Object.keys(agents).length,"agents"));
 c.appendChild(card("$"+cost.toFixed(4),"total cost"));
 c.appendChild(card(deny,"policy denials",deny?"deny":""));
 c.appendChild(card(D.sigs.state==="ok"?"signed":D.sigs.state==="bad"?"FAILED":D.sigs.state==="skipped"?"unchecked":"none","signatures"));
 var s=document.getElementById("sigs");s.textContent="Signatures: "+D.sigs.text+
  (D.sigs.records.length?" ("+D.sigs.records.map(function(r){return"#"+r.count+" "+r.status}).join(", ")+")":"");
 document.getElementById("head").textContent="Head hash: "+D.head+"  ("+D.count+" entries)";
 var ex=document.getElementById("expect");
 ex.oninput=function(){var v=ex.value.trim().toLowerCase();if(!v)return;
  if(v===D.head){b.className=(bad?"bad":"ok");b.textContent="Head hash matches the expected value ("+D.count+" entries)"+(bad?" but the chain is BROKEN":"")}
  else{b.className="bad";b.textContent="HEAD HASH DOES NOT MATCH the expected value: history was rewritten or truncated"}};
 render()
}).catch(function(x){failBanner(String(x))});
document.getElementById("vAgent").onclick=function(){view="agent";this.className="on";document.getElementById("vTime").className="";render()};
document.getElementById("vTime").onclick=function(){view="time";this.className="on";document.getElementById("vAgent").className="";render()};
</script></body></html>
"""
