import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { scanWebsite } from '../src/lib/scanner.ts';
const evidenceFixture={html:'<script>window.wallet={request:"personal_sign"}; const payload=atob("encoded"); fetch("https://api.fixture.example/v1/quote");</script><script src="/wallet.js"></script>',js:'provider.request({method:"eth_sendTransaction"}); token.approve(spender, 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);'};
const fixture=createServer((req,res)=>{
  if(req.url==='/benign'){res.writeHead(200,{'content-type':'text/html'});res.end('<script>provider.request({method:"eth_requestAccounts"}); provider.request({method:"personal_sign",params:[message,account]});</script>');return;}
  if(req.url==='/redirect-loop'){res.writeHead(302,{location:'/redirect-loop'});res.end();return;}
  if(req.url==='/redirect-private'){res.writeHead(302,{location:'http://127.0.0.1/private'});res.end();return;}
  if(req.url==='/'){res.writeHead(200,{'content-type':'text/html'});res.end(evidenceFixture.html);return;}
  res.writeHead(200,{'content-type':'application/javascript'});res.end(evidenceFixture.js);
});
await new Promise(resolve=>fixture.listen(18761,'127.0.0.1',resolve));
try {
  const benignResult=await scanWebsite('http://127.0.0.1:18761/benign',{allowLocalFixture:true});
  assert.equal(benignResult.analysisEngine,'static-html-js-v1');
  assert(benignResult.findings.some(f=>f.severity==='Info'));
  assert.equal(benignResult.riskScore,0,'wallet features alone should not increase heuristic risk');
  const suspicious=await scanWebsite('http://127.0.0.1:18761/',{allowLocalFixture:true});
  assert.equal(suspicious.scriptsAnalyzed,2);
  for(const expected of ['personal_sign','atob(','eth_sendTransaction','approve(']) assert(suspicious.findings.some(f=>f.evidence.includes(expected)),`missing evidence ${expected}`);
  assert(suspicious.apiEndpoints.includes('https://api.fixture.example/v1/quote'));
  assert(suspicious.findings.some(f=>f.title.includes('unlimited token approval')));
  await assert.rejects(scanWebsite('http://127.0.0.1:18761/'),/Private, local, and reserved/);
  await assert.rejects(scanWebsite('http://192.168.1.1/'),/Private, local, and reserved/);
    await assert.rejects(scanWebsite('http://127.0.0.1:18761/redirect-private',{allowLocalFixture:true}),/Private, local, and reserved/);
  await assert.rejects(scanWebsite('http://127.0.0.1:18761/redirect-loop',{allowLocalFixture:true}),/Redirect limit reached/);
  await assert.rejects(scanWebsite('file:///etc/passwd'),/Only public HTTP and HTTPS/);
  console.log('Controlled pattern evidence, API extraction, private address rejection, redirect policy, and protocol rejection passed.');
} finally { await new Promise(resolve=>fixture.close(resolve)); }
