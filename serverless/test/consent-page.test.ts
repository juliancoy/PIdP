import test from 'node:test';
import assert from 'node:assert/strict';
import {renderConsentPage} from '../src/consentPage';

test('same-service sign-in explains PIdP authorization and preserves permission review',async()=>{
 const input={client:'Swarm Control',account:'member',resource:'https://compai.lifetech.fyi/api/swarm',callback:'https://compai.lifetech.fyi/auth/callback',request:'consent-test',changeAccount:'/oauth/mcp/authorize',requested:['swarm:control'],dynamic:false};
 const {html}=await renderConsentPage(input);
 assert.ok(html.includes('<h1>Continue to Swarm Control</h1>'));
 assert.ok(html.includes('with your PIdP account'));
 for(const text of ['Control your swarm','Allow access','>Deny<'])assert.ok(html.includes(text));
 for(const changed of [{dynamic:true},{callback:'https://other.example/callback'}]){
  const page=await renderConsentPage({...input,...changed});
  assert.ok(page.html.includes('<h1>Connect Swarm Control to Swarm Control</h1>'));
 }
 const external=await renderConsentPage({...input,client:'Codex'});
 assert.ok(external.html.includes('<h1>Connect Codex to Swarm Control</h1>'));
});
