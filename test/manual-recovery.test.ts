import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes} from 'node:crypto';
import {AuthHttp} from '../src/auth-ui.ts';
import {createManualRecoveryFlows,validateRecoveryEvidence} from '../src/manual-recovery.ts';
import type {ManualRecoveryService} from '../src/manual-recovery.ts';
import type {ExtensionRequest} from '@jimhoyd/urlcode/extensions';

test('manual evidence accepts bounded plain text without fetching or retaining mutable input',()=>{
 const input={summary:' Independent human review ',reference:'https://internal.invalid/evidence'};
 const result=validateRecoveryEvidence(input);input.summary='changed';assert.equal(result.summary,'Independent human review');assert.equal(result.reference,'https://internal.invalid/evidence');
 for(const value of [{summary:''},{summary:'x'.repeat(2001)},{summary:'secret\nvalue'},{summary:'review',reference:'x'.repeat(257)},{summary:'review',upload:'document'}])assert.throws(()=>validateRecoveryEvidence(value));
});
test('manual restoration GET never redeems and POST requires same-origin CSRF',async()=>{
 let redeemed=0;const token='r'.repeat(43),origin='https://example.test',http=new AuthHttp({origin,csrfKey:randomBytes(32)});
 const service={getManualRecoveryEnabled:()=>true,redeemRecoveryCase:async()=>{redeemed++;throw new Error('Domain reached');}} as unknown as ManualRecoveryService;
 const helper=createManualRecoveryFlows(service,http,'/account');
 const request:ExtensionRequest={method:'GET',target:'/account/restore-access?token='+token,path:'/account/restore-access',query:new URLSearchParams({token}),headers:new Headers({accept:'text/html'}),headerCounts:{},body:new Uint8Array(),origin,route:'/account/*',mount:'/account',client:null};
 assert.equal((await helper.handle(request))?.status,200);assert.equal(redeemed,0);
 const post={...request,method:'POST',headers:new Headers({origin:'https://attacker.test','content-type':'application/json'}),body:new TextEncoder().encode(JSON.stringify({token,password:'replacement long password',csrf:'forged'}))};
 await assert.rejects(helper.handle(post));assert.equal(redeemed,0);
 const duplicate={...request,query:new URLSearchParams('token='+token+'&token='+token)};await assert.rejects(helper.handle(duplicate));
});
