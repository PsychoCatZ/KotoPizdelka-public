import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { transform } from 'esbuild';
const compiled=await transform(await readFile(new URL('../src/visibleUnread.ts',import.meta.url),'utf8'),{loader:'ts',format:'esm',target:'es2022'});
const {VisibleReadBatcher,hasVisibleMessage}=await import(`data:text/javascript;base64,${Buffer.from(compiled.code).toString('base64')}`);
const settle=async()=>{for(let i=0;i<20;i++)await Promise.resolve();};
const rect=(top,bottom,left=0,right=300)=>({top,bottom,left,right,height:bottom-top,width:right-left});
test('visible rows must overlap the actual feed; very long messages can be read without fitting entirely',()=>{
 const view=rect(50,500);
 assert.equal(hasVisibleMessage(rect(500,600),view),false);
 assert.equal(hasVisibleMessage(rect(480,600),view),false);
 assert.equal(hasVisibleMessage(rect(450,600),view),true);
 assert.equal(hasVisibleMessage(rect(100,200,310,400),view),false);
 assert.equal(hasVisibleMessage(rect(100,100),view),false);
 assert.equal(hasVisibleMessage(rect(100,10000),view),true);
});
test('selection/focus/modal is rechecked before a queued mark and only exact visible rows are submitted',async()=>{
 let active=true;const requests=[];
 const reader=new VisibleReadBatcher({canMark:(c,s)=>active&&c==='a'&&s<3,mark:async(c,s)=>requests.push([c,s]),committed:()=>{},failed:()=>assert.fail('unexpected failure')});
 reader.offer('a',[1,2,3,3,-1,0,Number.MAX_SAFE_INTEGER+1]);active=false;await settle();assert.equal(requests.length,0);
 active=true;reader.offer('a',[1,2,3]);await settle();assert.deepEqual(requests,[['a',[1,2]]]);reader.dispose();
});
test('read batches are bounded and serial; new arrivals stay separate from the submitted snapshot',async()=>{
 const requests=[];let resolve;const gate=new Promise(r=>resolve=r);let active=0,max=0;
 const reader=new VisibleReadBatcher({canMark:()=>true,mark:async(c,s)=>{requests.push([...s]);max=Math.max(max,++active);if(requests.length===1)await gate;active--;},committed:()=>{},failed:()=>assert.fail('unexpected failure')});
 reader.offer('a',Array.from({length:120},(_,i)=>i+1));await settle();assert.equal(requests.length,1);assert.equal(requests[0].length,100);
 reader.offer('a',[121]);await settle();assert.equal(requests.length,1);resolve();await settle();assert.equal(max,1);assert.deepEqual(requests[1],Array.from({length:21},(_,i)=>i+101));reader.dispose();
});
test('failed persistence never reports committed/read and a later observation can retry',async()=>{
 let fail=true;let commits=0,failures=0;
 const reader=new VisibleReadBatcher({canMark:()=>true,mark:async()=>{if(fail)throw Error('temporary');},committed:()=>{commits++;},failed:()=>{failures++;}});
 reader.offer('a',[1]);await settle();assert.equal(commits,0);assert.equal(failures,1);
 fail=false;reader.offer('a',[1]);await settle();assert.equal(commits,1);reader.dispose();
});
test('unmount prevents late UI updates while already viewed rows may finish persistence',async()=>{
 let resolve;let commits=0;const gate=new Promise(r=>resolve=r);
 const reader=new VisibleReadBatcher({canMark:()=>true,mark:()=>gate,committed:()=>{commits++;},failed:()=>assert.fail('unexpected failure')});
 reader.offer('a',[1]);await settle();reader.dispose();resolve();await settle();reader.offer('a',[2]);await settle();assert.equal(commits,0);
});
