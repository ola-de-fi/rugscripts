import { NextRequest, NextResponse } from 'next/server';
import { scanWebsite } from '@/lib/scanner';
export const runtime = 'nodejs';
export const maxDuration = 15;
const buckets = new Map<string,{start:number;count:number}>();
export async function POST(request:NextRequest) {
  const key=request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()||'unknown'; const now=Date.now(); const bucket=buckets.get(key);
  if(!bucket||now-bucket.start>60_000) buckets.set(key,{start:now,count:1}); else if(bucket.count>=5) return NextResponse.json({error:'Rate limit reached. Try again in a minute.'},{status:429}); else bucket.count++;
  try { const data=await request.json(); if(typeof data?.url!=='string'||data.url.length>2048) return NextResponse.json({error:'Provide a website URL up to 2048 characters.'},{status:400}); const result=await scanWebsite(data.url); return NextResponse.json(result,{headers:{'Cache-Control':'no-store'}}); }
  catch(error) {
    const message=error instanceof Error?error.message:'The scan could not be completed.';
    const status=/time limit|aborted/i.test(message)?504:/Target returned HTTP|response exceeded|readable text document|empty response/i.test(message)?502:400;
    return NextResponse.json({error:message},{status});
  }
}
