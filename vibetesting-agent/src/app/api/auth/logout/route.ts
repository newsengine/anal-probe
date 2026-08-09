import { NextResponse } from 'next/server';
import { destroySession } from '@/lib/auth';
import { config } from '@/lib/config';

export async function POST() {
  await destroySession();
  return NextResponse.redirect(new URL('/', config.appUrl), { status: 303 });
}

export async function GET() {
  await destroySession();
  return NextResponse.redirect(new URL('/', config.appUrl));
}
