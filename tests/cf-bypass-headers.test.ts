import { test } from 'node:test';
import assert from 'node:assert/strict';
import { cfBypassHeaders, withCfBypassHeaders } from '../src/cf-bypass-headers.ts';

test('cfBypassHeaders empty without env', () => {
  const prev = { ...process.env };
  delete process.env.CF_SMOKE_KEY;
  delete process.env.X_SMOKE_KEY;
  delete process.env.SMOKE_KEY;
  delete process.env.CF_ACCESS_CLIENT_ID;
  delete process.env.CF_ACCESS_CLIENT_SECRET;
  try {
    assert.deepEqual(cfBypassHeaders('https://beta.dynamicbusiness.com'), {});
  } finally {
    process.env = prev as NodeJS.ProcessEnv;
  }
});

test('cfBypassHeaders smoke key + beta Access', () => {
  const prev = { ...process.env };
  process.env.CF_SMOKE_KEY = 'smk_test';
  process.env.CF_ACCESS_CLIENT_ID = 'id.access';
  process.env.CF_ACCESS_CLIENT_SECRET = 'cfast_test';
  try {
    const beta = cfBypassHeaders('https://beta.dynamicbusiness.com/path');
    assert.equal(beta['x-smoke-key'], 'smk_test');
    assert.equal(beta['CF-Access-Client-Id'], 'id.access');
    assert.equal(beta['CF-Access-Client-Secret'], 'cfast_test');

    const www = cfBypassHeaders('https://www.dynamicbusiness.com');
    assert.equal(www['x-smoke-key'], 'smk_test');
    assert.equal(www['CF-Access-Client-Id'], undefined);

    const merged = withCfBypassHeaders('https://beta.dynamicbusiness.com', { cookie: 'a=b' });
    assert.equal(merged?.cookie, 'a=b');
    assert.equal(merged?.['x-smoke-key'], 'smk_test');
  } finally {
    for (const k of Object.keys(process.env)) delete process.env[k];
    Object.assign(process.env, prev);
  }
});
