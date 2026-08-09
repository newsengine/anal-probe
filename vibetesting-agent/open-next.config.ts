import { defineCloudflareConfig } from '@opennextjs/cloudflare';

export default defineCloudflareConfig({
  // Memory cache is fine for MVP; add R2 incremental cache later if needed.
});
