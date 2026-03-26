// Temporary: list and abort ALL incomplete multipart uploads
// Run via: wrangler dev --test-scheduled

export default {
  async scheduled(event: any, env: any, ctx: any) {
    console.log("Listing incomplete multipart uploads...");
    
    // List all incomplete multipart uploads via R2 API
    const listed = await env.BUCKET.list({ prefix: "" });
    console.log(`Found ${listed.objects.length} objects in bucket`);
    
    // The real fix: we need to use the internal R2 API to list multipart uploads
    // But Workers R2 binding doesn't expose listMultipartUploads directly
    // We need to abort via the uploads we can find in KV
    
    const kvList = await env.ROOMS.list({ prefix: "upload:" });
    console.log(`Found ${kvList.keys.length} upload states in KV`);
    
    let aborted = 0;
    for (const key of kvList.keys) {
      const state = await env.ROOMS.get(key.name, "json");
      if (!state) continue;
      try {
        const multipart = env.BUCKET.resumeMultipartUpload(state.key, state.uploadId);
        await multipart.abort();
        aborted++;
        console.log(`Aborted: ${state.uploadId}`);
      } catch (e: any) {
        console.log(`Skip: ${state.uploadId} - ${e.message}`);
      }
      await env.ROOMS.delete(key.name);
    }
    
    console.log(`Aborted ${aborted} uploads from KV`);
  },
  
  async fetch(request: Request, env: any) {
    // Force abort endpoint - tries to abort known upload IDs
    if (new URL(request.url).pathname === "/force-cleanup") {
      const kvList = await env.ROOMS.list({ prefix: "upload:" });
      let aborted = 0;
      for (const key of kvList.keys) {
        const state = await env.ROOMS.get(key.name, "json");
        if (!state) continue;
        try {
          const multipart = env.BUCKET.resumeMultipartUpload(state.key, state.uploadId);
          await multipart.abort();
          aborted++;
        } catch {}
        await env.ROOMS.delete(key.name);
      }
      return new Response(JSON.stringify({ aborted, checked: kvList.keys.length }));
    }
    return new Response("ok");
  }
};
