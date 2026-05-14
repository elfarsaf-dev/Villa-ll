import http from "node:http";
import worker from "./worker.js";

const PORT = process.env.PORT || 5000;

const env = {
  SUPABASE_URL:    process.env.SUPABASE_URL,
  SUPABASE_KEY:    process.env.SUPABASE_KEY,
  JWT_SECRET:      process.env.JWT_SECRET,
  GITHUB_TOKEN:    process.env.GITHUB_TOKEN,
  GITHUB_REPO:     process.env.GITHUB_REPO,
  GITHUB_BRANCH:   process.env.GITHUB_BRANCH || "main",
  GITHUB_IMG_PATH: process.env.GITHUB_IMG_PATH || "images/villas",
  OPENROUTER_KEY:  process.env.OPENROUTER_KEY,
  ALLOWED_ORIGIN:  process.env.ALLOWED_ORIGIN || "*",
};

const server = http.createServer(async (req, res) => {
  try {
    const host = req.headers.host || "localhost";
    const url = `http://${host}${req.url}`;

    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const bodyBuf = chunks.length ? Buffer.concat(chunks) : null;

    const headers = new Headers();
    for (const [k, v] of Object.entries(req.headers)) {
      if (Array.isArray(v)) v.forEach(val => headers.append(k, val));
      else if (v != null) headers.set(k, v);
    }

    const init = { method: req.method, headers };
    if (bodyBuf && bodyBuf.length > 0) init.body = bodyBuf;

    const request = new Request(url, init);
    const response = await worker.fetch(request, env, {});

    res.statusCode = response.status;
    response.headers.forEach((v, k) => res.setHeader(k, v));

    const body = await response.arrayBuffer();
    res.end(Buffer.from(body));
  } catch (err) {
    console.error("Server error:", err);
    res.statusCode = 500;
    res.end(JSON.stringify({ error: "Internal server error" }));
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
});
