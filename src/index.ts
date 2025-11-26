// src/index.ts
const SECURE_API_DATA = {
  api_keys: [
    {
      name: "primary",
      key: "74074fb6f51063e40f55",
      secret: "885439176976b165e50f414fdd594a2c75a89f85512927359416b9d79aae93ab"
    }
  ],
  jwt_tokens: [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiJiNmRjODMxMC0xNGQ1LTRlMmEtOTRjNS1iOWE2MThmMzhkYmYiLCJlbWFpbCI6ImFobWFkYWhtYWRpYWZnMDg1QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6IkZSQTEifSx7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6Ik5ZQzEifV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiI3NDA3NGZiNmY1MTA2M2U0MGY1NSIsInNjb3BlZEtleVNlY3JldCI6Ijg4NTQzOTE3Njk3NmIxNjVlNTBmNDE0ZmRkNTk0YTJjNzVhODlmODU1MTI5MjczNTk0MTZiOWQ3OWFhZTkzYWIiLCJleHAiOjE3OTUyMDAyODN9.CecVpXHvvfYigUHr909Mmc36Nan3sWg8hvnPWIvUTaA"
  ],
  uuids: [
    "019aa299-3759-75d4-8c36-c6b70f6104ea",
    "019aa29b-0f99-70e3-a899-e693dc4258cd"
  ],
  ipfs_pinata: {
    cid: "bafkreic3uxleigat5kieluw4uq3vrji4flwwsr6ltgme4yn7a2yqnx7nfm",
    gateway: "https://peach-tropical-reindeer-499.mypinata.cloud",
    api: "https://app.pinata.cloud/developers/api-keys"
  },
  links: [
    { url: "https://k00.fr/cv9tszq", password: "285861" },
    { url: "https://k00.fr/k9ourdsf" },
    { url: "https://app.koofr.net/app/storage/d9699792-7987-4f17-9069-d0a14e681749" },
    { url: "https://k00.fr/mqdrkha5" }
  ],
  file_jason: {
    storage_path: "/My safe box",
    filename_encryption: "standard",
    dir_encryption: true,
    salt: "m7LAs4ca3s5WGYeTTVAs7IbwJevCr_nUrvEMNnC6ZTsyO0WcV7JPTLSXdCZWYpRGj774CRc8unhuTjto4p9BMufEdn6ktQ08RWVRXg9mvj62YynuW36gadD8jwbRgjvQUIiZVTKl057teVC8C1uzleYkv0dVpJTDq_1gq71mB4Q"
  },
  rclone: {
    name: "my-safe-box",
    type: "crypt",
    remote: "koofr:/My safe box",
    password: "Jbo626Z49ARQQEiNfHJ-EGWO73LA1pQpioJzLQ",
    password2: "SMQF-LhWfCFP7nVdRFEFDWfbNV8Nf5ZfZOC5veg0Pym2lxhVsC7miuuZNJeo8wZYtWe4L32JAg0cGq-UjF1dgpwJ-dgTKMwXKVcsTS6zX0GIFR9tplSrsJkXSp2U5atyVSSc3LAOgm_aZf989XB_YpO1L0652hmxUdSb4ZXWkH48znNpeA8jFNQ05Jz65hfLNFI1ODBhfPkQInJxXUkNDtI6uEZo0fWRN0ujaglrw2T50ip10gja4degAw"
  },
  hashes: [
    "74074fb6f51063e40f55",
    "885439176976b165e50f414fdd594a2c75a89f85512927359416b9d79aae93ab"
  ],
  base_url: "https://vortex-universal-orchestrator-cppw.onrender.com",
  cron_api: "/api/cron",
  telegram_bots: [
    { bot_token: "8418306947:AAGZZb0qMchirqRLF85ILmp-7Ym1TWoJTT8", username: "@King8906_bot/cybersadatsafe" },
    { bot_token: "8483782411:AAHFj5eYx2FKI0rVZ640kiX4O-mJMcqJLCQ", username: null },
    { bot_token: "8285830252:AAGIAklX2i9F_Hpej-AfJgfqoz020oFJ7zI", username: null },
    { bot_token: "xA92njsK-Secret-Token-7788", username: "secret_repo" }
  ],
  other_links: [
    "https://t.me/Janj1234_bot",
    "https://t.me/Shenel231_bot",
    "https://chatgpt.com/share/68e85049-2958-8003-a775-2ba6e7a01bce"
  ]
};

export default SECURE_API_DATA;

// src/index.ts
import { Container } from "@cloudflare/containers";
import { Hono } from "hono";
import type { Env } from "./types";
import SECURE_API_DATA from "./secure_endpoints";
import { jwtVerify } from "jose";

async function readFileFallback(path: string): Promise<string> {
  try {
    const response = await fetch(path);
    if (!response.ok) throw new Error("File not found");
    return await response.text();
  } catch {
    return "<h1>Loader file not found</h1>";
  }
}

async function verifyJwtToken(token: string, secret: string): Promise<boolean> {
  try {
    const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
    // Optionally verify claims e.g. issuer, audience, expiration here
    return true;
  } catch {
    return false;
  }
}

const app = new Hono<{ Bindings: Env }>();

app.use(['/secure-data', '/logs'], async (c, next) => {
  const auth = c.req.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) {
    return c.text("Unauthorized", 401);
  }
  const token = auth.substring(7);
  const valid = await verifyJwtToken(token, SECURE_API_DATA.api_keys[0].secret);
  if (!valid) {
    return c.text("Invalid token", 401);
  }
  await next();
});

app.get("/", (c) => {
  return c.text(
    "Available endpoints:\n" +
    "GET /loader - fetch loader HTML\n" +
    "POST /secure-data - get secure config JSON (auth required)\n" +
    "GET /logs - get logs JSON (auth required)"
  );
});

app.get("/loader", async (c) => {
  const html = await readFileFallback("/static/loader.html");
  return c.html(html);
});

app.post("/secure-data", (c) => {
  return c.json(SECURE_API_DATA);
});

app.get("/logs", (c) => {
  // Implement real log fetch from KV, R2, or DB here
  const logs: any[] = [];
  // Optionally send Telegram notification asynchronously
  // sendTelegramMessage(c.env.TELEGRAM_BOT_TOKEN, "Logs accessed");
  return c.json({ logs });
});

export class MyContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = "2m";
  envVars = {
    NODE_ENV: "production",
    TELEGRAM_BOT_TOKEN: "<insert_bot_token_here>",
    RCLONE_REMOTE: SECURE_API_DATA.rclone.remote,
    PINATA_CID: SECURE_API_DATA.ipfs_pinata.cid,
  };

  override onStart() {
    console.log("Container started");
  }

  override onStop() {
    console.log("Container stopped");
  }

  override onError(error: unknown) {
    console.error("Container error:", error);
  }

  override async fetch(request: Request): Promise<Response> {
    try {
      return await app.fetch(request);
    } catch (err) {
      console.error("Fetch error:", err);
      return new Response("Internal Server Error", { status: 500 });
    }
  }
}
