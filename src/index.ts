// src/secure_endpoints.ts
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
dotenv.config();

function loadJsonFile(filePath: string) {
  try {
    const fullPath = path.resolve(__dirname, filePath);
    if (!fs.existsSync(fullPath)) return {};
    return JSON.parse(fs.readFileSync(fullPath, 'utf-8'));
  } catch (e) {
    console.error('Failed to load JSON file:', filePath, e);
    return {};
  }
}

function loadSecret(key: string, defaultVal?: string) {
  return process.env[key] || defaultVal || '';
}

const dynamicApiKeys = loadJsonFile('./data/api_keys.json');
const dynamicRclone = loadJsonFile('./data/rclone.json');
const dynamicPinata = loadJsonFile('./data/pinata.json');
const dynamicLinks = loadJsonFile('./data/links.json');
const dynamicUuids = loadJsonFile('./data/uuids.json');
const dynamicTelegramBots = loadJsonFile('./data/telegram_bots.json');
const dynamicOtherLinks = loadJsonFile('./data/other_links.json');
const dynamicFileJason = loadJsonFile('./data/file_jason.json');

export const SECURE_API_DATA = {
  api_keys: dynamicApiKeys.api_keys || [
    { name: 'primary', key: loadSecret('PRIMARY_API_KEY', '74074fb6f51063e40f55'), secret: loadSecret('PRIMARY_API_SECRET', '885439176976b165e50f414fdd594a2c75a89f85512927359416b9d79aae93ab') },
    { name: 'secondary', key: loadSecret('SECONDARY_API_KEY', 'a1b2c3d4e5f60718293a'), secret: loadSecret('SECONDARY_API_SECRET', '4d3c2b1a9876543210fedcba0987654321fdecba9876543210abcdef12345678') },
  ],
  jwt_tokens: [
    loadSecret('JWT_TOKEN_PRIMARY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySW5mb3JtYXRpb24iOnsiaWQiOiJiNmRjODMxMC0xNGQ1LTRlMmEtOTRjNS1iOWE2MThmMzhkYmYiLCJlbWFpbCI6ImFobWFkYWhtYWRpYWZnMDg1QGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJwaW5fcG9saWN5Ijp7InJlZ2lvbnMiOlt7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6IkZSQTEifSx7ImRlc2lyZWRSZXBsaWNhdGlvbkNvdW50IjoxLCJpZCI6Ik5ZQzEifV0sInZlcnNpb24iOjF9LCJtZmFfZW5hYmxlZCI6ZmFsc2UsInN0YXR1cyI6IkFDVElWRSJ9LCJhdXRoZW50aWNhdGlvblR5cGUiOiJzY29wZWRLZXkiLCJzY29wZWRLZXlLZXkiOiI3NDA3NGZiNmY1MTA2M2U0MGY1NSIsInNjb3BlZEtleVNlY3JldCI6Ijg4NTQzOTE3Njk3NmIxNjVlNTBmNDE0ZmRkNTk0YTJjNzVhODlmODU1MTI5MjczNTk0MTZiOWQ3OWFhZTkzYWIiLCJleHAiOjE3OTUyMDAyODN9.CecVpXHvvfYigUHr909Mmc36Nan3sWg8hvnPWIvUTaA'),
    loadSecret('JWT_TOKEN_SECONDARY', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZGVtb19qd3QiLCJleHAiOjIxNDNzMjAwMDB9.Z8ycTiC1maG1N-0Pi2QCvqE1L3KgaYOdLacN8_0c1vA')
  ],
  uuids: dynamicUuids.uuids || [
    "019aa299-3759-75d4-8c36-c6b70f6104ea",
    "019aa29b-0f99-70e3-a899-e693dc4258cd",
    "019aa2af-9b52-4e70-bf58-d5738c8a4a8f"
  ],
  ipfs_pinata: dynamicPinata || {
    cid: 'bafkreic3uxleigat5kieluw4uq3vrji4flwwsr6ltgme4yn7a2yqnx7nfm',
    gateway: 'https://peach-tropical-reindeer-499.mypinata.cloud',
    api: 'https://api.pinata.cloud/data/pinList',
    api_key: loadSecret('PINATA_API_KEY', '1234567890abcdef1234567890abcdef'),
    secret_api_key: loadSecret('PINATA_SECRET_API_KEY', 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'),
  },
  links: dynamicLinks.links || [
    { url: "https://k00.fr/cv9tszq", password: "285861" },
    { url: "https://k00.fr/k9ourdsf" },
    { url: "https://app.koofr.net/app/storage/d9699792-7987-4f17-9069-d0a14e681749" },
    { url: "https://k00.fr/mqdrkha5", password: "xYz123!" }
  ],
  file_jason: dynamicFileJason || {
    storage_path: "/My safe box",
    filename_encryption: "AES-256-GCM",
    dir_encryption: true,
    salt: "m7LAs4ca3s5WGYeTTVAs7IbwJevCr_nUrvEMNnC6ZTsyO0WcV7JPTLSXdCZWYpRGj774CRc8unhuTjto4p9BMufEdn6ktQ08RWVRXg9mvj62YynuW36gadD8jwbRgjvQUIiZVTKl057teVC8C1uzleYkv0dVpJTDq_1gq71mB4Q"
  },
  rclone: dynamicRclone || {
    name: "my-safe-box",
    type: "crypt",
    remote: "koofr:/My safe box",
    password: loadSecret('RCLONE_PASS', 'Jbo626Z49ARQQEiNfHJ-EGWO73LA1pQpioJzLQ'),
    password2: loadSecret('RCLONE_PASS2', 'SMQF-LhWfCFP7nVdRFEFDWfbNV8Nf5ZfZOC5veg0Pym2lxhVsC7miuuZNJeo8wZYtWe4L32JAg0cGq-UjF1dgpwJ-dgTKMwXKVcsTS6zX0GIFR9tplSrsJkXSp2U5atyVSSc3LAOgm_aZf989XB_YpO1L0652hmxUdSb4ZXWkH48znNpeA8jFNQ05Jz65hfLNFI1ODBhfPkQInJxXUkNDtI6uEZo0fWRN0ujaglrw2T50ip10gja4degAw')
  },
  telegram_bots: dynamicTelegramBots.bots || [
    { bot_token: "8418306947:AAGZZbqMchirqRLF85ILmp-7Ym1TWoJTT8", username: "@King8906_bot/cybersadatsafe" }
  ],
  other_links: dynamicOtherLinks.links || [
    "https://t.me/Janj1234_bot",
    "https://t.me/Shenel231_bot",
    "https://chatgpt.com/share/68e85049-2958-8003-a775-2ba6e7a01bce",
    "https://github.com/vortexhub/official",
    "https://vortexhub.io/docs/api"
  ],
  base_url: "https://vortex-universal-orchestrator-cppw.onrender.com",
  cron_api: "/api/cron",
};

// src/index.ts
import { Container } from "@cloudflare/containers";
import { Hono } from "hono";
import type { Env } from "./types";
import { jwtVerify } from "jose";
import { SECURE_API_DATA } from "./secure_endpoints";

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
    await jwtVerify(token, new TextEncoder().encode(secret));
    return true;
  } catch {
    return false;
  }
}

const app = new Hono<{ Bindings: Env }>();

app.use(['/secure-data', '/logs'], async (c, next) => {
  const auth = c.req.headers.get("Authorization");
  if (!auth || !auth.startsWith("Bearer ")) return c.text("Unauthorized", 401);
  const token = auth.substring(7);
  const validPrimary = await verifyJwtToken(token, SECURE_API_DATA.api_keys[0].secret);
  const validSecondary = await verifyJwtToken(token, SECURE_API_DATA.api_keys[1]?.secret || '');
  if (!validPrimary && !validSecondary) return c.text("Invalid token", 401);
  await next();
});

app.get("/", (c) =>
  c.text(
    "Available endpoints:\n" +
    "GET /loader - fetch loader HTML\n" +
    "POST /secure-data - get secure config JSON (auth required)\n" +
    "GET /logs - get logs JSON (auth required)"
  )
);

app.get("/loader", async (c) => {
  const html = await readFileFallback("/static/loader.html");
  return c.html(html);
});

app.post("/secure-data", (c) => c.json(SECURE_API_DATA));

app.get("/logs", (c) => {
  const logs: any[] = []; // Fetch or accumulate logs here as needed
  return c.json({ logs });
});

export class MyContainer extends Container<Env> {
  defaultPort = 8080;
  sleepAfter = '2m';
  envVars = {
    NODE_ENV: 'production',
    TELEGRAM_BOT_TOKEN: SECURE_API_DATA.telegram_bots[0]?.bot_token || '',
    RCLONE_REMOTE: SECURE_API_DATA.rclone.remote || '',
    PINATA_CID: SECURE_API_DATA.ipfs_pinata.cid || '',
  };

  override onStart() {
    console.log('Container started');
  }

  override onStop() {
    console.log('Container stopped');
  }

  override onError(error: unknown) {
    console.error('Container error:', error);
  }

  override async fetch(request: Request): Promise<Response> {
    try {
      return await app.fetch(request);
    } catch (err) {
      console.error('Fetch error:', err);
      return new Response('Internal Server Error', { status: 500 });
    }
  }
}

// static/loader.js
import { SECURE_API_DATA } from '../src/secure_endpoints.js';

function showSecureData() {
  const el = document.getElementById('secureData');
  if (!el) return;
  el.textContent = JSON.stringify(SECURE_API_DATA, null, 2);
}

async function preloadModules(urls) {
  const loadedModules = {};
  await Promise.all(urls.map(async (url) => {
    try {
      if (url.endsWith('.js')) {
        loadedModules[url] = await import(url);
      } else if (url.endsWith('.wasm')) {
        const response = await fetch(url);
        const buffer = await response.arrayBuffer();
        const wasmModule = await WebAssembly.instantiate(buffer, {});
        loadedModules[url] = wasmModule.instance;
      } else if (url.endsWith('.py')) {
        const response = await fetch(url);
        loadedModules[url] = await response.text();
      }
    } catch (e) {
      console.warn(`Failed to load module ${url}:`, e);
    }
  }));
  return loadedModules;
}

(async () => {
  showSecureData();
  const urls = [
    SECURE_API_DATA.links[0]?.url || '',
    SECURE_API_DATA.links[1]?.url || '',
    SECURE_API_DATA.links[2]?.url || '',
  ].filter(Boolean);

  const modules = await preloadModules(urls);

  for (const url in modules) {
    const mod = modules[url];
    if (mod && mod.exports && typeof mod.exports.init === 'function') {
      mod.exports.init();
    }
  }

  console.log('Modules loaded:', Object.keys(modules));
})();
