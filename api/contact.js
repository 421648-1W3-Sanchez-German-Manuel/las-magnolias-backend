import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import nodemailer from "nodemailer";
import serverless from "serverless-http";

dotenv.config();

const app = express();

const ALLOWED_ORIGINS = [
  "http://localhost:3000",
  "http://127.0.0.1:5500",
  "https://www.lasmagnolias.com.ar",
  "https://lasmagnolias.com.ar",
];

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const RECAPTCHA_VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";
const RECAPTCHA_MIN_SCORE = Number(process.env.RECAPTCHA_MIN_SCORE || 0.5);
const RECAPTCHA_EXPECTED_ACTION = "contact_submit";

async function verifyRecaptcha(token, remoteIp) {
  const secret = process.env.RECAPTCHA_SECRET_KEY;
  if (!secret) {
    console.error("RECAPTCHA_SECRET_KEY missing");
    return { ok: false, reason: "config" };
  }
  if (!token || typeof token !== "string") {
    return { ok: false, reason: "missing_token" };
  }

  const params = new URLSearchParams({ secret, response: token });
  if (remoteIp) params.append("remoteip", remoteIp);

  try {
    const resp = await fetch(RECAPTCHA_VERIFY_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const data = await resp.json();
    if (!data.success) return { ok: false, reason: "not_success", data };
    if (data.action && data.action !== RECAPTCHA_EXPECTED_ACTION) {
      return { ok: false, reason: "wrong_action", data };
    }
    if (typeof data.score === "number" && data.score < RECAPTCHA_MIN_SCORE) {
      return { ok: false, reason: "low_score", data };
    }
    return { ok: true, data };
  } catch (err) {
    console.error("reCAPTCHA verify error", { message: err?.message });
    return { ok: false, reason: "network" };
  }
}

let transporter;

function sanitizeText(value) {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .trim()
    .replace(/[<>{}\\$`]/g, "")
    .replace(/[\u0000-\u001F\u007F]/g, "");
}

function sanitizePayload(req, res, next) {
  if (!req.body || typeof req.body !== "object") {
    return next();
  }

  req.body.name = sanitizeText(req.body.name);
  req.body.email = sanitizeText(req.body.email).toLowerCase();
  req.body.telefono = sanitizeText(req.body.telefono);
  req.body.ciudad = sanitizeText(req.body.ciudad);
  req.body.message = sanitizeText(req.body.message);

  return next();
}

function corsOriginValidator(origin, callback) {
  // Allow requests with no origin (curl, server-to-server) and known browser origins.
  if (!origin || ALLOWED_ORIGINS.includes(origin)) {
    callback(null, true);
    return;
  }

  callback(new Error("CORS origin not allowed"));
}

const corsOptions = {
  origin: corsOriginValidator,
  methods: ["POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
  optionsSuccessStatus: 204,
};

const contactRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Demasiadas solicitudes. Probá de nuevo en un minuto",
  },
});

function getSmtpConfig() {
  return {
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
    receiverEmail: process.env.RECEIVER_EMAIL,
  };
}

function validateSmtpConfig(config) {
  const missing = [];

  if (!config.host) missing.push("SMTP_HOST");
  if (!config.port) missing.push("SMTP_PORT");
  if (!config.user) missing.push("SMTP_USER");
  if (!config.pass) missing.push("SMTP_PASS");
  if (!config.receiverEmail) missing.push("RECEIVER_EMAIL");

  if (missing.length > 0) {
    console.error("SMTP config error: missing env vars", { missing });
    return false;
  }

  return true;
}

function getTransporter(config) {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.port === 465,
      auth: {
        user: config.user,
        pass: config.pass,
      },
    });
  }

  return transporter;
}

app.use(helmet());
app.use(cors(corsOptions));
app.options("/api/contact", cors(corsOptions));
app.options("/", cors(corsOptions));
app.use(express.json({ limit: "100kb" }));

async function handleContact(req, res) {
  try {
    const { name, email, telefono, ciudad, message } = req.body || {};
    const recaptchaToken = req.body?.recaptchaToken;
    const remoteIp =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket?.remoteAddress;

    const verification = await verifyRecaptcha(recaptchaToken, remoteIp);
    if (!verification.ok) {
      console.warn("reCAPTCHA rejected", { reason: verification.reason });
      return res.status(400).json({
        success: false,
        error: "No pudimos verificar la solicitud. Intentá de nuevo.",
      });
    }

    if (!name || !email || !telefono || !message) {
      return res.status(400).json({
        success: false,
        error: "Los campos name, email, telefono y message son obligatorios",
      });
    }

    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({
        success: false,
        error: "El campo email no tiene un formato válido",
      });
    }

    const smtpConfig = getSmtpConfig();
    if (!validateSmtpConfig(smtpConfig)) {
      return res.status(500).json({
        success: false,
        error: "Configuración SMTP incompleta",
      });
    }

    const smtpTransport = getTransporter(smtpConfig);

    await smtpTransport.sendMail({
      from: `Formulario de contacto <${smtpConfig.user}>`,
      to: smtpConfig.receiverEmail,
      replyTo: email,
      subject: `Nuevo contacto de ${name}`,
      text: [
        `Nombre: ${name}`,
        `Email: ${email}`,
        `Telefono: ${telefono}`,
        `Ciudad: ${ciudad || "No especificada"}`,
        "",
        "Mensaje:",
        message,
      ].join("\n"),
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("SMTP send error", {
      message: error?.message,
      code: error?.code,
      response: error?.response,
    });

    return res.status(500).json({
      success: false,
      error: "No se pudo enviar el correo de contacto",
    });
  }
}

app.post("/api/contact", contactRateLimiter, sanitizePayload, handleContact);
// Vercel may invoke this function with stripped path depending on routing setup.
app.post("/", contactRateLimiter, sanitizePayload, handleContact);
app.get("/api/contact", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "Endpoint activo. Usa POST para enviar el formulario.",
  });
});
app.get("/", (req, res) => {
  return res.status(200).json({
    success: true,
    message: "API activa. Usa POST /api/contact.",
  });
});

app.use((err, req, res, next) => {
  if (err && err.message === "CORS origin not allowed") {
    return res.status(403).json({
      success: false,
      error: "Origen no permitido por CORS",
    });
  }

  console.error("Unhandled API error", {
    message: err?.message,
    stack: err?.stack,
  });

  return res.status(500).json({
    success: false,
    error: "Error interno del servidor",
  });
});

const lambdaHandler = serverless(app);

// Keep lambda-compatible export while using Express req/res for Vercel runtime.
export { lambdaHandler as handler };
export default app;
