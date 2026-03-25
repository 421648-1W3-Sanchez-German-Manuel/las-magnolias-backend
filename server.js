// Load environment variables from the .env file into process.env.
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import nodemailer from "nodemailer";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

// Initialize dotenv as early as possible so env vars are available everywhere.
dotenv.config();

// Create the Express application instance.
const app = express();

// Read configuration from environment variables with safe defaults.
const PORT = process.env.PORT || 4000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "http://localhost:3000";
const SMTP_HOST = process.env.SMTP_HOST;
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER;
const SMTP_PASS = process.env.SMTP_PASS;
const RECEIVER_EMAIL = process.env.RECEIVER_EMAIL;
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET;

// Basic pattern to verify that the email looks valid.
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Limit /api/contact to 5 requests per minute per client IP.
const contactRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: "Too many requests, please try again later",
  },
});

// Create SMTP transporter once and reuse it for all requests.
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: SMTP_PORT === 465,
  auth: {
    user: SMTP_USER,
    pass: SMTP_PASS,
  },
});

// Verify reCAPTCHA token with Google's siteverify API.
async function verifyRecaptcha(token) {
  if (!RECAPTCHA_SECRET) {
    console.error("Missing RECAPTCHA_SECRET in environment variables.");
    return false;
  }

  try {
    const response = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        secret: RECAPTCHA_SECRET,
        response: token,
      }).toString(),
    });

    if (!response.ok) {
      console.error("reCAPTCHA verification request failed with status:", response.status);
      return false;
    }

    const data = await response.json();
    return data.success === true;
  } catch (error) {
    console.error("Error while verifying reCAPTCHA:", error);
    return false;
  }
}

// Basic sanitization to reduce simple injection and malformed input risks.
function sanitizeText(value) {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .trim()
    .replace(/[<>]/g, "")
    .replace(/[\u0000-\u001F\u007F]/g, "");
}

function sanitizeContactInput(req, res, next) {
  if (!req.body || typeof req.body !== "object") {
    return next();
  }

  req.body.name = sanitizeText(req.body.name);
  req.body.email = sanitizeText(req.body.email).toLowerCase();
  req.body.message = sanitizeText(req.body.message);
  req.body.token = sanitizeText(req.body.token);

  next();
}

// Enable CORS so the frontend app can call this API from the browser.
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
  })
);

// Set secure HTTP response headers.
app.use(helmet());

// Parse incoming JSON request bodies (application/json).
app.use(express.json());

// Health check endpoint used to confirm the API is up and running.
app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

// Contact endpoint that validates payload and sends an email via SMTP.
app.post("/api/contact", contactRateLimiter, sanitizeContactInput, async (req, res) => {
  try {
    const { name, email, message, token } = req.body;

    if (!name || !email || !message || !token) {
      return res.status(400).json({
        success: false,
        error: "name, email, message, and token are required",
      });
    }

    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({
        success: false,
        error: "invalid email format",
      });
    }

    const isCaptchaValid = await verifyRecaptcha(token);
    if (!isCaptchaValid) {
      return res.status(400).json({
        success: false,
        error: "Invalid captcha",
      });
    }

    if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !RECEIVER_EMAIL) {
      console.error("Missing SMTP configuration in environment variables.");
      return res.status(500).json({
        success: false,
        error: "email service is not configured",
      });
    }

    await transporter.sendMail({
      from: `Contact Form <${SMTP_USER}>`,
      to: RECEIVER_EMAIL,
      replyTo: email,
      subject: `New contact message from ${name}`,
      text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
    });

    return res.json({ success: true });
  } catch (error) {
    console.error("Failed to send contact email:", error);
    return res.status(500).json({
      success: false,
      error: "failed to send email",
    });
  }
});

// Last-resort error handler for unexpected server errors.
app.use((error, req, res, next) => {
  console.error("Unhandled server error:", error);
  res.status(500).json({
    success: false,
    error: "internal server error",
  });
});

// Start the server and listen on the configured port.
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
