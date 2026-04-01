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
    error: "Demasiadas solicitudes. Probá de nuevo en unos minutos",
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
  req.body.telefono = sanitizeText(req.body.telefono);
  req.body.ciudad = sanitizeText(req.body.ciudad);
  req.body.message = sanitizeText(req.body.message);

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
    const { name, email, telefono, ciudad, message } = req.body;

    if (!name || !email || !telefono || !message) {
      return res.status(400).json({
        success: false,
        error: "Los campos nombre, email, teléfono y mensaje son obligatorios",
      });
    }

    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({
        success: false,
        error: "El formato del email no es válido",
      });
    }

    if (!SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS || !RECEIVER_EMAIL) {
      console.error("Falta configuración SMTP en las variables de entorno.");
      return res.status(500).json({
        success: false,
        error: "El servicio de correo no está configurado",
      });
    }

    await transporter.sendMail({
      from: `Formulario de contacto <${SMTP_USER}>`,
      to: RECEIVER_EMAIL,
      replyTo: email,
      subject: `Nuevo mensaje de contacto de ${name}`,
      text: `Nombre: ${name}\nEmail: ${email}\nTeléfono: ${telefono}\nCiudad: ${ciudad || "No especificada"}\n\nMensaje:\n${message}`,
    });

    return res.json({ success: true });
  } catch (error) {
    console.error("No se pudo enviar el correo de contacto:", error);
    return res.status(500).json({
      success: false,
      error: "No se pudo enviar el correo",
    });
  }
});

// Last-resort error handler for unexpected server errors.
app.use((error, req, res, next) => {
  console.error("Error no controlado del servidor:", error);
  res.status(500).json({
    success: false,
    error: "Error interno del servidor",
  });
});

// Start the server and listen on the configured port.
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);

  transporter.verify((error) => {
    if (error) {
      console.error("Falló la conexión SMTP:", error.message);
      return;
    }

    console.log("Conexión SMTP verificada.");
  });
});
