# Las Magnolias Backend

Minimal Node.js + Express backend for a contact form.

## What this backend does

- Exposes a health endpoint to check server status.
- Exposes a contact endpoint that:
  - validates input (`name`, `email`, `message`, `token`)
  - verifies Google reCAPTCHA token
  - rate-limits requests (5 per minute per IP)
  - sanitizes incoming text fields
  - sends emails using SMTP (Nodemailer)
- Adds common HTTP security headers using Helmet.

## Endpoints

- `GET /api/health`
  - Response: `{ "status": "ok" }`

- `POST /api/contact`
  - Body:
    ```json
    {
      "name": "John Doe",
      "email": "john@example.com",
      "message": "Hello!",
      "token": "recaptcha_token"
    }
    ```
  - Success: `{ "success": true }`
  - Error: `{ "success": false, "error": "message" }`

## Environment variables

Create or update `.env` with:

- `PORT` (default: `4000`)
- `FRONTEND_ORIGIN` (example: `http://localhost:3000`)
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `RECEIVER_EMAIL`
- `RECAPTCHA_SECRET`

## Run locally

1. Install dependencies:
   `npm install`
2. Start server:
   `npm start`

Server runs on `http://localhost:4000` by default.
