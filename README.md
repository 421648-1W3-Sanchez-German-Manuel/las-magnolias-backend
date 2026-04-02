# Las Magnolias Backend

Node.js + Express backend preparado para Vercel Serverless Functions.

## What this backend does

- Exposes a contact endpoint that:
  - validates input (`name`, `email`, `telefono`, `ciudad`, `message`)
  - rate-limits requests (5 per minute per IP)
  - sanitizes incoming text fields
  - applies strict CORS allowlist + preflight handling
  - sends emails using SMTP (Nodemailer)
- Adds common HTTP security headers using Helmet.

## Endpoints

- `POST /api/contact`
  - Body:
    ```json
    {
      "name": "John Doe",
      "email": "john@example.com",
      "telefono": "+54 9 11 1234 5678",
      "ciudad": "Buenos Aires",
      "message": "Hola!"
    }
    ```
  - Success: `{ "success": true }`
  - Error: `{ "success": false, "error": "message" }`

- `OPTIONS /api/contact`
  - Maneja preflight CORS.

## Environment variables

Create or update `.env` with:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `RECEIVER_EMAIL`

Allowed origins are fixed in the API implementation:

- `http://localhost:3000`
- `http://127.0.0.1:5500`
- `https://www.lasmagnolias.com.ar`
- `https://lasmagnolias.com.ar`

## Run locally

1. Install dependencies:
   `npm install`
2. Run locally:
  `npm start`

For Vercel deployment, use the serverless function in `api/contact.js`.
