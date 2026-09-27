// ═══════════════════════════════════════════════════════════════════
// TouchQue Express.js middleware example
// ═══════════════════════════════════════════════════════════════════
//
// Shows how to protect Express routes with the middleware the SDK
// exports: add `requireTouchQue(tq, 'WITHDRAW')` to any route and it is
// now 2FA-protected.
// ═══════════════════════════════════════════════════════════════════

const { TouchQue, requireTouchQue } = require('../dist/index.js');

// ─── Initialize the TouchQue client ────────────────────────────
const tq = new TouchQue({
  apiKey: process.env.TOUCHQUE_API_KEY || 'tq_auth_abc123',
  apiSecret: process.env.TOUCHQUE_API_SECRET || 'YOUR_API_SECRET',
  baseUrl: process.env.TOUCHQUE_BASE_URL || 'http://localhost:3000',
});

// ═══════════════════════════════════════════════════════════════════
// Webhook verification middleware
// ═══════════════════════════════════════════════════════════════════

function verifyTouchQueWebhook(req, res, next) {
  try {
    const rawBody = typeof req.body === 'string'
      ? req.body
      : JSON.stringify(req.body);

    const event = tq.webhook.verify({
      rawBody,
      signature: req.headers['x-tq-signature'],
    });

    req.touchqueEvent = event;
    next();
  } catch {
    return res.status(403).json({
      error: 'INVALID_WEBHOOK',
      message: 'Webhook signature verification failed',
    });
  }
}

// ═══════════════════════════════════════════════════════════════════
// Usage (Express.js app)
// ═══════════════════════════════════════════════════════════════════
//
// const express = require('express');
// const app = express();
// app.use(express.json());
//
// // Your own auth middleware (JWT, session, etc.)
// const authenticate = require('./middleware/auth');
//
// // ─── 2FA-protected routes ──────────────────────────────────
//
// app.post('/api/withdraw',
//   authenticate,                        // 1) authenticate the user (JWT)
//   requireTouchQue(tq, 'WITHDRAW'),     // 2) require TouchQue 2FA approval
//   async (req, res) => {                // 3) perform the action
//     // req.touchque holds { requestId, challengeCode, approved }
//     const result = await executeWithdraw(req.body);
//     res.json({ success: true, ...result });
//   }
// );
//
// app.post('/api/transfer',
//   authenticate,
//   requireTouchQue(tq, 'TRANSFER'),
//   async (req, res) => {
//     const result = await executeTransfer(req.body);
//     res.json({ success: true, ...result });
//   }
// );
//
// app.post('/api/settings/change-password',
//   authenticate,
//   requireTouchQue(tq, 'SENSITIVE_ACTION', { timeout: 60000 }),
//   async (req, res) => {
//     await changePassword(req.user.id, req.body.newPassword);
//     res.json({ success: true });
//   }
// );
//
// // ─── Webhook endpoint ──────────────────────────────────────
// app.post('/webhooks/touchque',
//   express.raw({ type: 'application/json' }),
//   verifyTouchQueWebhook,
//   (req, res) => {
//     const event = req.touchqueEvent;
//     console.log('Webhook event:', event.event, event.status);
//     res.sendStatus(200);
//   }
// );

module.exports = { verifyTouchQueWebhook, tq };
