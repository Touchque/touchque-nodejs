// ═══════════════════════════════════════════════════════════════════
// TouchQue Node.js SDK — real-world usage examples
// ═══════════════════════════════════════════════════════════════════
//
// Shows how a company integrating the TouchQue SDK into its own system
// (e.g. a crypto exchange) would use it.
//
// To run:
//   1. Start a backend:  cd your-backend && npm run dev
//   2. Run this file:     node examples/withdraw.js
// ═══════════════════════════════════════════════════════════════════

const { TouchQue, TouchQueRejectedError, TouchQueTimeoutError } = require('../dist/index.js');

// ─── Initialize the SDK client ──────────────────────────────────
// The partner enters the API credentials from the TouchQue Dashboard.
// All HMAC signing, nonce and timestamp handling is done by the SDK.
const tq = new TouchQue({
  apiKey: 'tq_auth_abc123',        // API key from the Dashboard
  apiSecret: 'YOUR_API_SECRET',    // API secret from the Dashboard
  baseUrl: 'http://localhost:3000', // local testing (prod: https://api.touchque.com)
});

// ═══════════════════════════════════════════════════════════════════
// SCENARIO 1: Withdraw — full flow
// ═══════════════════════════════════════════════════════════════════
//
// When a user taps "Withdraw 1 BTC" on the exchange, the company's
// backend calls this function.

async function handleWithdraw(userId, amount, currency) {
  console.log(`\nWithdraw request: ${amount} ${currency} — user: ${userId}`);
  console.log('Sending an approval prompt to the user\'s phone...\n');

  try {
    // ─── 2FA in one call ─────────────────────────────────────
    // The SDK sends the login request, waits for the user's answer and
    // returns the result. It resolves on approval and throws on
    // rejection or timeout.
    const result = await tq.login.verify({
      externalUsername: userId,
      type: 'WITHDRAW',                     // action type (defined in the Dashboard)
      referenceId: `withdraw_${Date.now()}`, // your own transaction id
      timeout: 30000,                        // wait 30 seconds
    });

    // Reaching here means the user approved.
    console.log('Approved — executing the transaction...');
    console.log(`   Request ID: ${result.requestId}`);

    // The company performs its own withdraw here:
    // await executeWithdraw(userId, amount, currency);

    return { success: true, message: 'Withdraw succeeded' };

  } catch (error) {
    if (error instanceof TouchQueRejectedError) {
      console.log('User rejected the request. Withdraw cancelled.');
      return { success: false, message: 'User rejected' };
    }

    if (error instanceof TouchQueTimeoutError) {
      console.log('User did not respond in time. Withdraw cancelled.');
      return { success: false, message: 'Timed out' };
    }

    console.error('Unexpected error:', error.message);
    return { success: false, message: 'System error' };
  }
}

// ═══════════════════════════════════════════════════════════════════
// SCENARIO 2: Login — simple usage
// ═══════════════════════════════════════════════════════════════════

async function handleLogin(userId) {
  console.log(`\nLogin request: ${userId}`);

  try {
    await tq.login.verify({
      externalUsername: userId,
      type: 'LOGIN',
      timeout: 60000, // 60 seconds for a login
    });

    console.log('Login approved — creating a session...');
    return { success: true };

  } catch (error) {
    if (error instanceof TouchQueRejectedError) {
      console.log('Login rejected.');
      return { success: false, reason: 'rejected' };
    }
    if (error instanceof TouchQueTimeoutError) {
      console.log('Login timed out.');
      return { success: false, reason: 'timeout' };
    }
    throw error;
  }
}

// ═══════════════════════════════════════════════════════════════════
// SCENARIO 3: Step-by-step control (advanced)
// ═══════════════════════════════════════════════════════════════════
//
// If the company wants to show a "Waiting..." animation in its own UI
// while approval is pending, it can drive the flow step by step.

async function handleTransferAdvanced(userId, targetAccount, amount) {
  console.log(`\nTransfer request: ${amount} → ${targetAccount}`);

  // Step 1: send the request
  const loginReq = await tq.login.request({
    externalUsername: userId,
    type: 'TRANSFER',
    referenceId: `transfer_${Date.now()}`,
  });

  console.log(`Prompt sent. Request ID: ${loginReq.requestId}`);
  if (loginReq.challengeCode) {
    console.log(`Challenge code: ${loginReq.challengeCode} (show this to the user)`);
  }

  // Step 2: poll the status (usable to drive your own UI)
  let attempts = 0;
  while (attempts < 20) {
    const { status } = await tq.login.status(loginReq.requestId);

    if (status === 'CONFIRMED') {
      console.log('Transfer approved.');
      return { success: true };
    }
    if (status === 'REJECTED') {
      console.log('Transfer rejected.');
      return { success: false, reason: 'rejected' };
    }
    if (status === 'EXPIRED') {
      console.log('Transfer expired.');
      return { success: false, reason: 'expired' };
    }

    // PENDING — wait
    console.log(`   Waiting... (${++attempts}/20)`);
    await new Promise(r => setTimeout(r, 1500));
  }

  return { success: false, reason: 'timeout' };
}

// ═══════════════════════════════════════════════════════════════════
// SCENARIO 4: Webhook verification
// ═══════════════════════════════════════════════════════════════════
//
// TouchQue also reports outcomes to the partner via webhooks. Always
// verify that a webhook actually came from TouchQue.

function handleWebhook(rawBody, signatureHeader) {
  try {
    const event = tq.webhook.verify({
      rawBody: rawBody,
      signature: signatureHeader,
    });

    console.log(`\nWebhook received: ${event.event}`);
    console.log(`   Request: ${event.requestId}`);
    console.log(`   User: ${event.externalUsername}`);
    console.log(`   Status: ${event.status}`);

    switch (event.event) {
      case 'login.confirmed':
        // perform the action
        break;
      case 'login.rejected':
        // cancel the action
        break;
    }
  } catch {
    console.log('Forged webhook detected — request rejected.');
  }
}

// ═══════════════════════════════════════════════════════════════════
// RUN
// ═══════════════════════════════════════════════════════════════════

// Uncomment one of these to run an example:
// handleLogin('user@company.com');
// handleWithdraw('user@company.com', '1.5', 'BTC');
// handleTransferAdvanced('user@company.com', 'ACC-123456', '5000');

console.log('─────────────────────────────────────────');
console.log(' TouchQue Node.js SDK');
console.log(' Enable a function call above to run an example.');
console.log('─────────────────────────────────────────');

module.exports = { handleWithdraw, handleLogin, handleTransferAdvanced, handleWebhook };
