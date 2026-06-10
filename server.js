const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "64kb" }));

const PORT = Number(process.env.PORT || 3000);
const BREVO_API_KEY = process.env.BREVO_API_KEY || "";
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL || "";
const BREVO_SENDER_NAME = process.env.BREVO_SENDER_NAME || "SmartGuard Verification";
const OTP_HASH_SECRET = process.env.OTP_HASH_SECRET || "";

const OTP_EXPIRATION_MS = 5 * 60 * 1000;
const OTP_REQUEST_COOLDOWN_MS = 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;
const requestCooldowns = new Map();

function requireEnvironment() {
  const missing = [];

  if (!BREVO_API_KEY) missing.push("BREVO_API_KEY");
  if (!BREVO_SENDER_EMAIL) missing.push("BREVO_SENDER_EMAIL");
  if (!OTP_HASH_SECRET) missing.push("OTP_HASH_SECRET");

  if (missing.length > 0) {
    throw new Error(`Missing environment variables: ${missing.join(", ")}`);
  }
}

requireEnvironment();

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

const db = admin.firestore();

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function createOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function hashOtp(email, otp) {
  return crypto
    .createHmac("sha256", OTP_HASH_SECRET)
    .update(`${email}:${otp}`)
    .digest("hex");
}

function safeHashEquals(left, right) {
  try {
    const a = Buffer.from(left, "hex");
    const b = Buffer.from(right, "hex");

    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

async function sendOtpUsingBrevoApi(recipientEmail, otp) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);

  try {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "api-key": BREVO_API_KEY,
      },
      body: JSON.stringify({
        sender: {
          name: BREVO_SENDER_NAME,
          email: BREVO_SENDER_EMAIL,
        },
        to: [{ email: recipientEmail }],
        subject: "Your SmartGuard verification code",
        textContent:
          `Your SmartGuard verification code is ${otp}.\n\n` +
          "It expires in 5 minutes. Do not share this code with anyone.",
        htmlContent:
          `<div style="font-family:Arial,sans-serif;line-height:1.6">` +
          `<h2>SmartGuard Verification</h2>` +
          `<p>Your verification code is:</p>` +
          `<p style="font-size:30px;font-weight:bold;letter-spacing:6px">${otp}</p>` +
          `<p>This code expires in 5 minutes. Do not share it with anyone.</p>` +
          `</div>`,
      }),
      signal: controller.signal,
    });

    const responseText = await response.text();

    if (!response.ok) {
      throw new Error(
        `Brevo API returned ${response.status}: ${responseText || "Unknown error"}`
      );
    }

    return responseText ? JSON.parse(responseText) : {};
  } finally {
    clearTimeout(timeout);
  }
}

app.get("/health", (_req, res) => {
  res.status(200).json({
    success: true,
    message: "SmartGuard online OTP server is running.",
  });
});

app.post("/request-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!isValidEmail(email)) {
    return res.status(400).json({
      success: false,
      message: "Enter a valid email address.",
    });
  }

  const now = Date.now();
  const lastRequestAt = requestCooldowns.get(email) || 0;

  if (now - lastRequestAt < OTP_REQUEST_COOLDOWN_MS) {
    return res.status(429).json({
      success: false,
      message: "Please wait one minute before requesting another OTP.",
    });
  }

  requestCooldowns.set(email, now);

  const otp = createOtp();
  const requestRef = db.collection("email_otp_requests").doc(email);

  try {
    await requestRef.set({
      email,
      codeHash: hashOtp(email, otp),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(now + OTP_EXPIRATION_MS),
      attempts: 0,
      consumed: false,
    });

    await sendOtpUsingBrevoApi(email, otp);

    return res.status(200).json({
      success: true,
      message: "OTP sent. Check your inbox and spam folder.",
    });
  } catch (error) {
    console.error("REQUEST_OTP_FAILED", error);

    try {
      await requestRef.delete();
    } catch (deleteError) {
      console.error("OTP_CLEANUP_FAILED", deleteError);
    }

    requestCooldowns.delete(email);

    return res.status(502).json({
      success: false,
      message: "Unable to send OTP. Check the online server logs.",
    });
  }
});

app.post("/verify-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const otp = String(req.body?.otp || "").trim();

  if (!isValidEmail(email) || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({
      success: false,
      message: "Enter a valid email and 6-digit OTP.",
    });
  }

  const requestRef = db.collection("email_otp_requests").doc(email);

  try {
    const snapshot = await requestRef.get();

    if (!snapshot.exists) {
      return res.status(400).json({
        success: false,
        message: "Request a new OTP first.",
      });
    }

    const data = snapshot.data() || {};
    const expiresAtMs = data.expiresAt?.toMillis?.() || 0;
    const attempts = Number(data.attempts || 0);

    if (data.consumed === true) {
      return res.status(400).json({
        success: false,
        message: "This OTP was already used. Request a new one.",
      });
    }

    if (Date.now() > expiresAtMs) {
      return res.status(400).json({
        success: false,
        message: "OTP expired. Request a new one.",
      });
    }

    if (attempts >= OTP_MAX_ATTEMPTS) {
      return res.status(429).json({
        success: false,
        message: "Too many attempts. Request a new OTP.",
      });
    }

    const isCorrect = safeHashEquals(
      String(data.codeHash || ""),
      hashOtp(email, otp)
    );

    if (!isCorrect) {
      await requestRef.update({
        attempts: admin.firestore.FieldValue.increment(1),
      });

      return res.status(400).json({
        success: false,
        message: "Incorrect OTP.",
      });
    }

    await db.collection("verified_email_users").doc(email).set(
      {
        email,
        status: "verified",
        verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    await requestRef.update({
      consumed: true,
      verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.status(200).json({
      success: true,
      message: "Email verified successfully.",
    });
  } catch (error) {
    console.error("VERIFY_OTP_FAILED", error);

    return res.status(500).json({
      success: false,
      message: "Unable to verify OTP. Check the online server logs.",
    });
  }
});

app.post("/verification-status", async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!isValidEmail(email)) {
    return res.status(400).json({
      success: false,
      verified: false,
      message: "Enter a valid email address.",
    });
  }

  try {
    const snapshot = await db.collection("verified_email_users").doc(email).get();
    const verified = snapshot.exists && snapshot.data()?.status === "verified";

    return res.status(200).json({
      success: true,
      verified,
    });
  } catch (error) {
    console.error("VERIFICATION_STATUS_FAILED", error);

    return res.status(500).json({
      success: false,
      verified: false,
      message: "Unable to check verification status.",
    });
  }
});

app.use((error, _req, res, _next) => {
  console.error("UNHANDLED_SERVER_ERROR", error);

  res.status(500).json({
    success: false,
    message: "Unexpected server error.",
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SmartGuard online OTP server running on port ${PORT}`);
});
