require("dotenv").config();

const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");

const app = express();
app.use(cors());
app.use(express.json({ limit: "20kb" }));

const PORT = Number(process.env.PORT || 3000);
const SMTP_USER = String(process.env.SMTP_USER || "").trim();
const SMTP_APP_PASSWORD = String(process.env.SMTP_APP_PASSWORD || "").replace(/\s+/g, "");
const OTP_HASH_SECRET = String(process.env.OTP_HASH_SECRET || "").trim();

const OTP_EXPIRY_MS = 5 * 60 * 1000;
const SMTP_TIMEOUT_MS = 20 * 1000;
const FIRESTORE_TIMEOUT_MS = 15 * 1000;
const REQUEST_COOLDOWN_MS = 60 * 1000;
const MAX_ATTEMPTS = 5;

function requireEnv(name, value) {
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

requireEnv("SMTP_USER", SMTP_USER);
requireEnv("SMTP_APP_PASSWORD", SMTP_APP_PASSWORD);
requireEnv("OTP_HASH_SECRET", OTP_HASH_SECRET);

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

const db = admin.firestore();

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: SMTP_USER,
    pass: SMTP_APP_PASSWORD,
  },
  connectionTimeout: 10000,
  greetingTimeout: 10000,
  socketTimeout: 15000,
});

function withTimeout(promise, timeoutMs, label) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs} ms`)), timeoutMs);
    }),
  ]);
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function emailDocumentId(email) {
  return crypto.createHash("sha256").update(email).digest("hex");
}

function hashOtp(email, otp) {
  return crypto
    .createHmac("sha256", OTP_HASH_SECRET)
    .update(`${email}:${otp}`)
    .digest("hex");
}

function createOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function safeError(error) {
  return error instanceof Error ? error.message : String(error);
}

app.get("/", (_req, res) => {
  res.status(200).json({
    success: true,
    message: "SmartGuard online OTP server is running.",
  });
});

app.get("/health", (_req, res) => {
  res.status(200).json({
    success: true,
    message: "SmartGuard online OTP server is running.",
    timestamp: new Date().toISOString(),
  });
});

app.post("/request-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "Enter a valid email address." });
  }

  const documentId = emailDocumentId(email);
  const otpRef = db.collection("email_otp_requests").doc(documentId);

  try {
    const previous = await withTimeout(otpRef.get(), FIRESTORE_TIMEOUT_MS, "Firestore read");
    const previousData = previous.exists ? previous.data() : null;
    const previousCreatedAt = Number(previousData?.createdAtMs || 0);

    if (Date.now() - previousCreatedAt < REQUEST_COOLDOWN_MS) {
      return res.status(429).json({
        success: false,
        message: "Please wait one minute before requesting another OTP.",
      });
    }

    const otp = createOtp();
    const expiresAtMs = Date.now() + OTP_EXPIRY_MS;

    await withTimeout(
      otpRef.set({
        email,
        otpHash: hashOtp(email, otp),
        expiresAtMs,
        createdAtMs: Date.now(),
        attempts: 0,
        verified: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      }),
      FIRESTORE_TIMEOUT_MS,
      "Firestore write"
    );

    try {
      await withTimeout(
        transporter.sendMail({
          from: `SmartGuard Verification <${SMTP_USER}>`,
          to: email,
          subject: "Your SmartGuard verification code",
          text: `Your SmartGuard verification code is ${otp}.\n\nIt expires in 5 minutes. Do not share this code with anyone.`,
          html: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #111827;">
              <h2>SmartGuard Email Verification</h2>
              <p>Your verification code is:</p>
              <p style="font-size: 30px; font-weight: 700; letter-spacing: 8px;">${otp}</p>
              <p>This code expires in 5 minutes. Do not share this code with anyone.</p>
            </div>
          `,
        }),
        SMTP_TIMEOUT_MS,
        "SMTP send"
      );
    } catch (smtpError) {
      await otpRef.delete().catch(() => {});
      console.error("SMTP_SEND_FAILED", safeError(smtpError));
      return res.status(503).json({
        success: false,
        message: "Unable to send OTP email right now. Check the Render logs for SMTP_SEND_FAILED.",
      });
    }

    console.log("OTP_SENT", email);
    return res.status(200).json({
      success: true,
      message: "OTP sent. Check your inbox and spam folder.",
    });
  } catch (error) {
    console.error("REQUEST_OTP_FAILED", safeError(error));
    return res.status(500).json({
      success: false,
      message: "Unable to create OTP request. Check the Render logs for REQUEST_OTP_FAILED.",
    });
  }
});

app.post("/verify-otp", async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const otp = String(req.body?.otp || "").trim();

  if (!isValidEmail(email) || !/^\d{6}$/.test(otp)) {
    return res.status(400).json({ success: false, message: "Enter a valid email and 6-digit OTP." });
  }

  const documentId = emailDocumentId(email);
  const otpRef = db.collection("email_otp_requests").doc(documentId);
  const verifiedRef = db.collection("verified_email_users").doc(documentId);

  try {
    const snapshot = await withTimeout(otpRef.get(), FIRESTORE_TIMEOUT_MS, "Firestore read");

    if (!snapshot.exists) {
      return res.status(400).json({ success: false, message: "OTP request not found. Request a new OTP." });
    }

    const data = snapshot.data() || {};
    const attempts = Number(data.attempts || 0);

    if (attempts >= MAX_ATTEMPTS) {
      await otpRef.delete().catch(() => {});
      return res.status(400).json({ success: false, message: "Too many incorrect attempts. Request a new OTP." });
    }

    if (Date.now() > Number(data.expiresAtMs || 0)) {
      await otpRef.delete().catch(() => {});
      return res.status(400).json({ success: false, message: "OTP expired. Request a new OTP." });
    }

    if (data.otpHash !== hashOtp(email, otp)) {
      await otpRef.update({ attempts: attempts + 1 }).catch(() => {});
      return res.status(400).json({ success: false, message: "Incorrect OTP." });
    }

    await withTimeout(
      verifiedRef.set({
        email,
        status: "verified",
        verifiedAt: admin.firestore.FieldValue.serverTimestamp(),
      }),
      FIRESTORE_TIMEOUT_MS,
      "Firestore verified-user write"
    );

    await otpRef.delete().catch(() => {});

    console.log("OTP_VERIFIED", email);
    return res.status(200).json({ success: true, message: "Email verified successfully." });
  } catch (error) {
    console.error("VERIFY_OTP_FAILED", safeError(error));
    return res.status(500).json({
      success: false,
      message: "Unable to verify OTP. Check the Render logs for VERIFY_OTP_FAILED.",
    });
  }
});

app.post("/verification-status", async (req, res) => {
  const email = normalizeEmail(req.body?.email);

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, verified: false, message: "Enter a valid email address." });
  }

  try {
    const documentId = emailDocumentId(email);
    const snapshot = await withTimeout(
      db.collection("verified_email_users").doc(documentId).get(),
      FIRESTORE_TIMEOUT_MS,
      "Firestore verification-status read"
    );

    return res.status(200).json({ success: true, verified: snapshot.exists });
  } catch (error) {
    console.error("VERIFICATION_STATUS_FAILED", safeError(error));
    return res.status(500).json({
      success: false,
      verified: false,
      message: "Unable to check verification status.",
    });
  }
});

app.use((error, _req, res, _next) => {
  console.error("UNHANDLED_ERROR", safeError(error));
  res.status(500).json({ success: false, message: "Unexpected server error." });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SmartGuard online OTP server running on port ${PORT}`);
});
