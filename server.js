"use strict";

require("dotenv").config();

const crypto = require("crypto");
const fs = require("fs");
const express = require("express");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");

const app = express();
const port = Number(process.env.PORT || 3000);
const smtpUser = String(process.env.SMTP_USER || "smartguardverify@gmail.com").trim();
const smtpAppPassword = String(process.env.SMTP_APP_PASSWORD || "").replace(/\s+/g, "");
const otpHashSecret = String(process.env.OTP_HASH_SECRET || "").trim();
const serviceAccountPath = String(
  process.env.GOOGLE_APPLICATION_CREDENTIALS || "/etc/secrets/firebase-service-account.json"
).trim();

const OTP_EXPIRY_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 5;
const MAX_VERIFY_ATTEMPTS = 5;

function initializeFirebase() {
  if (admin.apps.length > 0) {
    return;
  }

  if (fs.existsSync(serviceAccountPath)) {
    const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, "utf8"));
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    return;
  }

  admin.initializeApp({
    credential: admin.credential.applicationDefault()
  });
}

initializeFirebase();

const db = admin.firestore();
const otpCollection = db.collection("email_otp_requests");
const verifiedCollection = db.collection("verified_email_users");

app.use(express.json({ limit: "16kb" }));

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function createOtp() {
  return crypto.randomInt(100000, 1000000).toString();
}

function createSalt() {
  return crypto.randomBytes(16).toString("hex");
}

function emailDocumentId(email) {
  return crypto.createHash("sha256").update(email).digest("hex");
}

function hashOtp(email, otp, salt) {
  return crypto
    .createHmac("sha256", otpHashSecret)
    .update(`${email}|${otp}|${salt}`)
    .digest("hex");
}

function constantTimeEquals(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));

  if (leftBuffer.length !== rightBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function timestampFromMillis(value) {
  return admin.firestore.Timestamp.fromMillis(value);
}

function serverIsConfigured() {
  return Boolean(
    smtpUser &&
      smtpAppPassword &&
      otpHashSecret &&
      !smtpAppPassword.includes("PASTE_") &&
      !otpHashSecret.includes("PASTE_")
  );
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: smtpUser,
    pass: smtpAppPassword
  }
});

app.get("/health", async (_request, response) => {
  try {
    await db.collection("server_health_checks").doc("otp-server").set(
      {
        checkedAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );

    return response.json({
      success: true,
      message: "SmartGuard online OTP server is running.",
      configured: serverIsConfigured()
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    return response.status(500).json({
      success: false,
      message: "Server is running, but Firestore connection failed."
    });
  }
});

app.post("/verification-status", async (request, response) => {
  try {
    const email = normalizeEmail(request.body && request.body.email);

    if (!isValidEmail(email)) {
      return response.status(400).json({
        success: false,
        verified: false,
        message: "Enter a valid email address."
      });
    }

    const snapshot = await verifiedCollection.doc(emailDocumentId(email)).get();
    const verified = snapshot.exists && snapshot.get("status") === "verified";

    return response.json({
      success: true,
      verified
    });
  } catch (error) {
    console.error("Unable to check verification status:", error.message);

    return response.status(500).json({
      success: false,
      verified: false,
      message: "Unable to check verification status. Try again."
    });
  }
});

app.post("/request-otp", async (request, response) => {
  const email = normalizeEmail(request.body && request.body.email);

  if (!isValidEmail(email)) {
    return response.status(400).json({
      success: false,
      message: "Enter a valid email address."
    });
  }

  if (!serverIsConfigured()) {
    return response.status(500).json({
      success: false,
      message: "OTP server is not configured yet."
    });
  }

  const now = Date.now();
  const otpRef = otpCollection.doc(emailDocumentId(email));

  try {
    const existingSnapshot = await otpRef.get();
    const existing = existingSnapshot.exists ? existingSnapshot.data() : null;

    if (existing && existing.createdAtMillis && now - existing.createdAtMillis < RESEND_COOLDOWN_MS) {
      const waitSeconds = Math.ceil(
        (RESEND_COOLDOWN_MS - (now - existing.createdAtMillis)) / 1000
      );

      return response.status(429).json({
        success: false,
        message: `Wait ${waitSeconds} second(s) before requesting another OTP.`
      });
    }

    let requestWindowStartedAtMillis = now;
    let requestCount = 1;

    if (
      existing &&
      existing.requestWindowStartedAtMillis &&
      now - existing.requestWindowStartedAtMillis < RATE_LIMIT_WINDOW_MS
    ) {
      requestWindowStartedAtMillis = existing.requestWindowStartedAtMillis;
      requestCount = Number(existing.requestCount || 0) + 1;
    }

    if (requestCount > MAX_REQUESTS_PER_WINDOW) {
      return response.status(429).json({
        success: false,
        message: "Too many OTP requests. Try again after 15 minutes."
      });
    }

    const otp = createOtp();
    const salt = createSalt();

    await otpRef.set({
      email,
      otpHash: hashOtp(email, otp, salt),
      salt,
      attemptsLeft: MAX_VERIFY_ATTEMPTS,
      createdAtMillis: now,
      expiresAtMillis: now + OTP_EXPIRY_MS,
      requestWindowStartedAtMillis,
      requestCount,
      createdAt: timestampFromMillis(now),
      expiresAt: timestampFromMillis(now + OTP_EXPIRY_MS),
      status: "pending"
    });

    try {
      await transporter.sendMail({
        from: `SmartGuard Verification <${smtpUser}>`,
        to: email,
        subject: "Your SmartGuard verification code",
        text: `Your SmartGuard verification code is ${otp}. It expires in 5 minutes. Do not share this code with anyone.`,
        html: `
          <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;border:1px solid #dbeafe;border-radius:16px;">
            <h2 style="margin:0 0 12px;color:#0f172a;">SmartGuard Email Verification</h2>
            <p style="color:#334155;">Use this 6-digit code to verify your email:</p>
            <div style="font-size:34px;font-weight:700;letter-spacing:8px;color:#1d4ed8;margin:18px 0;">${otp}</div>
            <p style="color:#475569;">This code expires in 5 minutes. Do not share it with anyone.</p>
          </div>
        `
      });

      return response.json({
        success: true,
        message: "OTP sent. Check your inbox and spam folder."
      });
    } catch (mailError) {
      await otpRef.delete();
      console.error("Unable to send OTP:", mailError.message);

      return response.status(500).json({
        success: false,
        message: "Unable to send OTP. Check the OTP sender configuration."
      });
    }
  } catch (error) {
    console.error("Unable to create OTP:", error.message);

    return response.status(500).json({
      success: false,
      message: "Unable to create OTP. Try again."
    });
  }
});

app.post("/verify-otp", async (request, response) => {
  const email = normalizeEmail(request.body && request.body.email);
  const otp = String((request.body && request.body.otp) || "").trim();

  if (!isValidEmail(email) || !/^\d{6}$/.test(otp)) {
    return response.status(400).json({
      success: false,
      message: "Enter the email and the 6-digit OTP."
    });
  }

  const otpRef = otpCollection.doc(emailDocumentId(email));
  const verifiedRef = verifiedCollection.doc(emailDocumentId(email));

  try {
    const result = await db.runTransaction(async (transaction) => {
      const snapshot = await transaction.get(otpRef);

      if (!snapshot.exists) {
        return {
          status: 400,
          message: "OTP not found or already expired. Request a new OTP."
        };
      }

      const record = snapshot.data();

      if (Date.now() > Number(record.expiresAtMillis || 0)) {
        transaction.delete(otpRef);
        return {
          status: 400,
          message: "OTP expired. Request a new OTP."
        };
      }

      if (Number(record.attemptsLeft || 0) <= 0) {
        transaction.delete(otpRef);
        return {
          status: 429,
          message: "Too many incorrect attempts. Request a new OTP."
        };
      }

      const receivedHash = hashOtp(email, otp, record.salt);
      const valid = constantTimeEquals(receivedHash, record.otpHash);

      if (!valid) {
        const attemptsLeft = Number(record.attemptsLeft || 0) - 1;

        if (attemptsLeft <= 0) {
          transaction.delete(otpRef);
        } else {
          transaction.update(otpRef, { attemptsLeft });
        }

        return {
          status: 400,
          message: `Incorrect OTP. ${Math.max(attemptsLeft, 0)} attempt(s) remaining.`
        };
      }

      transaction.set(
        verifiedRef,
        {
          email,
          status: "verified",
          verifiedAt: admin.firestore.FieldValue.serverTimestamp()
        },
        { merge: true }
      );

      transaction.delete(otpRef);

      return {
        status: 200,
        message: "Email verified successfully."
      };
    });

    return response.status(result.status).json({
      success: result.status === 200,
      message: result.message
    });
  } catch (error) {
    console.error("Unable to verify OTP:", error.message);

    return response.status(500).json({
      success: false,
      message: "Unable to verify OTP. Try again."
    });
  }
});

app.listen(port, "0.0.0.0", () => {
  console.log(`SmartGuard online OTP server running on port ${port}`);
});
