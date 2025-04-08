const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET = "your_jwt_secret_key";
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes = 256 bits
const IV = crypto.randomBytes(16); // 16 bytes = 128 bits

const encrypt = (payload) => {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

  const cipher = crypto.createCipheriv("aes-256-cbc", ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, "utf8", "hex");
  encrypted += cipher.final("hex");

  const encryptedToken = `${IV.toString("hex")}:${encrypted}`;
  console.log("Encrypted Token:", encryptedToken);
  return encryptedToken;
};

const decrypt = (token) => {
  const [ivHex, encryptedToken] = token.split(":");
  const iv = Buffer.from(ivHex, "hex");

  const decipher = crypto.createDecipheriv("aes-256-cbc", ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encryptedToken, "hex", "utf8");
  decrypted += decipher.final("utf8");

  const payload = jwt.verify(decrypted, JWT_SECRET);
  console.log("Decrypted Payload:", payload);
  return payload;
};

// Test the functions
const samplePayload = { userId: "12345", role: "admin" };

const encrypted = encrypt(samplePayload);
const decrypted = decrypt(encrypted);

console.log("✅ Success: Payload matched!");
