// server.js - Complete Humanitarian Backend with Supabase (for Vercel)
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();

// ---------- MIDDLEWARE ----------
app.use(cors());
app.use(express.json());

// ---------- SUPABASE CLIENT ----------
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_KEY;
if (!supabaseUrl || !supabaseServiceKey) {
  console.error(
    "Missing SUPABASE_URL or SUPABASE_SERVICE_KEY environment variables",
  );
  process.exit(1);
}
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// ---------- JWT SECRET ----------
const JWT_SECRET =
  process.env.JWT_SECRET || "humanitarian_secret_key_change_me";

const nodemailer = require("nodemailer");

// Email transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || "587"),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});
const FROM_EMAIL = process.env.SMTP_FROM || "noreply@humanityfirst.org";

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function storeOTP(email, otp) {
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
  await supabase
    .from("email_otps")
    .insert([{ email, otp, expires_at: expiresAt.toISOString(), used: false }]);
}

async function verifyOTP(email, otp) {
  const { data } = await supabase
    .from("email_otps")
    .select("*")
    .eq("email", email)
    .eq("otp", otp)
    .eq("used", false)
    .gt("expires_at", new Date().toISOString())
    .order("created_at", { ascending: false })
    .limit(1);
  if (!data || data.length === 0) return false;
  await supabase.from("email_otps").update({ used: true }).eq("id", data[0].id);
  return true;
}

// In-memory pending volunteer store (or use a DB table)
const pendingVolunteers = new Map();

// ---------- HELPER: AUTHENTICATE MIDDLEWARE ----------
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

// ---------- INITIALIZE DEFAULT ADMIN (with bcrypt hashed password) ----------
const initAdmin = async () => {
  const email = "admin@humanityfirst.org";
  const plainPassword = "admin123";
  const hashedPassword = await bcrypt.hash(plainPassword, 10);

  // Check if user exists
  const { data: existing, error: findError } = await supabase
    .from("users")
    .select("id")
    .eq("email", email)
    .maybeSingle();

  if (findError && findError.code !== "PGRST116") {
    console.error("Error checking admin:", findError.message);
    return;
  }

  if (!existing) {
    // Insert new admin
    const { error: insertError } = await supabase
      .from("users")
      .insert([{ email, password: hashedPassword, role: "admin" }]);
    if (insertError) console.error("Admin insert error:", insertError.message);
    else console.log("✅ Default admin created:", email);
  } else {
    // Update password to latest hash (in case hash changes)
    const { error: updateError } = await supabase
      .from("users")
      .update({ password: hashedPassword })
      .eq("email", email);
    if (updateError) console.error("Admin update error:", updateError.message);
    else console.log("✅ Admin password synced");
  }
};

// ---------- SEED RESOURCES IF EMPTY ----------
const seedResources = async () => {
  const { count, error: countError } = await supabase
    .from("resources")
    .select("*", { count: "exact", head: true });
  if (countError) {
    console.error("Resource count error:", countError.message);
    return;
  }
  if (count === 0) {
    const resources = [
      { name: "Food Parcels", amount: 5000, unit: "kits" },
      { name: "Clean Water (liters)", amount: 20000, unit: "liters" },
      { name: "Medical Kits", amount: 1200, unit: "kits" },
      { name: "Tents", amount: 350, unit: "units" },
    ];
    const { error: insertError } = await supabase
      .from("resources")
      .insert(resources);
    if (insertError) console.error("Resource seed error:", insertError.message);
    else console.log("✅ Resources seeded");
  }
};

// Run initializers (do not block startup)
initAdmin();
seedResources();

// ---------- HEALTH CHECK ----------
app.get("/", (req, res) => {
  res.json({ message: "Humanitarian API with Supabase is running" });
});

// ---------- AUTH ROUTES ----------
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password required" });
  }

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, password")
      .eq("email", email)
      .maybeSingle();

    if (error || !user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.json({ token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------- CRISIS ROUTES ----------
app.get("/api/crisis", async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("crisis")
      .select("*")
      .order("date", { ascending: false });
    if (error) throw error;
    res.json({ crisis: data });
  } catch (err) {
    console.error("GET /crisis error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/crisis", authenticate, async (req, res) => {
  const { title, content, type } = req.body;
  if (!title) {
    return res.status(400).json({ error: "Title is required" });
  }
  try {
    const { data, error } = await supabase
      .from("crisis")
      .insert([{ title, content, type: type || "update" }])
      .select();
    if (error) throw error;
    res.json({ success: true, crisis: data[0] });
  } catch (err) {
    console.error("POST /crisis error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/crisis/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from("crisis").delete().eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /crisis error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- TASKS ROUTES ----------
app.get("/api/tasks", async (req, res) => {
  try {
    let query = supabase
      .from("tasks")
      .select("*")
      .order("created_at", { ascending: false });
    if (req.query.public === "true") {
      query = query.neq("status", "completed");
    }
    const { data, error } = await query;
    if (error) throw error;
    res.json({ tasks: data });
  } catch (err) {
    console.error("GET /tasks error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/tasks", authenticate, async (req, res) => {
  const { title, description, location } = req.body;
  if (!title) {
    return res.status(400).json({ error: "Task title required" });
  }
  try {
    const { data, error } = await supabase
      .from("tasks")
      .insert([{ title, description, location, status: "pending" }])
      .select();
    if (error) throw error;
    res.json({ success: true, task: data[0] });
  } catch (err) {
    console.error("POST /tasks error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/tasks/:id/assign", authenticate, async (req, res) => {
  const { id } = req.params;
  const { volunteerEmail } = req.body;
  if (!volunteerEmail) {
    return res.status(400).json({ error: "Volunteer email required" });
  }
  try {
    const { data, error } = await supabase
      .from("tasks")
      .update({ assigned_to: volunteerEmail, status: "assigned" })
      .eq("id", id)
      .select();
    if (error) throw error;
    res.json({ success: true, task: data[0] });
  } catch (err) {
    console.error("PUT /tasks/assign error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/tasks/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase.from("tasks").delete().eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /tasks error:", err);
    res.status(500).json({ error: err.message });
  }
});

//const pendingVolunteers = new Map();

// ---------- VOLUNTEERS ROUTES ----------
app.get("/api/volunteers", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase.from("volunteers").select("*");
    if (error) throw error;
    res.json({ volunteers: data });
  } catch (err) {
    console.error("GET /volunteers error:", err);
    res.status(500).json({ error: err.message });
  }
});

/*app.post("/api/volunteers", async (req, res) => {
  const { name, email, skills } = req.body;
  if (!name || !email) {
    return res.status(400).json({ error: "Name and email required" });
  }
  try {
    const { data, error } = await supabase
      .from("volunteers")
      .insert([{ name, email, skills, phone, age, status: "pending" }])
      .select();
    if (error) throw error;
    res.json({ success: true, volunteer: data[0] });
  } catch (err) {
    console.error("POST /volunteers error:", err);
    res.status(500).json({ error: err.message });
  }
});*/

app.put("/api/volunteers/:id/approve", authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    const { error } = await supabase
      .from("volunteers")
      .update({ status: "approved" })
      .eq("id", id);
    if (error) throw error;
    res.json({ success: true });
  } catch (err) {
    console.error("PUT /volunteers/approve error:", err);
    res.status(500).json({ error: err.message });
  }
});

// otp mode

// 1. Send OTP
app.post("/api/volunteers/send-otp", async (req, res) => {
  const { email, name, phone, age, skills } = req.body;
  if (!email || !name) {
    return res.status(400).json({ error: "Email and name required" });
  }

  // Store pending data with all fields
  pendingVolunteers.set(email, {
    name,
    email,
    phone: phone || null,
    age: age ? parseInt(age) : null,
    skills: skills || null,
  });

  const otp = generateOTP();
  await storeOTP(email, otp);

  const html = `<h2>Email Verification</h2>
                <p>Your OTP for volunteer registration: <strong>${otp}</strong></p>
                <p>Valid for 10 minutes.</p>`;

  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: "Verify your email",
      html,
    });
    res.json({ success: true });
  } catch (err) {
    console.error("Email send error:", err);
    res.status(500).json({ error: "Failed to send OTP email" });
  }
});

// 2. Verify OTP and create volunteer
app.post("/api/volunteers/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: "Email and OTP required" });
  }

  const isValid = await verifyOTP(email, otp);
  if (!isValid) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  const pending = pendingVolunteers.get(email);
  if (!pending) {
    return res.status(400).json({ error: "No pending registration" });
  }

  // Insert volunteer with all fields
  const { error } = await supabase.from("volunteers").insert([
    {
      name: pending.name,
      email: pending.email,
      phone: pending.phone,
      age: pending.age,
      skills: pending.skills,
      status: "pending",
    },
  ]);

  if (error) {
    console.error("Insert error:", error);
    return res.status(500).json({ error: "Failed to register volunteer" });
  }

  pendingVolunteers.delete(email);
  res.json({ success: true });
});

// 3. Admin send message to volunteer (unchanged, but ensure error handling)
app.post("/api/admin/send-message", authenticate, async (req, res) => {
  const { toEmail, subject, message } = req.body;
  if (!toEmail || !subject || !message) {
    return res.status(400).json({ error: "Missing fields" });
  }
  const html = `<div><h2>HumanityFirst</h2><p>${message.replace(
    /\n/g,
    "<br>",
  )}</p></div>`;
  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: toEmail,
      subject,
      html,
    });
    res.json({ success: true });
  } catch (err) {
    console.error("Message send error:", err);
    res.status(500).json({ error: "Failed to send email" });
  }
});

// ---------- RESOURCES ROUTES ----------
app.get("/api/resources", async (req, res) => {
  try {
    const { data, error } = await supabase.from("resources").select("*");
    if (error) throw error;
    res.json({ resources: data });
  } catch (err) {
    console.error("GET /resources error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/resources/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { amount } = req.body;
  if (amount === undefined) {
    return res.status(400).json({ error: "Amount required" });
  }
  try {
    const { data, error } = await supabase
      .from("resources")
      .update({ amount, last_updated: new Date() })
      .eq("id", id)
      .select();
    if (error) throw error;
    res.json({ success: true, resource: data[0] });
  } catch (err) {
    console.error("PUT /resources error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- DONATIONS ROUTES ----------
app.post("/api/donations", async (req, res) => {
  const { donorName, donorEmail, amount, message } = req.body;
  if (!donorName || !amount) {
    return res.status(400).json({ error: "Donor name and amount required" });
  }
  try {
    const { data, error } = await supabase
      .from("donations")
      .insert([
        { donor_name: donorName, donor_email: donorEmail, amount, message },
      ])
      .select();
    if (error) throw error;
    res.json({ success: true, donation: data[0] });
  } catch (err) {
    console.error("POST /donations error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/donations", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("donations")
      .select("*")
      .order("date", { ascending: false });
    if (error) throw error;
    res.json({ donations: data });
  } catch (err) {
    console.error("GET /donations error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/donations/total", async (req, res) => {
  try {
    const { data, error } = await supabase.from("donations").select("amount");
    if (error) throw error;
    const totalDonated = data.reduce((sum, d) => sum + (d.amount || 0), 0);
    res.json({ totalDonated });
  } catch (err) {
    console.error("GET /donations/total error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- AID REQUESTS ROUTES ----------
app.post("/api/aid-requests", async (req, res) => {
  const { name, contact, familySize, needs } = req.body;
  if (!name || !contact) {
    return res.status(400).json({ error: "Name and contact required" });
  }
  try {
    const { data, error } = await supabase
      .from("aid_requests")
      .insert([
        { name, contact, family_size: familySize, needs, status: "pending" },
      ])
      .select();
    if (error) throw error;
    res.json({ success: true, request: data[0] });
  } catch (err) {
    console.error("POST /aid-requests error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/aid-requests", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("aid_requests")
      .select("*")
      .order("date", { ascending: false });
    if (error) throw error;
    res.json({ requests: data });
  } catch (err) {
    console.error("GET /aid-requests error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- EXPORT FOR VERCEL --------
module.exports = app;
