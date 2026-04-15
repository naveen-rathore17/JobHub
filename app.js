require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static("public"));

/* ---------------- DB ---------------- */

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch((err) => console.log(err));

/* ---------------- MODELS ---------------- */

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: { type: String, default: "user" },
});

const jobSchema = new mongoose.Schema({
  title: String,
  company: String,
  location: String,
  salary: String,
  description: String,
});

const applicationSchema = new mongoose.Schema({
  jobId: { type: mongoose.Schema.Types.ObjectId, ref: "Job" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  resume: String,
  status: {
    type: String,
    default: "Pending",
  },
});

const User = mongoose.model("User", userSchema);
const Job = mongoose.model("Job", jobSchema);
const Application = mongoose.model("Application", applicationSchema);

/* ---------------- MULTER ---------------- */

if (!fs.existsSync("./public/uploads")) {
  fs.mkdirSync("./public/uploads", { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});

const upload = multer({ storage });

/* ---------------- AUTH ---------------- */

function auth(req, res, next) {
  const token = req.cookies.token;

  if (!token) return res.redirect("/login");

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.redirect("/login");
  }
}

/* ---------------- HOME ---------------- */

app.get("/", async (req, res) => {
  const jobs = await Job.find();
  res.render("index", { jobs });
});

/* ---------------- REGISTER ---------------- */

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { name, email, password, isAdmin } = req.body;

  const role = isAdmin ? "admin" : "user";

  const hash = await bcrypt.hash(password, 10);

  const user = new User({
    name,
    email,
    password: hash,
    role,
  });

  await user.save();

  res.redirect("/login");
});

/* ---------------- LOGIN ---------------- */

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) {
    return res.render("login", { error: "User not found" });
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.render("login", { error: "Incorrect password" });
  }

  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET
  );

  res.cookie("token", token);

  if (user.role === "admin") {
    res.redirect("/admin-dashboard");
  } else {
    res.redirect("/user-dashboard");
  }
});

/* ---------------- ADMIN DASHBOARD ---------------- */

app.get("/admin-dashboard", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Not allowed");
  }

  const jobs = await Job.find();

  res.render("admin-dashboard", { jobs });
});

/* ---------------- POST JOB ---------------- */

app.get("/post-job", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Only admin allowed");
  }

  res.render("post-job");
});

app.post("/post-job", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Only admin allowed");
  }

  const { title, company, location, salary, description } = req.body;

  const job = new Job({
    title,
    company,
    location,
    salary,
    description,
  });

  await job.save();

  res.redirect("/admin-dashboard");
});

/* ---------------- JOB LIST ---------------- */

app.get("/jobs", async (req, res) => {
  const jobs = await Job.find();
  res.render("jobs", { jobs });
});

/* ---------------- JOB DETAILS ---------------- */

app.get("/jobs/:id", async (req, res) => {
  const job = await Job.findById(req.params.id);
  res.render("jobdetails", { job });
});

/* ---------------- APPLY JOB ---------------- */

app.post(
  "/apply/:id",
  auth,
  upload.single("resume"),
  async (req, res) => {
    const alreadyApplied = await Application.findOne({
      jobId: req.params.id,
      userId: req.user.id,
    });

    if (alreadyApplied) {
      return res.send("You already applied for this job");
    }

    if (!req.file) {
      return res.send("Resume required");
    }

    const application = new Application({
      jobId: req.params.id,
      userId: req.user.id,
      resume: req.file.filename,
    });

    await application.save();

    res.redirect("/user-dashboard");
  }
);

/* ---------------- USER DASHBOARD ---------------- */

app.get("/user-dashboard", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  const applications = await Application.find({
    userId: req.user.id,
  }).populate("jobId");

  res.render("user-dashboard", {
    applications,
    user,
  });
});

/* ---------------- DELETE JOB ---------------- */

app.get("/delete-job/:id", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Not allowed");
  }

  await Job.findByIdAndDelete(req.params.id);

  res.redirect("/admin-dashboard");
});

/* ---------------- EDIT JOB ---------------- */

app.get("/edit-job/:id", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Not allowed");
  }

  const job = await Job.findById(req.params.id);

  res.render("edit-job", { job });
});

app.post("/edit-job/:id", auth, async (req, res) => {
  const { title, company, location, salary, description } = req.body;

  await Job.findByIdAndUpdate(req.params.id, {
    title,
    company,
    location,
    salary,
    description,
  });

  res.redirect("/admin-dashboard");
});

/* ---------------- APPLICANTS ---------------- */

app.get("/applicants/:jobId", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Not allowed");
  }

  const applications = await Application.find({
    jobId: req.params.jobId,
  })
    .populate("userId")
    .populate("jobId");

  res.render("applicants", { applications });
});

app.get("/update-status/:id/:status", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  if (user.role !== "admin") {
    return res.send("Not allowed");
  }

  const application = await Application.findById(req.params.id);

  if (!application) {
    return res.send("Application not found");
  }

  await Application.findByIdAndUpdate(req.params.id, {
    status: req.params.status,
  });

  res.redirect("/applicants/" + application.jobId);
});

/* ---------------- SEARCH ---------------- */

app.get("/search", async (req, res) => {
  const keyword = req.query.q;

  const jobs = await Job.find({
    title: { $regex: keyword, $options: "i" },
  });

  res.render("jobs", { jobs });
});

/* ---------------- LOGOUT ---------------- */

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

/* ---------------- SERVER ---------------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});