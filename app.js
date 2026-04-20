require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const fs = require("fs");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");

const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));
app.set("trust proxy", 1);
app.use(session({
  secret: "googleloginsecret",
  resave: false,
  saveUninitialized: false,
 cookie: {
  secure: false,
  sameSite: "lax"
}
}));
app.use(passport.initialize());
app.use(passport.session());



/* ---------------- DB ---------------- */

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch(err => console.log(err));

/* ---------------- MODELS ---------------- */

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  googleId: String,

  phone: String,
  isPhoneVerified: { type: Boolean, default: true },

  dob: Date,
  maritalStatus: {
    type: String,
    enum: ["Single", "Married"]
  },

  // 🔥 NEW FEATURES
  profilePic: String,
  isEmailVerified: { type: Boolean, default: false }
});

const jobSchema = new mongoose.Schema({
  title: String,
  company: String,
  location: String,
  salary: String,
  description: String,
  applyLink: String,
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User"
  }
});

const applicationSchema = new mongoose.Schema({
  jobId: { type: mongoose.Schema.Types.ObjectId, ref: "Job" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  resume: String,
  status: { type: String, default: "Pending" }
});

const User = mongoose.model("User", userSchema);
const Job = mongoose.model("Job", jobSchema);
const Application = mongoose.model("Application", applicationSchema);


passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
  async (accessToken, refreshToken, profile, done) => {

    try {

      let user = await User.findOne({ googleId: profile.id });

      if (!user) {
        user = await new User({
          name: profile.displayName,
          email: profile.emails[0].value,
          googleId: profile.id
        }).save();
      }

      return done(null, user);

    } catch (err) {
      return done(err, null);
    }

  }));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

/* ---------------- MULTER ---------------- */

if (!fs.existsSync("./public/uploads")) {
  fs.mkdirSync("./public/uploads", { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "public/uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
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




app.use(async (req, res, next) => {
  const token = req.cookies.token;

  if (!token) {
    res.locals.user = null;
    return next();
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    res.locals.user = user; // 🔥 GLOBAL USER
  } catch {
    res.locals.user = null;
  }

  next();
});


const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function calculateProfile(user) {
  if (!user) return 0;

  let total = 5;
  let done = 0;

  if (user.name) done++;
  if (user.phone) done++;
  if (user.dob) done++;
  if (user.maritalStatus) done++;
  if (user.profilePic) done++;

  return Math.floor((done / total) * 100);
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

  const { name, email, password } = req.body;

  const existing = await User.findOne({ email });

  if (existing) {
    return res.send("Email already registered");
  }

  const hash = await bcrypt.hash(password, 10);

  await new User({
    name,
    email,
    password: hash
  }).save();

  res.redirect("/login");

});

/* ---------------- LOGIN ---------------- */

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });

  if (!user) return res.render("login", { error: "User not found" });

  const match = await bcrypt.compare(password, user.password);

  if (!match) return res.render("login", { error: "Incorrect password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.cookie("token", token, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  res.redirect("/user-dashboard");
});

/* ---------------- GOOGLE LOGIN ---------------- */

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => {

    const token = jwt.sign(
      { id: req.user._id },
      process.env.JWT_SECRET
    );

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.redirect("/user-dashboard");

  }
);

/* ---------------- POST JOB ---------------- */

app.get("/post-job", auth, (req, res) => {
  res.render("post-job");
});

app.post("/post-job", auth, async (req, res) => {
  const { title, company, location, salary, description, applyLink } = req.body;

  const finalLink = applyLink
    ? (applyLink.startsWith("http") ? applyLink : "https://" + applyLink)
    : "";

  await new Job({
    title,
    company,
    location,
    salary,
    description,
    applyLink: finalLink,
    createdBy: req.user.id
  }).save();

  res.redirect("/user-dashboard");
});

/* ---------------- JOB LIST ---------------- */

app.get("/jobs", async (req, res) => {
  const jobs = await Job.find();
  res.render("jobs", { jobs });
});


app.get("/jobs/:id", async (req, res) => {
  const job = await Job.findById(req.params.id);
  res.render("jobdetails", { job });
});

/* ---------------- APPLY JOB ---------------- */

app.post("/apply/:id", auth, upload.single("resume"), async (req, res) => {

  const exists = await Application.findOne({
    jobId: req.params.id,
    userId: req.user.id
  });

  if (exists) return res.send("Already applied");
  if (!req.file) return res.send("Resume required");

  await new Application({
    jobId: req.params.id,
    userId: req.user.id,
    resume: req.file.filename
  }).save();

  res.render("apply-success");
});

/* ---------------- APPLICANTS ---------------- */

app.get("/applicants/:jobId", auth, async (req, res) => {

  const job = await Job.findById(req.params.jobId);

  if (!job) return res.send("Job not found");

  if (job.createdBy.toString() !== req.user.id) {
    return res.send("Not allowed");
  }

  const applicants = await Application.find({
    jobId: req.params.jobId
  })
    .populate("userId")
    .populate("jobId"); // 🔥 IMPORTANT

  res.render("applicants", { applicants, job });
});

/* ---------------- STATUS UPDATE ---------------- */

app.get("/update-status/:id/:status", auth, async (req, res) => {

  const application = await Application.findById(req.params.id).populate("jobId");

  if (!application) return res.send("Application not found");

  if (application.jobId.createdBy.toString() !== req.user.id) {
    return res.send("Not allowed");
  }

  await Application.findByIdAndUpdate(req.params.id, {
    status: req.params.status
  });

  // 🔥 FIX: redirect to applicants page
  res.redirect(`/applicants/${application.jobId._id}`);
});
/* ---------------- DASHBOARD ---------------- */

app.get("/user-dashboard", auth, async (req, res) => {

  const user = await User.findById(req.user.id);

  if (!user) {
    return res.redirect("/login"); // safety
  }

  const applications = await Application.find({
    userId: req.user.id
  }).populate("jobId");

  const myJobs = await Job.find({
    createdBy: req.user.id
  });

  const profilePercent = calculateProfile(user);

  res.render("user-dashboard", {
    user,
    applications,
    myJobs,
    profilePercent
  });
});
/* ---------------- search ---------------- */

app.get("/search", async (req, res) => {
  const query = req.query.q;

  try {
    const jobs = await Job.find({
      title: { $regex: query, $options: "i" }
    });

    res.render("jobs", { jobs, query });
  } catch (err) {
    res.send("Error in search");
  }
});

/* ---------------- DELETE ---------------- */

app.get("/delete-job/:id", auth, async (req, res) => {

  const job = await Job.findById(req.params.id);

  if (job.createdBy.toString() !== req.user.id) {
    return res.send("Not allowed");
  }

  await Job.findByIdAndDelete(req.params.id);

  res.redirect("/user-dashboard");
});
/* ---------------- Edit page ---------------- */

app.get("/edit-job/:id", auth, async (req, res) => {

  const job = await Job.findById(req.params.id);

  if (!job) return res.send("Job not found");

  // security check
  if (job.createdBy.toString() !== req.user.id) {
    return res.send("Not allowed");
  }

  res.render("edit-job", { job });
});

/* ---------------- updated route ---------------- */
app.post("/edit-job/:id", auth, async (req, res) => {

  const job = await Job.findById(req.params.id);

  if (!job) return res.send("Job not found");

  if (job.createdBy.toString() !== req.user.id) {
    return res.send("Not allowed");
  }

  const { title, company, location, salary, description, applyLink } = req.body;

  await Job.findByIdAndUpdate(req.params.id, {
    title,
    company,
    location,
    salary,
    description,
    applyLink
  });

  res.redirect("/user-dashboard");
});


/* ---------------- PROFILE PAGE ---------------- */

app.get("/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id);

  const profilePercent = calculateProfile(user); // ⭐ ADD THIS

  res.render("profile", {
    user,
    query: req.query,
     profilePercent,// ⭐ PASS TO FRONTEND
  });
});

app.post("/upload-profile-pic", auth, upload.single("profilePic"), async (req, res) => {
  if (!req.file) return res.send("No file");

  await User.findByIdAndUpdate(req.user.id, {
    profilePic: req.file.filename
  });

  res.redirect("/profile?updated=true");
});
/* ---------------- UPDATE PROFILE ---------------- */

app.post("/profile", auth, async (req, res) => {
  const { name, phone, dob, maritalStatus } = req.body;

  await User.findByIdAndUpdate(req.user.id, {
    name,
    phone,
    dob,
    maritalStatus,
    isPhoneVerified: true // ✅ always verified
  });
  res.redirect("/profile?updated=true");
  
});





/* ---------------- LOGOUT ---------------- */

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.clearCookie("token");
    res.redirect("/");
  });
});
/* ---------------- SERVER ---------------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});