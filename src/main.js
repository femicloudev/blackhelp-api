require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  role: { type: String, enum: ["user", "admin"], default: "user" },
});
const User = mongoose.model("User", UserSchema);

// Project Schema
const ProjectSchema = new mongoose.Schema({
  title: String,
  description: String,
  goal: Number,
  raised: { type: Number, default: 0 },
  category: String,
  milestones: [{ title: String, amount: Number, reached: { type: Boolean, default: false } }],
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  socialLinks: { facebook: String, twitter: String, linkedin: String },
});
const Project = mongoose.model("Project", ProjectSchema);

// Middleware for authentication
const authMiddleware = (req, res, next) => {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "Access Denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid Token" });
  }
};

// User Registration
app.post("/register", async (req, res) => {
  const { name, email, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const newUser = await User.create({ name, email, password: hashedPassword, role });
    res.status(201).json({ message: "User created", user: newUser });
  } catch (error) {
    res.status(400).json({ error: "Email already exists" });
  }
});

// User Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.json({ token });
});

// Create Project (Authenticated)
app.post("/projects", authMiddleware, async (req, res) => {
  const { title, description, goal, category, milestones, socialLinks } = req.body;
  const project = await Project.create({ title, description, goal, category, milestones, socialLinks, owner: req.user.id });
  res.status(201).json(project);
});

// Get All Projects
app.get("/projects", async (req, res) => {
  const projects = await Project.find().populate("owner", "name");
  res.json(projects);
});

// Donate to Project
app.post("/projects/:id/donate", async (req, res) => {
  const { amount } = req.body;
  const project = await Project.findById(req.params.id);
  if (!project) return res.status(404).json({ error: "Project not found" });

  project.raised += amount;
  project.milestones.forEach(milestone => {
    if (project.raised >= milestone.amount) {
      milestone.reached = true;
    }
  });

  await project.save();
  res.json({ message: "Donation successful", project });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
