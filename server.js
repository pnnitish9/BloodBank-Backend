import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import bodyParser from "body-parser";
import User from "./models/User.js";

dotenv.config();

const app = express();
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://pn-dsa-visuliazer.vercel.app"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.warn("Blocked CORS for origin:", origin);
      return callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
}));
app.use(bodyParser.json());

mongoose
  .connect(process.env.MONGO_URI, { dbName: "DSAVisualizer" })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// let isConnected = false;
// async function ConnectedToDB() {
//       mongoose.connect(process.env.MONGO_URI, {
//       useNewUrlParser: true,
//       useUnifiedTopology: true
//     })
//     .then(() => {
//       isConnected = true
//       console.log("MongoDB Connected")
//     })
//     .catch(err => console.error("MongoDB Connection Error:", err));
// }

// // middleware 
// app.use((req,res,next)=>{
//   if(!isConnected){
//     ConnectedToDB();
//   }
//   next();
// })

app.use("/",(req,res)=>{
  res.send("HOME");
})

// REGISTER
app.post("/api/register", async (req, res) => {
  try {

    const { name, gender, dob, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      gender,
      dob,
      email,
      password: hashedPassword,
    });

    res.status(201).json({
      message: "User registered successfully",
      userId: user._id,
    });
  } catch (error) {
    console.error("Register error:", error.message);
    res.status(400).json({ message: error.message || "Invalid data" });
  }
});


// LOGIN
app.post("/api/login", async (req, res) => {
  try {

    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7D" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error.message);
    res.status(400).json({ message: error.message || "Invalid data" });
  }
});

// const PORT = process.env.PORT || 3000;
// app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

module.exports = app;