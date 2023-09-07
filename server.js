const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(express.json());

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// user schema and model using Mongoose
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  image: String,
  address: String,
  phoneNumber: String,
  password: String,
  authToken: String,
  userSkills: [String],
  pricePerHour: Number,
});

const User = mongoose.model("User", UserSchema);

// --- Token Verification Middleware ---
const verifyToken = (req, res, next) => {
  const authToken = req.header("Authorization");

  if (!authToken) {
    return res.status(401).json({ message: "Authorization token missing" });
  }

  jwt.verify(authToken, process.env.JWT_SECRET, (err, decodedToken) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }

    req.userId = decodedToken.userId;
    req.isAdmin = decodedToken.isAdmin; // Include isAdmin flag in the request

    next();
  });
};

// --- User Registration Route ---
app.post("/register", async (req, res, next) => {
  try {
    const {
      name,
      email,
      image,
      address,
      phoneNumber,
      password,
      userSkills,
      pricePerHour,
    } = req.body;

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      image,
      address,
      phoneNumber,
      password: hashedPassword,
      userSkills,
      pricePerHour,
    });

    const authToken = jwt.sign(
      { userId: newUser._id, isAdmin: false },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    newUser.authToken = authToken;
    await newUser.save();
    res
      .status(201)
      .json({ message: "User registered successfully", authToken });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// --- User Login Route ---
app.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const authToken = jwt.sign(
      { userId: user._id, isAdmin: false },
      process.env.JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    res.json({ message: "Login successful", authToken });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// --- Get User by ID Route ---
app.get("/user/:id", async (req, res, next) => {
  const userId = req.params.id;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User data retrieved successfully", user });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

//get all data
app.get("/users", async (req, res, next) => {
  try {
    const users = await User.find();
    res.json({ users });
  } catch (error) {
    console.error(error);
    next(error);
  }
});
//delet user
app.delete("/user/:id", async (req, res, next) => {
  const userId = req.params.id;

  try {
    const deletedUser = await User.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User deleted successfully", deletedUser });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

//edit user data
app.put("/user/:id", async (req, res, next) => {
  const userId = req.params.id;
  const updateData = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
    });

    if (!updatedUser) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "User updated successfully", updatedUser });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

// --- Protected Route for Demonstration ---
app.get("/protected-route", async (req, res, next) => {
  const userId = req.userId;

  try {
    const user = await User.findById(userId);

    if (err || !user) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json({ message: "Protected route accessed", user });
  } catch (error) {
    console.error(error);
    next(error);
  }
});
// --- Error-handling middleware ---
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ message: "Something went wrong" });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
