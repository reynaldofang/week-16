const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_ATTEMPT_WINDOW_MINUTES = 1;
const loginAttempts = new Map();
const refreshTokenMap = new Map();

const generateAccessToken = (user) => {
  return jwt.sign(
    { _id: user._id, username: user.username, role: user.role },
    "your-secret-key",
    { expiresIn: "1h" }
  );
};

const generateRefreshToken = () => {
  const refreshToken = jwt.sign({}, "your-refresh-secret-key", {
    expiresIn: "7d", // 7 days
  });
  return refreshToken;
};

const createUser = async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res
      .status(400)
      .json({ error: "Username, password, and role are required." });
  }

  if (username.trim() === "") {
    return res.status(400).json({ error: "Username cannot be blank." });
  }

  if (
    password.length < 8 ||
    !password.match(/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/)
  ) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters long and contain both letters and numbers.",
    });
  }

  if (role !== "maker" && role !== "approver") {
    return res
      .status(400)
      .json({ error: "Invalid role. Valid roles are 'maker' and 'approver'." });
  }

  try {
    // Check if username already exists
    const existingUser = await req.db.collection("users").findOne({ username });
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists." });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await req.db.collection("users").insertOne({
      username,
      password: hashedPassword,
      role,
    });
    res.json({
      message: "User created successfully.",
      userId: result.insertedId,
    });
  } catch (error) {
    console.error("Error creating user:", error);
    res.status(500).json({ error: "Failed to create user." });
  }
};

const loginUser = async (req, res) => {
  const { username, password } = req.body;

  // Check if the user has exceeded the maximum login attempts
  if (
    loginAttempts.has(username) &&
    loginAttempts.get(username).count >= MAX_LOGIN_ATTEMPTS
  ) {
    const lastAttemptTime = loginAttempts.get(username).timestamp;
    const elapsedTime = Date.now() - lastAttemptTime;

    if (elapsedTime < LOGIN_ATTEMPT_TIMEOUT) {
      return res.status(401).json({
        error: `Maximum login attempts exceeded. Please try again after ${
          (LOGIN_ATTEMPT_TIMEOUT - elapsedTime) / 1000
        } seconds.`,
      });
    } else {
      // Reset login attempts after 1 minute
      loginAttempts.delete(username);
    }
  }

  try {
    const user = await req.db.collection("users").findOne({ username });
    if (!user) {
      throw new Error("Invalid credentials.");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      // Increment login attempts for the user
      if (!loginAttempts.has(username)) {
        loginAttempts.set(username, { count: 1, timestamp: Date.now() });
      } else {
        loginAttempts.get(username).count++;
      }

      throw new Error("Invalid credentials.");
    }

    // If login is successful, reset login attempts for the user
    loginAttempts.delete(username);

    const token = generateAccessToken({
      _id: user._id,
      username: user.username,
      role: user.role,
    });
    const refreshToken = generateRefreshToken();

    // Store the refresh token in a map for future use
    refreshTokenMap.set(username, refreshToken);

    res.json({
      message: "Login successful.",
      tokens: {
        access_token: token,
        refresh_token: refreshToken,
        expires_in: 3600, // 1 hour in seconds
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(401).json({ error: error.message });
  }
};

const getAllUsers = (req, res) => {
  const query = "SELECT * FROM users";

  db.query(query, (err, result) => {
    if (err) {
      console.error("Error fetching users:", err);
      return res.status(500).json({ error: "Error fetching users." });
    }
    return res.status(200).json({ users: result });
  });
};

module.exports = {
  createUser,
  loginUser,
  getAllUsers,
};
