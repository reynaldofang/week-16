const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const generateAccessToken = (user) => {
  return jwt.sign(
    { _id: user._id, username: user.username, role: user.role },
    "your-secret-key",
    { expiresIn: "15m" } // Access token expires in 15 minutes (adjust as needed)
  );
};

const generateRefreshToken = (user) => {
  return jwt.sign(
    { _id: user._id, username: user.username, role: user.role },
    "your-refresh-secret-key",
    { expiresIn: "7d" } // Refresh token expires in 7 days (adjust as needed)
  );
};

const loginUser = async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await req.db.collection("users").findOne({ username });
    if (!user) {
      throw new Error("Invalid credentials.");
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      throw new Error("Invalid credentials.");
    }

    const accessToken = generateAccessToken(user); // Generate access token
    const refreshToken = generateRefreshToken(user); // Generate refresh token

    res.json({
      message: "Login successful.",
      accessToken,
      refreshToken,
      expiresIn: "15m", // Include the expiration time of the access token
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(401).json({ error: error.message });
  }
};

module.exports = {
  loginUser,
};
