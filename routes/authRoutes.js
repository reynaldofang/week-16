const express = require("express");
const router = express.Router();
const userController = require("../controllers/userController");

// Define routes for user registration and login
router.post("/register", userController.createUser);
router.post("/login", userController.loginUser);
router.post("/reset-password-request", userController.resetPasswordRequest);

// New route to reset the password using the token
router.post("/reset-password", userController.resetPassword);

module.exports = router;
