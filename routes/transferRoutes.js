const express = require("express");
const transferController = require("../controllers/transferController");
const {
  authenticateJWT,
  authorizeRole,
} = require("../middleware/authMiddleware");

const router = express.Router();

router.post(
  "/create",
  authenticateJWT,
  transferController.createTransferRequest
);

router.get(
  "/transfer-list",
  authenticateJWT,
  transferController.getTransferList
);

router.patch(
  "/change-status/:transferId",
  authenticateJWT,
  authorizeRole("approver"), // Assuming you have this middleware
  transferController.changeTransferStatus
);

module.exports = router;
