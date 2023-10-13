const { ObjectId } = require("mongodb");

const createTransferRequest = async (req, res) => {
  try {
    const userId = req.user._id;
    const { title, amount } = req.body;

    const result = await req.db
      .collection("transfers")
      .insertOne({ userId, title, amount, status: "pending" });

    res.json({
      message: "Transfer request created successfully.",
      transferId: result.insertedId,
    });
  } catch (error) {
    console.error("Error creating transfer request:", error);
    res.status(500).json({ error: "Failed to create transfer request." });
  }
};

const getTransferList = async (req, res) => {
  try {
    const userId = req.user._id;

    const transferList = await req.db
      .collection("transfers")
      .find({ userId })
      .toArray();

    res.json({ transferList });
  } catch (error) {
    console.error("Error getting transfer list:", error);
    res.status(500).json({ error: "Failed to get transfer list." });
  }
};

const changeTransferStatus = async (req, res) => {
  try {
    const transferId = new ObjectId(req.params.transferId);

    console.log(transferId);
    const { status } = req.body;

    // Check if the user is an "approver"
    if (req.user.role !== "approver") {
      return res.status(403).json({ error: "Unauthorized" });
    }
    if (status !== "accept" && status !== "decline") {
      return res.status(400).json({ error: "Invalid status value." });
    }

    const result = await req.db
      .collection("transfers")
      .updateOne({ _id: transferId }, { $set: { status } });

    console.log("MongoDB Update Result:", result);

    if (result.modifiedCount === 1) {
      res.json({ message: "Transfer status updated successfully." });
    } else {
      res.status(404).json({ error: "Transfer not found." });
    }
  } catch (error) {
    console.error("Error changing transfer status:", error);
    res.status(500).json({ error: "Failed to change transfer status." });
  }
};

module.exports = {
  createTransferRequest,
  getTransferList,
  changeTransferStatus,
};
