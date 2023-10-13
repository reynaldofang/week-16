const { MongoClient } = require("mongodb");

let db;

const databaseMiddleware = async (req, res, next) => {
  try {
    console.log("try connect");
    const mongoClient = await new MongoClient(
      "mongodb://mongo:Th6nXt15sqzewC1SWJps@containers-us-west-64.railway.app:6173"
    ).connect();

    console.log("Connected to MongoDB");
    db = mongoClient.db("revou_week16");

    console.log(`Using database: ${db.databaseName}`);

    req.db = db;

    next();
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    res.status(500).send("Failed to connect to MongoDB");
  }
};

module.exports = databaseMiddleware;
