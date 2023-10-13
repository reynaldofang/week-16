const express = require("express");
const bodyParser = require("body-parser");
const userRouter = require("./routes/authRoutes");
// const transferRoutes = require("./routes/transferRoutes");
const databaseMiddleware = require("./db");
const swaggerUi = require("swagger-ui-express");
const yaml = require("yaml");
const fs = require("fs");

const openApiPath = "swagger.yaml";
const file = fs.readFileSync(openApiPath, "utf8");
const swaggerDocument = yaml.parse(file);

const app = express();
const port = 8000;

app.use(bodyParser.json());

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use(databaseMiddleware);

app.use("/", userRouter);
// app.use("/transfers", transferRoutes);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
