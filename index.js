const express = require("express");
const bodyParser = require("body-parser");
const dotenv = require("dotenv").config();
const connectDb = require("./db/dbConnection");
const AuthRoute = require("./routes/authRoute");
const userRoute = require("./routes/userRoute");
const questionRoute = require("./routes/questionRoute");
const cors = require("cors");

connectDb();

const app = express();

const port = process.env.PORT || 5000;

app.use(express.json());
// app.use(
//   cors({
//     origin: "http://localhost:3000",
//     credentials: true,
//   }),
// );

const allowedOrigins = [
  "http://localhost:3000",
  "https://soty-frontend-2026.vercel.app",
  "https://soty-frontend-26-eight.vercel.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
  })
);

app.use("/auth", AuthRoute);
app.use("/users", userRoute);
app.use("/questions", questionRoute);

app.get("");

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
