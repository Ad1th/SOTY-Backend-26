const userModel = require("../models/userModel");
const jwt = require("jsonwebtoken");

const isAdmin = async (req, res, next) => {
  try {
    let token;
    let authHeader = req.headers.authorization || req.headers.Authorization;

    if (!authHeader) {
      return res
        .status(401)
        .json({ message: "Authorization header is missing." });
    }

    token = authHeader.split(" ")[1];

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Token expired" });
      }
      return res.status(401).json({ message: "Invalid token" });
    }

    const user = await userModel.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    if (user.isAdmin === true) {
      next();
    } else {
      res.status(403).json({ message: "Access Forbidden: Admin only" });
    }
  } catch (error) {
    console.error("Admin Validation Error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

module.exports = isAdmin;
