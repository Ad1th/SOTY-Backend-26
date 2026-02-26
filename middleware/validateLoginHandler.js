const UserModel = require("../models/userModel");
const jwt = require("jsonwebtoken");

const isSingleLogin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization;

    if (!authHeader) {
      return res
        .status(401)
        .json({ message: "Authorization header is missing." });
    }

    const token = authHeader.split(" ")[1];

    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await UserModel.findById(decoded.id);

    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    if (decoded.tokenVersion !== user.tokenVersion) {
      return res.status(401).json({
        message:
          "Session expired. Logged in from another device/browser. Please login again.",
      });
    }
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Invalid or expired token." });
  }
};

module.exports = isSingleLogin;