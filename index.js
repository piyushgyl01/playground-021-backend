const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { initialiseDatabase } = require("./db/db.connect.js");
const User = require("./models/user.model.js");
const Album = require("./models/album.model.js");
const Image = require("./models/image.model.js");

const app = express();
const PORT = process.env.PORT || 4000;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = multer.diskStorage({});
const upload = multer({
  storage,
  fileFilter: function (req, file, cb) {
    if (!file.originalname.match(/\.(jpg|jpeg|png|gif)$/)) {
      return cb(new Error("Only image files are allowed!"), false);
    }
  },
});

app.use(express.json());
app.use(cors({ credentials: true, origin: process.env.FRONTEND_URL }));
app.use(cookieParser());

initialiseDatabase();

const verifyToken = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid token." });
  }
};

app.post("/auth/register", async (req, res) => {
  const { username, name, password } = req.body;
});
