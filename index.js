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
    cb(null, true);
  },
});

app.use(express.json());
const corsOptions = {
  origin: "*",
  credentials: true,
  optionSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(cookieParser());

const JWT_SECRET = process.env.JWT_SECRET;

initialiseDatabase();

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    console.log("Provide token");
    return res
      .status(401)
      .json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Invalid token." });
  }
};

app.post("/auth/register", async (req, res) => {
  const { username, name, password } = req.body;

  if (!username || !name || !password) {
    return res.status(400).json({ message: "Please provide" });
  }

  try {
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      username,
      name,
      password: hashedPassword,
    });

    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error registering user", error: error.message });
  }
});

app.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Please provide" });
  }

  try {
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Invalid password" });
    }

    const token = jwt.sign(
      {
        id: user._id,
        username: user.username,
      },
      JWT_SECRET,
      {
        expiresIn: "24h",
      }
    );

    const userResponse = {
      _id: user._id,
      username: user.username,
      name: user.name,
    };

    res.status(200).json({
      message: "Logged in",
      token,
      user: userResponse,
    });
  } catch (error) {
    res.status(500).json({ message: "Error logging in", error: error.message });
  }
});

app.get("/auth/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error fetching user", error: error.message });
  }
});

app.post("/auth/logout", (req, res) => {
  res.json({ message: "Logged out successfully" });
});

app.post("/albums", verifyToken, async (req, res) => {
  const { name, description, albumCover } = req.body;
  const userId = req.user.id;

  try {
    const newAlbum = new Album({
      name,
      description,
      owner: userId,
      albumCover,
    });

    const savedAlbum = await newAlbum.save();
    res
      .status(201)
      .json({ message: "Album created successfully", album: savedAlbum });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error creating album", error: error.message });
  }
});

app.get("/albums", verifyToken, async (req, res) => {
  try {
    const albums = await Album.find({ owner: req.user.id });
    res.json({ albums });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error getting album", error: error.message });
  }
});

app.get("/albums/shared", verifyToken, async (req, res) => {
  try {
    const userUsername = req.user.username;

    const sharedAlbums = await Album.find({
      sharedUsers: userUsername,
      owner: { $ne: req.user.id },
    });

    res.status(200).json({
      message: "Shared albums fetched successfully.",
      albums: sharedAlbums,
    });
  } catch (error) {
    res.status(500).json({
      message: "Error fetching shared albums",
      error: error.message,
    });
  }
});

app.get("/albums/:id", verifyToken, async (req, res) => {
  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (
      album.owner !== req.user.id &&
      !album.sharedUsers.includes(req.user.username)
    ) {
      return res.status(403).json({ message: "Access denied" });
    }

    res.json({ album });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error getting album", error: error.message });
  }
});

app.put("/albums/:id", verifyToken, async (req, res) => {
  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (album.owner !== req.user.id) {
      res.status(403).json({ message: "Not authorised to update this album" });
    }

    const updatedAlbum = await Album.findByIdAndUpdate(
      req.params.id,
      { $set: req.body },
      { new: true }
    );

    res.json({ message: "Album updated successfully", album: updatedAlbum });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error updating album", error: error.message });
  }
});

app.delete("/albums/:id", verifyToken, async (req, res) => {
  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (album.owner !== req.user.id) {
      res.status(403).json({ message: "Not authorized to delete this album" });
    }

    await Album.findByIdAndDelete(req.params.id);
    await Image.deleteMany({ albumId: req.params.id });

    res.json({ message: "Album and associated images deleted successfully" });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error deleting album", error: error.message });
  }
});

app.post("/albums/:id/share", verifyToken, async (req, res) => {
  const { usernames } = req.body;

  try {
    const album = await Album.findById(req.params.id);
    if (!album) {
      return res.status(404).json({ message: "Album not found" });
    }

    if (album.owner !== req.user.id) {
      res.status(403).json({ message: "Not authorized to share this album" });
    }

    album.sharedUsers = [...new Set([...album.sharedUsers, ...usernames])];
    await album.save();

    res.json({ message: "Album shared successfully", album });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error sharing album", error: error.message });
  }
});

app.post(
  "/albums/:albumId/images",
  verifyToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const { albumId } = req.params;
      const { tags, person, isFavorite, name } = req.body;
      const userId = req.user.id;
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ message: "Album not found" });
      }

      if (album.owner !== userId) {
        return res
          .status(403)
          .json({ message: "Not authorized to upload to this album" });
      }

      const file = req.file;
      if (!file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const fileSize = fs.statSync(file.path).size;
      if (fileSize > 5 * 1024 * 1024) {
        return res.status(400).json({ message: "File size exceeds 5MB limit" });
      }

      const result = await cloudinary.uploader.upload(file.path, {
        folder: "uploads",
      });

      const newImage = new Image({
        albumId,
        cloudinaryPublicId: result.public_id,
        file: result.secure_url,
        tags: tags ? tags.split(",").map((tag) => tag.trim()) : [],
        person,
        isFavorite: isFavorite || false,
        name,
        size: fileSize,
      });

      await newImage.save();

      res
        .status(201)
        .json({ message: "Image uploaded successfully", image: newImage });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Error posting images", error: error.message });
    }
  }
);

app.get("/albums/:albumId/images", verifyToken, async (req, res) => {
  try {
    const { albumId } = req.params;
    const { tags } = req.query;

    const query = { albumId };
    if (tags) {
      query.tags = { $in: tags.split(",").map((tag) => tag.trim()) };
    }

    const images = await Image.find(query).populate("comments.user");
    res.json({ images });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Error getting images", error: error.message });
  }
});

app.put(
  "/albums/:albumId/images/:imageId/favorite",
  verifyToken,
  async (req, res) => {
    try {
      const { albumId, imageId } = req.params;
      const userId = req.user.id;

      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ message: "Album not found" });
      }

      if (userId !== album.owner) {
        return res.status(403).json({ message: "Not authorised" });
      }

      const image = await Image.findByIdAndUpdate(
        imageId,
        [{ $set: { isFavorite: { $not: "$isFavorite" } } }],
        { new: true }
      );

      if (!image) {
        res.status(404).json({ message: "Image not found" });
      }

      res.json({ message: "Favorite status updated", image });
    } catch (error) {
      res.status(500).json({
        message: "Error toggling favorite status",
        error: error.message,
      });
    }
  }
);

app.post(
  "/albums/:albumId/images/:imageId/comments",
  verifyToken,
  async (req, res) => {
    try {
      const { albumId, imageId } = req.params;
      const { text } = req.body;
      const userId = req.user.id;

      if (!text || text.trim() === "") {
        return res.status(400).json({ message: "Comment text is required" });
      }

      // Check if album exists and user has access
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ message: "Album not found" });
      }

      // Allow comments from both the owner and users the album is shared with
      if (
        album.owner !== userId &&
        !album.sharedUsers.includes(req.user.username)
      ) {
        return res
          .status(403)
          .json({ message: "Not authorized to comment on this album" });
      }

      // Find the image and add comment
      const image = await Image.findById(imageId);
      if (!image) {
        return res.status(404).json({ message: "Image not found" });
      }

      // Create and add the comment
      const newComment = {
        text,
        user: userId,
        createdAt: new Date(),
      };

      image.comments.push(newComment);
      await image.save();

      // Fetch the populated comment to return
      const populatedImage = await Image.findById(imageId).populate(
        "comments.user",
        "username name"
      );
      const addedComment =
        populatedImage.comments[populatedImage.comments.length - 1];

      res.status(201).json({
        message: "Comment added successfully",
        comment: addedComment,
        imageId,
      });
    } catch (error) {
      console.error("Add Comment Error:", error);
      res.status(500).json({
        message: "Error adding comment",
        error: error.message,
      });
    }
  }
);

app.delete(
  "/albums/:albumId/images/:imageId",
  verifyToken,
  async (req, res) => {
    try {
      const { albumId, imageId } = req.params;
      const userId = req.user.id;

      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ message: "Album not found" });
      }

      if (userId !== album.owner) {
        return res.status(403).json({ message: "Not authorised" });
      }

      const image = await Image.findById(imageId);
      if (!image) {
        return res.status(404).json({ message: "Image not found" });
      }

      if (image.cloudinaryPublicId) {
        await cloudinary.uploader.destroy(image.cloudinaryPublicId);
      }

      await Image.findByIdAndDelete(imageId);

      res.json({ message: "Image deleted successfully" });
    } catch (error) {
      res.status(500).json({
        message: "Error deleting image",
        error: error.message,
      });
    }
  }
);

app.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json({ user });
  } catch (error) {
    res.status(500).json({
      message: "Error getting profile",
      error: error.message,
    });
  }
});

app.put("/profile", verifyToken, async (req, res) => {
  try {
    const { name, profilePicture } = req.body;

    const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { name, profilePicture },
      { new: true }
    ).select("-password");

    res.json({ message: "Profile updated successfully", user: updatedUser });
  } catch (error) {
    res.status(500).json({
      message: "Error updating profile",
      error: error.message,
    });
  }
});

app.put("/profile/password", verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);
    const validPassword = await bcrypt.compare(currentPassword, user.password);

    if (!validPassword) {
      return res.status(400).json({ message: "Current password is incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;
    await user.save();

    res.json({ message: "Password updated successfully" });
  } catch (error) {
    res.status(500).json({
      message: "Error updating password",
      error: error.message,
    });
  }
});

app.get("/search/images", verifyToken, async (req, res) => {
  try {
    const { query, tags, person, albumId, favorite } = req.query;

    const searchCriteria = {};

    if (albumId) {
      const album = await Album.findById(albumId);
      if (!album) {
        return res.status(404).json({ message: "Album not found" });
      }

      if (
        album.owner !== req.user.id &&
        !album.sharedUsers.includes(req.user.username)
      ) {
        return res.status(403).json({ message: "Access denied" });
      }
      searchCriteria.albumId = albumId;
    } else {
      const userAlbums = await Album.find({
        $or: [{ owner: req.user.id }, { sharedUsers: req.user.username }],
      });
      searchCriteria.albumId = { $in: userAlbums.map((album) => album._id) };
    }

    if (query) {
      searchCriteria.name = { $regex: query, $options: "i" };
    }

    if (tags) {
      searchCriteria.tags = {
        $in: tags.split(",").map((tag) => new RegExp(tag.trim(), "i")),
      };
    }

    if (person) {
      searchCriteria.person = { $regex: person, $options: "i" };
    }

    if (favorite === "true") {
      searchCriteria.isFavorite = true;
    }

    const images = await Image.find(searchCriteria)
      .populate("comments.user", "username name")
      .sort({ createdAt: -1 });

    res.json({ images });
  } catch (error) {
    res.status(500).json({ message: "Error searching images" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
