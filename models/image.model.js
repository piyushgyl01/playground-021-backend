const mongoose = require("mongoose");

const imageSchema = new mongoose.Schema(
  {
    albumId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "picslifyAlbum",
      required: true,
    },
    cloudinaryPublicId: {
      type: String,
      required: true,
    },
    name: {
      type: String,
      required: true,
    },
    file: {
      type: String,
      required: true,
    },
    tage: [
      {
        type: String,
      },
    ],
    person: {
      type: String,
    },
    isFavorite: {
      type: Boolean,
      default: false,
    },
    comments: [
      {
        text: {
          type: String,
        },
        user: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "picslifyUser",
          createdAt: {
            type: Date,
            default: Date.now,
          },
        },
      },
    ],
    size: {
      type: Number,
      required: true,
    },
    uploadedAt: {
      type: Date,
      default: Date.now,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model("picslifyImage", imageSchema);
