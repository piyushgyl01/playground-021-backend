const mongoose = require("mongoose");

const albumSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    albumCover: {
      type: String,
    },
    description: {
      type: String,
    },
    owner: {
      type: String,    
      required: true,
    },
    sharedUsers: [
      {
        type: String,
      },
    ],
  },
  { timestamps: true }
);

module.exports = mongoose.model("picslifyAlbum", albumSchema);
