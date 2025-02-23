const mongoose = require("mongoose");

const albumSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
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
