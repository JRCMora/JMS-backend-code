// models/rubric.js

const mongoose = require('mongoose');

const rubricSchema = new mongoose.Schema({
  rubricId: mongoose.Schema.Types.ObjectId,
  name: {
    type: String,
    required: true
  },
  description: String,
  components: [{
    name: {
      type: String,
      required: true
    },
    levels: [{
      label: {
        type: String,
        required: true
      },
      description: String,
      score: {
        type: Number,
        required: true
      }
    }]
  }]
});

module.exports = mongoose.model('Rubric', rubricSchema);
