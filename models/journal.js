const mongoose = require('mongoose');

const journalSchema = new mongoose.Schema({
  journalId: mongoose.Schema.Types.ObjectId,
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  journalTitle: String,
  authors: [String],
  abstract: String,
  keywords: [String],
  submissionDate: Date,
  filePath: String,
  status: {
    type: String,
    enum: ['Pending', 'Under Review', 'Accepted', 'Rejected', 'Needs Revision', 'Reviewed'],
    default: 'Pending'
  },
  reviewers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  reviewComments: [{
    reviewer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    comment: String,
    date: { type: Date, default: Date.now }
  }],
  reviewerChoices: [{
    reviewer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    choice: String
  }],
  editorialNotes: String,
  publicationDate: {
    type: Date,
    default: null
  },
  rubricId: { type: mongoose.Schema.Types.ObjectId, ref: 'Rubric' },
  consolidatedFeedback: String
});

module.exports = mongoose.model('Journal', journalSchema);
