const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  notificationId: mongoose.Schema.Types.ObjectId,
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  message: String,
  status: { type: String, default: 'unread' },
  createdAt: { type: Date, default: Date.now },
  journalId: { type: mongoose.Schema.Types.ObjectId, ref: 'Journal' },
});

module.exports = mongoose.model('Notification', notificationSchema);
