const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  email: String,
  firstName: String,
  lastName: String,
  password: String,
  role: {
    type: String,
    enum: ['superadmin', 'admin', 'reviewer', 'author'],
  },
  status: {
    type: String,
    enum: ['Assigned', 'Not Assigned'],
    default: 'Not Assigned'
  },
  emailVerified: {
    type: Boolean,
    default: function() {
      // Set emailVerified to false for users with the role 'author'
      return this.role === 'author' ? false : true;
    }
  },
  verificationToken: String,
  verificationTokenExpires: Date,
  resetPasswordToken: String, // Add resetPasswordToken field
  resetPasswordExpires: Date // Add resetPasswordExpires field
});

module.exports = mongoose.model('User', userSchema);
