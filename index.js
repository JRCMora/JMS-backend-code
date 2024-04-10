const express = require("express");

const app = express();

require("dotenv").config();

app.use(express.json());

const connectDB = require("./connectMongo");

connectDB();

const bcrypt = require('bcrypt');
const User = require('./models/user');
const Journal = require('./models/journal');
const mongoose = require('mongoose');
const multer = require('multer');
const Notification = require('./models/notification');
const crypto = require('crypto');
const path = require('path');
const transporter = require('./models/email');
const Rubric = require('./models/rubric');
const cors = require("cors");
const { put } = require('@vercel/blob');
const containerName = 'jms-uploads';


// Multer configuration
const upload = multer({
  storage: multer.memoryStorage(), // Store files in memory for now
  limits: { fileSize: 5 * 1024 * 1024 }, // Limit file size to 5MB (adjust as needed)
  fileFilter: function (req, file, cb) {
    // Check if the uploaded file is a PDF
    if (file.mimetype !== 'application/pdf') {
      return cb(new Error('Only PDF files are allowed'));
    }
    cb(null, true);
  }
});

app.use(cors());

app.use('/uploads', express.static('uploads'));

app.use((req, res, next) => { 
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers",  
    "Origin, X-Requested-With, Content-Type, Accept");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  next(); 
});

app.use(express.urlencoded({ extended: true }));

// Retrieve all users or users by role
app.get('/users', async (req, res) => {
  try {
    const role = req.query.role;
    let users;
    if (role) {
      users = await User.find({ role }); // Filter users by role if role is provided in the query params
    } else {
      users = await User.find(); // Retrieve all users if no role is provided
    }
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update user information
app.put('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const userData = req.body; // Get user data from request body

    // Check if the user ID is valid
    if (!mongoose.Types.ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    // Find the user by ID in the database
    let user = await User.findById(userId);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update user data
    user.role = userData.role;

    // Save the updated user data
    user = await user.save();

    // Send the updated user data as the response
    res.json(user);
  } catch (error) {
    // Handle any errors that occur during the process
    console.error('Error updating user:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
});


// Delete a user by ID
app.delete('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    // Delete the user by ID
    await User.findByIdAndDelete(userId);
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to delete a journal by its ID
app.delete('/journals/:journalId', async (req, res) => {
  try {
    const { journalId } = req.params;

    // Check if journalId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(journalId)) {
      return res.status(400).json({ error: 'Invalid journalId' });
    }

    // Find the journal by ID and delete it
    await Journal.findByIdAndDelete(journalId);

    res.json({ message: 'Journal deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add route to create a rubric
app.post('/rubrics', async (req, res) => {
  try {
    const rubric = await Rubric.create(req.body);
    res.status(201).json(rubric);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add route to get all rubrics
app.get('/rubrics', async (req, res) => {
  try {
    const rubrics = await Rubric.find();
    res.json(rubrics);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add route to get a single rubric by its ID
app.get('/rubrics/:rubricId', async (req, res) => {
  try {
    const { rubricId } = req.params;
    const rubric = await Rubric.findById(rubricId);
    if (!rubric) {
      return res.status(404).json({ error: 'Rubric not found' });
    }
    res.json(rubric);
  } catch (error) {
    console.error('Error fetching rubric:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});




// Add a route to change a user's password
app.post('/users/:userId/change-password', async (req, res) => {
  try {
    const { userId } = req.params;
    const { currentPassword, newPassword } = req.body;

    // Find the user by ID in the database
    const user = await User.findById(userId);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if the provided current password matches the user's password
    const passwordMatch = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    user.password = hashedPassword;
    await user.save();

    // Send a success response
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    // Handle any errors that occur during the process
    console.error('Error changing password:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// Add a route to get a user by their userId
app.get('/users/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the user by ID in the database
    const user = await User.findById(userId);

    // Check if the user exists
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If the user is found, send their details as the response
    res.json(user);
  } catch (error) {
    // Handle any errors that occur during the process
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});




// Modify the register route to include email validation
app.post('/register', async (req, res) => {
  try {
    const { email, firstName, lastName, password, role } = req.body;

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a unique verification token using Crypto
    const verificationToken = crypto.randomBytes(20).toString('hex');

    const tokenExpiration = new Date();
    tokenExpiration.setMinutes(tokenExpiration.getMinutes() + 10);

    const user = new User({ email, firstName, lastName, password: hashedPassword, role, verificationToken, verificationTokenExpires: tokenExpiration });
    await user.save();

    // Send verification email
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Email Verification',
      html: `<p>Hello ${firstName},</p>
         <p>Please click the following link to verify your email address:</p>
         <p><a href="https://jms-backend-testing.vercel.app/verify/${verificationToken}?email=${email}" target="_blank">Verify Email</a></p>
         <p>If the button above doesn't work, you can also paste this link into your browser:</p>
         <p>https://jms-backend-testing.vercel.app/verify/${verificationToken}?email=${email}</p>
         <p>The link is valid for 10 minutes</p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending verification email:', error);
        return res.status(500).json({ error: 'Error sending verification email' });
      }
      console.log('Verification email sent:', info.response);
      res.json({ message: 'User registered successfully. Please check your email for verification.' });
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Route to Verify Token
app.get('/verify/:token', async (req, res) => {
  try {
    const { token } = req.params;

    // Find user by verification token
    const user = await User.findOne({ verificationToken: token });

    // Check if the token has expired or user not found
    if (!user || user.verificationTokenExpires < new Date()) {
      return res.redirect(`https://jmshau.site/verify-email-result?success=false&email=${user.email}`);
    }

    // Update user status to verified
    user.emailVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    // Redirect with success=true if verification succeeds
    res.redirect(`https://jmshau.site/verify-email-result?success=true&email=${user.email}`);
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
    
  }
});

// Add a route to resend verification email
app.post('/resend-verification-email', async (req, res) => {
  try {
    const { email } = req.body;

    // Fetch user by email and resend verification email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate a new verification token
    const verificationToken = crypto.randomBytes(20).toString('hex');
    user.verificationToken = verificationToken;
    user.verificationTokenExpires = Date.now() + 600000; // 10 minutes
    await user.save();

    // Send verification email
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: user.email,
      subject: 'Email Verification',
      html: `<p>Hello ${user.firstName},</p>
         <p>Please click the following link to verify your email address:</p>
         <p><a href="https://jms-backend-testing.vercel.app/verify/${verificationToken}?email=${email}" target="_blank">Verify Email</a></p>
         <p>If the button above doesn't work, you can also paste this link into your browser:</p>
         <p>https://jms-backend-testing.vercel.app/verify/${verificationToken}?email=${email}</p>
         <p>The link is valid for 10 minutes</p>`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error resending verification email:', error);
        return res.status(500).json({ error: 'Error resending verification email' });
      }
      console.log('Resent verification email sent:', info.response);
      res.json({ message: 'Verification email resent successfully.' });
    });
  } catch (error) {
    console.error('Resend verification email error:', error);
    res.status(500).json({ error: 'Resend verification email failed' });
  }
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = Date.now() + 600000; 
    await user.save();

    // Send reset password email
    const mailOptions = {
      from: process.env.GMAIL_USER,
      to: email,
      subject: 'Reset Password',
      html: `<p>You are receiving this because you (or someone else) have requested the reset of the password for your account.</p>
            <p><a href="https://jmshau.site/reset-password/${resetToken}" target="_blank">Reset Password</a></p>
             <p>Please click on the following link, or paste this into your browser to complete the process:</p>
             <p>https://jmshau.site/reset-password/${resetToken}</p>
             <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>`
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Error sending reset password email:', error);
        return res.status(500).json({ error: 'Error sending reset password email' });
      }
      console.log('Reset password email sent:', info.response);
      res.json({ message: 'Reset password instructions sent to your email' });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Forgot password failed' });
  }
});

// Add the following endpoint to handle password reset
app.post('/reset-password/:resetToken', async (req, res) => {
  try {
    const { resetToken } = req.params;
    const { newPassword } = req.body;

    // Find user by reset token
    const user = await User.findOne({ resetPasswordToken: resetToken });
    if (!user) {
      return res.status(404).json({ error: 'Invalid or expired reset token' });
    }

    // Check if the reset token has expired
    if (user.resetPasswordExpires < new Date()) {
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user's password and clear reset token
    user.password = hashedPassword;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Password reset failed' });
  }
});



// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    // Check if the user exists
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check if the user's email is verified
    if (!user.emailVerified) {
      return res.status(401).json({ message: 'Email not verified. Please check your email for verification.' });
    }

    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (passwordMatch) {
      res.json({ 
        message: 'Login successful', 
        role: user.role, 
        status: true,
        userId: user._id
      });
    } else {
      res.status(401).json({ message: 'Invalid credentials', status: false });
    }
  } catch (error) {
    res.status(500).json({ error: error.message,status:false });
  }
});


// Retrieve all journals
app.get('/journals', async (req, res) => {
  try {
    const journals = await Journal.find();
    res.json(journals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Handle both new journal submissions and revisions
app.post('/journals', upload.single('journalFile'), async (req, res) => {
  try {
    const { journalTitle, authors, abstract, userId, journalId } = req.body;

    // Check if file exists in request
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const file = req.file; // Access the uploaded file details

    // Upload the file to Vercel Blob using read-write token
    const blobName = `${Date.now()}-${file.originalname}`;
    console.log(blobName); // Create a unique blob name
    const uploadResponse = await put(blobName, file.buffer, {
      token: process.env.BLOB_READ_WRITE_TOKEN, // Use read-write token for authentication
      contentType: file.mimetype, // Optional: Specify content type
      access: 'public', // Optional: Set access permissions
    });
    console.log(uploadResponse);

    if (!uploadResponse || uploadResponse.error) {
      // Handle the error appropriately
      return res.status(500).json({ error: 'Failed to upload file to Vercel Blob storage' });
    }

    // If journalId is provided, it means this is a revised journal
    if (journalId) {
      // Update the existing journal entry in the database with the revised details
      await Journal.findOneAndUpdate(
        { _id: journalId },
        {
          $set: {
            journalTitle,
            authors,
            abstract,
            filePath: `vercel-blob:${containerName}/${blobName}`,
            downloadUrl: uploadResponse.downloadUrl,
            submittedBy: userId,
            reviewComments: [], // Clear reviewComments array
            reviewerChoices: [] // Clear reviewerChoices array
          }
        }
      );

      // Send notification to assigned reviewers
      const journal = await Journal.findById(journalId).populate('reviewers');
      const reviewers = journal.reviewers;
      const notificationPromises = reviewers.map(reviewer => {
        return Notification.create({
          recipient: reviewer._id, // Assign notification to reviewer
          message: `A revised version of the journal '${journalTitle}' is assigned to you for review.`,
          status: 'unread' // Set the status as unread
        });
      });
      await Promise.all(notificationPromises);

      // Send notification to admins
      const admins = await User.find({ role: 'admin' }); // Assuming you have a User model with a 'role' field
      const adminNotificationPromises = admins.map(admin => {
        return Notification.create({
          recipient: admin._id, // Assuming admin has a unique ID
          message: `A revised version of the journal '${journalTitle}' has been submitted.`,
          status: 'unread' // Set the status as unread
        });
      });
      await Promise.all(adminNotificationPromises);



      res.json({ message: 'Revised journal submitted successfully', downloadUrl: uploadResponse.downloadUrl });
    } else {
      // Create a new journal entry in the database
      const journal = new Journal({
        journalTitle,
        authors,
        abstract,
        filePath: `vercel-blob:${containerName}/${blobName}`,
        downloadUrl: uploadResponse.downloadUrl,
        submittedBy: userId,
      });
      await journal.save();

      // Send notification to admins
      const admins = await User.find({ role: 'admin' }); // Assuming you have a User model with a 'role' field
      const notificationPromises = admins.map(admin => {
        return Notification.create({
          recipient: admin._id, // Assuming admin has a unique ID
          message: 'A new journal has been submitted.', // Customize your message
          status: 'unread' // Set the status as unread
        });
      });
      await Promise.all(notificationPromises);

      res.json({ message: 'Journal submitted successfully', downloadUrl: uploadResponse.downloadUrl });
    }
  } catch (error) {
    console.error(error); // Log the error for debugging
    res.status(500).json({ error: 'An error occurred during journal submission' });
  }
});

// Add a route to fetch journals submitted by a specific user
app.get('/user/:userId/journals', async (req, res) => {
  try {
    const { userId } = req.params;

    // Find journals submitted by the specified user
    const journals = await Journal.find({ submittedBy: userId });

    res.json(journals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to update journal status
app.put('/journals/:journalId/update-status', async (req, res) => {
  try {
    const { journalId } = req.params;
    const { status } = req.body;

    if (!mongoose.Types.ObjectId.isValid(journalId)) {
      return res.status(400).json({ error: 'Invalid journalId' });
    }

    const journal = await Journal.findByIdAndUpdate(journalId, { status }, { new: true });

    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }

    const submittedById = journal.submittedBy ? journal.submittedBy._id : null;
    if (!submittedById) {
      return res.status(400).json({ error: 'Submitted by user ID not found' });
    }
    // Send notification to the user who submitted the journal
    const notification = await Notification.create({
      recipient: submittedBy,
      message: `The status of your journal "${journal.journalTitle}" has been updated to "${status}".`, // Customize your message
      status: 'unread'
    });

    res.json({ message: 'Journal status updated successfully', journal });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Add a route to retrieve a single journal by its ID
app.get('/journals/:journalId', async (req, res) => {
  try {
    const { journalId } = req.params;
    const journal = await Journal.findById(journalId);
    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }
    res.json(journal);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/journals/:journalId', async (req, res) => {
  const journalId = req.params.journalId;
  const updatedData = req.body;

  try {
    // Find the journal by ID and update it with the new data
    const updatedJournal = await Journal.findByIdAndUpdate(journalId, updatedData, { new: true });

    if (!updatedJournal) {
      return res.status(404).json({ message: 'Journal not found' });
    }

    res.json(updatedJournal); // Return the updated journal
  } catch (error) {
    console.error('Error updating journal:', error);
    res.status(500).json({ message: 'Internal server error' }); // Handle server error
  }
});

// Add a route for assigning reviewers to journals
app.post('/journals/:journalId/assign-reviewers', async (req, res) => {
  try {
    const { journalId } = req.params;
    const { reviewerIds, rubricId } = req.body; // Retrieve the array of selected reviewer IDs and rubricId from the request body

    // Check if journalId is a valid ObjectId
    if (!mongoose.Types.ObjectId.isValid(journalId)) {
      return res.status(400).json({ error: 'Invalid journalId' });
    }

    // Find the journal by ID
    const journal = await Journal.findById(journalId);
    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }

    // Find the selected reviewers by their IDs
    const reviewers = await User.find({ _id: { $in: reviewerIds } });
    if (reviewers.length !== reviewerIds.length) {
      // Check if all reviewers were found
      return res.status(404).json({ error: 'One or more reviewers not found' });
    }

    // Update the reviewers array with the IDs of the selected reviewers
    journal.reviewers = reviewerIds;
    journal.rubricId = rubricId; // Assign the rubricId to the journal
    await journal.save();

    // Update the status of the reviewers to 'Assigned'
    await User.updateMany({ _id: { $in: reviewerIds } }, { status: 'Assigned' });

    // Send notifications to the assigned reviewers with journalId
    const notifications = reviewerIds.map(reviewerId => new Notification({
      recipient: reviewerId,
      message: `You have been assigned to review the journal "${journal.journalTitle}"`,
      journalId: journal._id // Include journalId in the notification
    }));
    await Notification.insertMany(notifications);

    res.json({ message: 'Reviewers assigned successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to fetch notifications for a specific user
app.get('/notifications/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    // Find notifications for the user
    const notifications = await Notification.find({ recipient: userId });
    res.json(notifications);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to mark a notification as read
app.put('/notifications/:notificationId/mark-as-read', async (req, res) => {
  try {
    const { notificationId } = req.params;

    // Update the status of the notification to 'read'
    const notification = await Notification.findByIdAndUpdate(notificationId, { status: 'read' }, { new: true });

    res.json({ message: 'Notification marked as read', notification });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint to send notifications to admins when a journal is submitted
app.post('/admin-notifications', async (req, res) => {
  try {
    // Retrieve all admins from the database
    const admins = await User.find({ role: 'admin' }); // Assuming you have a User model with a 'role' field

    // Create notifications for each admin
    const notificationPromises = admins.map(admin => {
      return Notification.create({
        recipient: admin._id, // Assuming admin has a unique ID
        message: 'A new journal has been submitted.', // Customize your message
        status: 'unread' // Set the status as unread
      });
    });

    // Wait for all notifications to be created
    await Promise.all(notificationPromises);

    // Send response
    res.json({ message: 'Admin notifications sent successfully' });
  } catch (error) {
    console.error('Error sending admin notifications:', error);
    res.status(500).json({ error: 'An error occurred while sending admin notifications' });
  }
});


// Modify the route to accept an array of reviewer IDs
app.post('/user/reviewers', async (req, res) => {
  try {
    const { reviewerIds } = req.body;

    // Find all reviewers with the provided IDs
    const reviewers = await User.find({ _id: { $in: reviewerIds } });

    res.json(reviewers);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to fetch assigned journals for each reviewer
app.get('/user/reviewers/:userId/assigned-journals', async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the user by ID
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Fetch the assigned journals for the user
    const assignedJournals = await Journal.find({ reviewers: userId });

    res.json(assignedJournals);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to submit feedback and update journal status
app.post('/journals/:journalId/submit-feedback', async (req, res) => {
  try {
    const { journalId } = req.params;
    const { feedback, choice, userId } = req.body;

    const journal = await Journal.findById(journalId);
    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }

    // Find the index of the reviewer's previous feedback
    const previousFeedbackIndex = journal.reviewComments.findIndex(comment => String(comment.reviewer) === String(userId));
    if (previousFeedbackIndex !== -1) {
      // If the reviewer has provided feedback before, update the existing feedback
      journal.reviewComments[previousFeedbackIndex].comment = feedback;
      // Also update the choice made by the reviewer
      journal.reviewerChoices[previousFeedbackIndex].choice = choice;
    } else {
      // If the reviewer is providing feedback for the first time, add a new entry
      journal.reviewComments.push({ reviewer: userId, comment: feedback });
      journal.reviewerChoices.push({ reviewer: userId, choice });
    }

    const totalReviewers = journal.reviewers.length;
    const feedbackCount = journal.reviewComments.length;
    if (feedbackCount === totalReviewers) {
      if (journal.status !== 'Reviewed') {
        journal.status = 'Reviewed';
        const notification = await Notification.create({
          recipient: journal.submittedBy._id,
          message: `The status of your journal "${journal.journalTitle}" has been updated to "${journal.status}".`,
          status: 'unread'
        });
        const admins = await User.find({ role: 'admin' });
        const notificationPromises = admins.map(admin => {
          return Notification.create({
            recipient: admin._id,
            message: `The "${journal.journalTitle}" has been "${journal.status}".`,
            status: 'unread'
          });
        });
        await Promise.all(notificationPromises);
      }
    }
    await journal.save();

    res.json({ message: 'Feedback submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to submit consolidated feedback for a journal
app.post('/journals/:journalId/submit-consolidated-feedback', async (req, res) => {
  try {
    const { journalId } = req.params;
    const { consolidatedFeedback, adminChoice } = req.body; 

    // Find the journal by ID
    const journal = await Journal.findById(journalId);
    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }


    journal.consolidatedFeedback = consolidatedFeedback;
    journal.status = adminChoice; 
    await journal.save();

    // Send notification to the user who submitted the journal
    const notification = await Notification.create({
      recipient: journal.submittedBy._id,
      message: `The status of your journal "${journal.journalTitle}" has been updated to "${adminChoice}".`, // Customize your message
      status: 'unread'
    });

    res.json({ message: 'Consolidated feedback submitted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Add a route to fetch consolidated feedback for a specific journal
app.get('/journals/:journalId/consolidated-feedback', async (req, res) => {
  try {
    const { journalId } = req.params;

    // Find the journal by ID
    const journal = await Journal.findById(journalId);
    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }

    // Return the consolidated feedback for the journal
    res.json({
      journalTitle: journal.journalTitle,
      consolidatedFeedback: journal.consolidatedFeedback
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Add a route to fetch consolidate feedback for a journal
app.get('/journals/:journalId/consolidate-feedback', async (req, res) => {
  try {
    const { journalId } = req.params;

    // Find the journal by ID
    const journal = await Journal.findById(journalId);
    if (!journal) {
      return res.status(404).json({ error: 'Journal not found' });
    }

    // Retrieve all the feedback provided by reviewers for the journal
    const feedback = await Promise.all(journal.reviewComments.map(async comment => {
      try {
        const reviewer = await User.findById(comment.reviewer);
        return {
          reviewerName: reviewer ? `${reviewer.firstName} ${reviewer.lastName}` : 'Unknown',
          feedback: comment.comment,
          choice: journal.reviewerChoices.find(choice => String(choice.reviewer) === String(comment.reviewer)).choice
        };
      } catch (error) {
        console.error('Error fetching reviewer:', error);
        return {
          reviewerName: 'Unknown',
          feedback: comment.comment,
          choice: journal.reviewerChoices.find(choice => String(choice.reviewer) === String(comment.reviewer)).choice
        };
      }
    }));

    res.json({ feedback });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Add a route to check if the email is already registered
app.post('/check-email', async (req, res) => {
  try {
    const { email } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'Email already exists' });
    }
    res.json({ message: 'Email available' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

const PORT = process.env.PORT;

app.listen(PORT, () => {
  console.log("Server is running on port " + PORT);
});
