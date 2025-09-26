const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const { User, StudentProfile } = require('./models');
const auth = require('./authMiddleware');

// --- User Authentication Routes ---

// POST /api/register
router.post('/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }
        user = new User({ name, email, password, role });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error("Registration Error:", err);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

// POST /api/login
router.post('/login', async (req, res) => {
    const { email, password, role } = req.body;
    try {
        const user = await User.findOne({ email, role });
        if (!user) {
            return res.status(400).json({ message: 'Invalid credentials or role' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }
        const payload = { user: { id: user.id, name: user.name, role: user.role } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '5h' }, (err, token) => {
            if (err) throw err;
            res.json({ token, user: payload.user });
        });
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: 'Server error during login.' });
    }
});


// --- Student Routes ---

// GET /api/student/profile - Get student's own profile
router.get('/student/profile', auth, async (req, res) => {
    try {
        if (!req.user || !req.user.id) {
            return res.status(401).json({ message: 'Authentication error: Invalid user data in token.' });
        }
        const profile = await StudentProfile.findOne({ user: req.user.id });
        if (!profile) {
            return res.status(404).json({ message: 'Profile not found' });
        }
        res.json(profile);
    } catch (err) {
        console.error("Get Profile Error:", err);
        res.status(500).json({ message: 'Server Error fetching profile.' });
    }
});

// POST /api/student/profile - Create or update student profile
router.post('/student/profile', auth, async (req, res) => {
    const { fullName, dob, address, phone, highSchool, intermediate, branchPreferences } = req.body;
    
    try {
        if (!req.user || !req.user.id) {
            return res.status(401).json({ message: 'Authentication error: Invalid user data in token.' });
        }

        const existingProfile = await StudentProfile.findOne({ user: req.user.id });

        if (existingProfile && existingProfile.status !== 'Pending') {
            return res.status(400).json({ message: 'Application cannot be modified after it has been submitted.' });
        }
        
        const profileFields = {
            user: req.user.id,
            fullName, 
            dob: dob || null,
            address, phone, highSchool, intermediate, branchPreferences,
            status: 'Submitted'
        };

        const profile = await StudentProfile.findOneAndUpdate(
            { user: req.user.id },
            { $set: profileFields },
            // new: returns the modified document, upsert: creates if it doesn't exist, runValidators: enforces schema rules
            { new: true, upsert: true, runValidators: true, context: 'query' }
        );

        if (!profile) {
            throw new Error('Failed to save student profile to the database.');
        }

        res.json(profile);
    } catch (err) {
        // Mongoose validation errors will now be caught here because of runValidators: true
        if (err.name === 'ValidationError') {
            const messages = Object.values(err.errors).map(val => val.message);
            return res.status(400).json({ message: `Validation Error: ${messages.join(', ')}` });
        }
        if (err.name === 'CastError') {
             return res.status(400).json({ message: `Invalid data format for field: '${err.path}'. Please check your input.` });
        }
        console.error("Submit Profile Error:", err);
        res.status(500).json({ message: 'Server Error submitting application. Please check server logs.' });
    }
});


// PUT /api/student/status - Update student status
router.put('/student/status', auth, async (req, res) => {
    try {
        const { status } = req.body;
        let updateFields = { status: status };

        if (status === 'PaymentSubmitted') {
            // In a real app, you'd handle file upload and save its URL. Here we simulate with a dummy PDF link.
            updateFields.paymentReceipt = 'https://www.w3.org/WAI/ER/tests/xhtml/testfiles/resources/pdf/dummy.pdf';
        }
        
        if (status === 'Declined') {
            updateFields.allottedBranch = ''; // Clear allotted branch on decline
        }

        const profile = await StudentProfile.findOneAndUpdate(
            { user: req.user.id },
            { $set: updateFields },
            { new: true }
        );
        res.json(profile);
    } catch (err) {
        console.error("Update Status Error:", err);
        res.status(500).json({ message: 'Server Error updating status.' });
    }
});


// --- Admin Routes ---

// GET /api/admin/students - Get all student profiles ranked by marks
router.get('/admin/students', auth, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }
    try {
        let profiles = await StudentProfile.find({ status: { $ne: 'Pending' } }).populate('user', 'email');
        
        // Filter out any profiles with a null user (data integrity check)
        profiles = profiles.filter(profile => profile.user !== null);

        // Use .toObject({ virtuals: true }) to ensure virtual properties like totalMarks are included.
        const studentData = profiles.map(p => p.toObject({ virtuals: true }));

        // Sort by the now-included totalMarks property
        studentData.sort((a, b) => b.totalMarks - a.totalMarks);

        res.json(studentData);
    } catch (err) {
        console.error("Get Students Error:", err);
        res.status(500).json({ message: 'Server Error fetching student data.' });
    }
});

// POST /api/admin/allot - Allot a branch to a student
router.post('/admin/allot', auth, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
    
    const { studentId, branch } = req.body;
    try {
        await StudentProfile.findOneAndUpdate(
            { user: studentId },
            { $set: { allottedBranch: branch, status: 'Allotted' } }
        );
        res.json({ message: 'Branch allotted successfully' });
    } catch (err) {
        console.error("Allotment Error:", err);
        res.status(500).json({ message: 'Server Error during allotment.' });
    }
});

// POST /api/admin/verify - Verify a student's payment
router.post('/admin/verify', auth, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });

    const { studentId } = req.body;
    try {
        await StudentProfile.findOneAndUpdate(
            { user: studentId },
            { $set: { status: 'Confirmed' } }
        );
        res.json({ message: 'Payment verified successfully' });
    } catch (err) {
        console.error("Verification Error:", err);
        res.status(500).json({ message: 'Server Error during verification.' });
    }
});

// --- Password Reset Routes ---

// POST /api/forgot-password
router.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User with that email does not exist.' });
        }

        const token = crypto.randomBytes(20).toString('hex');
        user.resetPasswordToken = token;
        user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        const resetURL = `http://localhost:3000?resetToken=${token}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Link',
            text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n` +
                  `Please click on the following link, or paste this into your browser to complete the process:\n\n` +
                  `${resetURL}\n\n` +
                  `If you did not request this, please ignore this email and your password will remain unchanged.\n`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'An e-mail has been sent to ' + user.email + ' with further instructions.' });

    } catch (error) {
        console.error('Error in /forgot-password:', error);
        res.status(500).json({ message: 'Error on the server.' });
    }
});


// PUT /api/reset-password/:token
router.put('/reset-password/:token', async (req, res) => {
    try {
        const user = await User.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpires: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({ message: 'Password reset token is invalid or has expired.' });
        }

        user.password = req.body.password; // The pre-save hook will hash it
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();
        
        res.status(200).json({ message: 'Password has been updated.' });

    } catch (error) {
        console.error('Error in /reset-password:', error);
        res.status(500).json({ message: 'Server error during password reset.' });
    }
});


module.exports = router;

