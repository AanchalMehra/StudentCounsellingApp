const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['student', 'admin'], default: 'student' },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});

// Hash password before saving
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

// This is the schema for each individual mark field.
const MarksSchema = {
    type: Number,
    required: [true, 'Marks for all subjects are required.'],
    min: [0, 'Marks cannot be negative.'],
    max: [100, 'Marks cannot exceed 100.'],
    validate: {
        validator: Number.isInteger,
        message: '{VALUE} is not an integer value for marks.'
    }
};

const StudentProfileSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    fullName: { type: String, required: true },
    dob: { type: Date },
    address: { type: String },
    phone: { type: String },
    highSchool: {
        math: MarksSchema,
        science: MarksSchema,
        english: MarksSchema,
        hindi: MarksSchema,
    },
    intermediate: {
        physics: MarksSchema,
        chemistry: MarksSchema,
        math: MarksSchema,
    },
    branchPreferences: [{ type: String }],
    status: {
        type: String,
        enum: ['Pending', 'Submitted', 'Allotted', 'PaymentPending', 'PaymentSubmitted', 'Confirmed', 'Declined'],
        default: 'Pending',
    },
    allottedBranch: { type: String },
    paymentReceipt: { type: String },
}, {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
});

// Virtual property to calculate total marks
StudentProfileSchema.virtual('totalMarks').get(function() {
    const inter = this.intermediate;
    if (inter && inter.physics != null && inter.chemistry != null && inter.math != null) {
        return inter.physics + inter.chemistry + inter.math;
    }
    return 0;
});


const User = mongoose.model('User', UserSchema);
const StudentProfile = mongoose.model('StudentProfile', StudentProfileSchema);

module.exports = { User, StudentProfile };



