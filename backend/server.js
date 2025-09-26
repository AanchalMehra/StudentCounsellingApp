const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();

// --- Database Connection ---
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('MongoDB Connected...');
    } catch (err) {
        console.error("MongoDB Connection Error:", err.message);
        // Exit process with failure
        process.exit(1);
    }
};

// Connect to the database when the server starts
connectDB();

// --- Middleware ---
app.use(cors());
app.use(express.json({ extended: false }));

// --- Define Routes ---
// This prefixes all routes in routes.js with /api
app.use('/api', require('./routes'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`Server started on port ${PORT}`));

