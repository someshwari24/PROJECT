require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// MongoDB Connection
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { collection: 'users' });

const User = mongoose.model('User', userSchema);

// Address Schema
const addressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  name: { type: String, required: true },
  address: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  pincode: { type: String, required: true },
  shoppingDate: { type: Date, required: true },
  shoppingTime: { type: String, required: true },
  item: { type: String, required: true },
  mobile: { type: String, required: true },
  language: { type: String, required: true }
}, { collection: 'addresses' });

const Address = mongoose.model('Address', addressSchema);

// Assistant Schema
const assistantSchema = new mongoose.Schema({
  name: { type: String, required: true },
  phonenumber: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true }
}, { collection: 'assistants' });

const Assistant = mongoose.model('Assistant', assistantSchema);

// Delivery Confirmation Schema
const confirmationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  status: { type: String, enum: ['received', 'not_received'], required: true },
  confirmedAt: { type: Date, default: Date.now }
}, { collection: 'confirmations' });

const Confirmation = mongoose.model('Confirmation', confirmationSchema);

// Middleware for Authentication
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Signup Route
app.post('/signup', async (req, res) => {
  const { name, username, email, password } = req.body;

  if (!name || !username || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already in use' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).json({ message: 'Email and password are required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ 
      message: 'Login successful',
      token,
      username: user.username,
      name: user.name
    });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Get User Address Route
app.get('/get-user-address', authMiddleware, async (req, res) => {
  try {
    const address = await Address.findOne({ userId: req.user.userId }).sort({ _id: -1 });
    if (!address) return res.status(404).json({ message: 'No address found' });

    res.json({
      address: address.address,
      city: address.city,
      state: address.state,
      pincode: address.pincode,
      mobile: address.mobile
    });
  } catch (error) {
    console.error("❌ Error fetching address:", error);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET /me
app.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    User.findById(decoded.userId)
      .select("name username email")
      .then(user => {
        if (!user) return res.status(404).json({ message: "User not found" });
        res.json({ name: user.name, username: user.username });
      });
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

// Address Submission & Assistant Retrieval
app.post('/submit-details', authMiddleware, async (req, res) => {
  const { name, address, city, state, pincode, mobile, item, language, date, time } = req.body;

  if (!name || !address || !city || !state || !pincode || !mobile || !item || !language || !date || !time) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  try {
    const newAddress = new Address({
      userId: req.user.userId,
      name,
      address,
      city,
      state,
      pincode,
      shoppingDate: new Date(date),
      shoppingTime: time,
      item,
      mobile,
      language
    });
    await newAddress.save();

    const assistant = await getAssistantDetails(city, state);
    const assistantPhone = assistant.phonenumber;

    if (!assistantPhone || assistantPhone === '0000000000') {
      return res.status(404).json({ message: 'No assistant available for your location' });
    }

    const message = `Hello%20I%20need%20help%20shopping%20for%20${encodeURIComponent(item)}.%20My%20name%20is%20${encodeURIComponent(name)}.%20I%20am%20shopping%20on%20${encodeURIComponent(date)}%20at%20${encodeURIComponent(time)}.`;
    const whatsappLink = `https://wa.me/${assistantPhone}?text=${message}`;

    res.json({
      whatsappLink,
      assistantName: assistant.name,
      assistantPhone
    });

  } catch (error) {
    console.error("❌ Error submitting address:", error);
    res.status(500).json({ message: 'Error submitting address. Please try again.' });
  }
});

// Delivery Confirmation
app.post('/confirm-delivery', authMiddleware, async (req, res) => {
  const { confirmed } = req.body;

  let status;
  if (confirmed === true) status = 'received';
  else if (confirmed === false) status = 'not_received';
  else return res.status(400).json({ message: 'Invalid status' });

  try {
    const confirmation = new Confirmation({
      userId: req.user.userId,
      status
    });

    await confirmation.save();

    res.status(200).json({ message: `Delivery ${status.replace('_', ' ')} successfully` });
  } catch (error) {
    console.error("❌ Error saving confirmation:", error);
    res.status(500).json({ message: 'Server error while saving confirmation' });
  }
});

// Helper: Get Assistant Details
async function getAssistantDetails(city, state) {
  try {
    if (!city || !state) {
      return { name: 'Invalid Input', phonenumber: '0000000000' };
    }

    const trimmedCity = city.trim();
    const trimmedState = state.trim();

    const assistant = await Assistant.findOne({
      city: { $regex: new RegExp(`^${trimmedCity}$`, 'i') },
      state: { $regex: new RegExp(`^${trimmedState}$`, 'i') }
    });

    if (!assistant) {
      return { name: 'No Assistant Available', phonenumber: '0000000000' };
    }

    return assistant;
  } catch (error) {
    console.error("❌ Error fetching assistant:", error);
    return { name: 'Error', phonenumber: '0000000000' };
  }
}

// Root route to handle base URL
app.get("/", (req, res) => {
  res.send(`
    <h1>🚀 Welcome to the API</h1>
    <p>The server is running and MongoDB is connected.</p>
    <p>Here are some available routes:</p>
    <ul>
      <li>POST /signup</li>
      <li>POST /login</li>
      <li>GET /me</li>
      <li>GET /get-user-address</li>
      <li>POST /submit-details</li>
      <li>POST /confirm-delivery</li>
    </ul>
  `);
});

// Start Server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
