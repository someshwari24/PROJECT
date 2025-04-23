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

// Complaint Schema
const complaintSchema = new mongoose.Schema({
  assistantNumber: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, // optional
  submittedAt: { type: Date, default: Date.now }
}, { collection: 'complaints' });

const Complaint = mongoose.model('Complaint', complaintSchema);

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
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: 'Address', required: true },
  status: { type: String, enum: ['received', 'not_received', 'problem_with_assistant'], required: true },
  confirmedAt: { type: Date, default: Date.now }
}, { collection: 'confirmations' });

const Confirmation = mongoose.model('Confirmation', confirmationSchema);
const orderUpdateSchema = new mongoose.Schema({
  assistantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Assistant', required: true },
  orderId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Address',   required: true },
  status:      { type: String, enum: ['packed','shipped','in_transit','delivered','returned'], required: true },
  updatedAt:   { type: Date, default: Date.now }
}, { collection: 'orderUpdates' });
const OrderUpdate = mongoose.model('OrderUpdate', orderUpdateSchema);


const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    req.user.userId = user.userId || user.id; // Handle both user and assistant
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
    if (!user) return res.status(401).json({ message: 'Invalid login credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: 'Invalid login credentials' });

    // Include name in the JWT token
    const token = jwt.sign({ userId: user._id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });

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
app.post('/assistant_update', authMiddleware, async (req, res) => {
  const { orderId, status } = req.body;
  const allowed = ['packed','shipped','Out for Delivery','delivered','returned','Cancelled'];
  if (!orderId || !status || !allowed.includes(status))
    return res.status(400).json({ message: 'Invalid status or missing orderId' });

  try {
    const order = await Address.findById(orderId);
    if (!order) return res.status(404).json({ message: 'Order not found' });

    await new OrderUpdate({
      assistantId: req.user.userId,
      orderId,
      status
    }).save();


    res.json({ message: `Order status updated to ${status.replace('_',' ')}` });
  } catch {
    res.status(500).json({ message: 'Error updating order status' });
  }
});
// Get Order Tracking Status
app.get('/track-order/:orderId', authMiddleware, async (req, res) => {
  const { orderId } = req.params;

  try {
    // Find the order updates for the provided orderId
    const updates = await OrderUpdate.find({ orderId })
      .populate('assistantId', 'name phonenumber')  // Populate assistant details
      .sort({ updatedAt: -1 });  // Sort by most recent update

    if (!updates.length) {
      return res.status(404).json({ message: 'No tracking information found for this order.' });
    }

    // Extract the latest order status
    const latestUpdate = updates[0];

    res.json({
      orderId,
      status: latestUpdate.status,
      assistant: latestUpdate.assistantId ? latestUpdate.assistantId.name : 'Unknown Assistant',
      updatedAt: latestUpdate.updatedAt,
    });
  } catch (err) {
    console.error('Error fetching order tracking status:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});


// Get All Addresses with Delivery Status
app.get("/get-user-address", authMiddleware, async (req, res) => {
  try {
    const userId = req.user.userId;

    // Get all addresses for the user
    const addresses = await Address.find({ userId });

    // Get all confirmations for the user
    const confirmations = await Confirmation.find({ userId });

    // Map through addresses and attach status (if any)
    const userOrdersWithStatus = addresses.map(order => {
      const matchedConfirmation = confirmations.find(c =>
        c.orderId?.toString() === order._id?.toString()
      );

      return {
        ...order.toObject(),
        status: matchedConfirmation ? matchedConfirmation.status : 'pending'
      };
    });

    res.json(userOrdersWithStatus);
  } catch (err) {
    console.error("❌ Error fetching addresses:", err);
    res.status(500).json({ message: "Failed to fetch addresses." });
  }
});

// Get User Details
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select("name username email");

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ name: user.name, username: user.username });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

// Submit Address & Get Assistant
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

    const message = `Hello I need help shopping for ${encodeURIComponent(item)}. My name is ${encodeURIComponent(name)}. I am shopping on ${encodeURIComponent(date)} at ${encodeURIComponent(time)}.`;
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

// Confirm Delivery Status
app.post('/confirm-delivery', authMiddleware, async (req, res) => {
  const { orderId, status } = req.body;

  if (!orderId || !status || !['received', 'not_received', 'problem_with_assistant'].includes(status)) {
    return res.status(400).json({ message: 'Invalid status or missing orderId' });
  }

  try {
    const confirmation = await Confirmation.findOneAndUpdate(
      { userId: req.user.userId, orderId: orderId },
      { status },
      { new: true, upsert: true }
    );

    res.status(200).json({ message: `Delivery status updated to ${status.replace('_', ' ')}` });
  } catch (error) {
    console.error("❌ Error saving confirmation:", error);
    res.status(500).json({ message: 'Server error while saving confirmation' });
  }
});

// Get Assistant Details
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

    return assistant || { name: 'No Assistant Available', phonenumber: '0000000000' };
  } catch (error) {
    console.error("❌ Error fetching assistant:", error);
    return { name: 'Error', phonenumber: '0000000000' };
  }
}

// Submit Assistant Complaint
app.post('/submit-assistant-info', authMiddleware, async (req, res) => {
  let { assistantNumber } = req.body;

  if (!assistantNumber) {
    return res.status(400).json({ message: "Assistant number is required." });
  }

  assistantNumber = assistantNumber.replace(/[^\d]/g, ''); // normalize input

  try {
    const existingComplaint = await Complaint.findOne({ assistantNumber, userId: req.user.userId });

    if (existingComplaint) {
      return res.status(400).json({ message: "You already reported this assistant." });
    }

    const newComplaint = new Complaint({
      assistantNumber,
      userId: req.user.userId
    });

    await newComplaint.save();

    res.status(200).json({ message: "We will contact you shortly." });
  } catch (error) {
    console.error("❌ Error submitting complaint:", error);
    res.status(500).json({ message: "An error occurred while submitting the complaint." });
  }
});
// POST request to login assistant by phone number
app.post('/assistant-login', async (req, res) => {
  const { phone } = req.body;

  if (!phone) {
    return res.status(400).json({ message: 'Phone number is required' });
  }

  // Optionally, add phone number validation here (example, to check length or format)
  if (phone.length !== 10 || !/^\d+$/.test(phone)) {
    return res.status(400).json({ message: 'Invalid phone number format' });
  }

  try {
    // Find the assistant by phone number
    const assistant = await Assistant.findOne({ phonenumber: phone });

    if (!assistant) {
      return res.status(404).json({ message: 'Assistant not found' });
    }

    // If assistant is found, generate a token (you can add more logic for JWT)
    const token = jwt.sign({ id: assistant._id, phone: assistant.phonenumber }, process.env.JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      message: 'Login successful',
      token,
      assistantName: assistant.name,  // You can include other details here
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});


// Start Server
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
