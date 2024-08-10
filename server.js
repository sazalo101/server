// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3001;

const JWT_SECRET = 'your-secret-key';

// Set up multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});
const upload = multer({ storage: storage });

// Serve uploaded files
app.use('/uploads', express.static('uploads'));

// In-memory storage
let users = [{
  email: 'admin@admin.com',
  password: bcrypt.hashSync('admin', 10),
  role: 'admin'
}];
let employees = [];
let customers = [];
let schedules = [];

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (token == null) return res.sendStatus(401);
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  
  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET);
    res.json({ token, role: user.role });
  } else {
    res.status(400).send('Invalid credentials');
  }
});

// Create employee profile (admin only)
app.post('/employee', authenticateToken, upload.single('photo'), (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  const { email, password, jobTitle, department, phoneNumber, socialSecurityNumber } = req.body;
  const photoUrl = req.file ? `/uploads/${req.file.filename}` : null;
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  const employee = { email, password: hashedPassword, jobTitle, department, phoneNumber, socialSecurityNumber, photoUrl };
  
  employees.push(employee);
  users.push({ email, password: hashedPassword, role: 'employee' });
  
  res.status(201).send('Employee profile created');
});

// Create customer profile (admin only)
app.post('/customer', authenticateToken, upload.single('photo'), (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  const { email, phoneNumber } = req.body;
  const photoUrl = req.file ? `/uploads/${req.file.filename}` : null;
  
  const customer = { email, phoneNumber, photoUrl };
  customers.push(customer);
  
  res.status(201).send('Customer profile created');
});

// Send schedule (admin only)
app.post('/schedule', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  const { department, schedule } = req.body;
  schedules.push({ department, schedule });
  res.status(201).send('Schedule sent');
});

// Get schedules for an employee
app.get('/schedule', authenticateToken, (req, res) => {
  if (req.user.role !== 'employee') {
    return res.sendStatus(403);
  }
  const employee = employees.find(e => e.email === req.user.email);
  const employeeSchedules = schedules.filter(s => s.department === employee.department);
  res.json(employeeSchedules);
});

// Get all employees (admin only)
app.get('/employees', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  res.json(employees.map(e => ({ ...e, password: undefined })));
});

// Get all customers (admin only)
app.get('/customers', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  res.json(customers);
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});