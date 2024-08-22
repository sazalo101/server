require('dotenv').config();
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
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

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
let clients = [];
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
  const { 
    name, gender, age, address, email, workEmail, phoneNumber1, phoneNumber2, 
    contractDuration, skills, specialisation, password, salary 
  } = req.body;
  const photoUrl = req.file ? `/uploads/${req.file.filename}` : null;
  
  if (password.length < 8) {
    return res.status(400).send('Password must be at least 8 characters long');
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const employee = { 
    name, gender, age, address, email, workEmail, phoneNumber1, phoneNumber2, 
    contractDuration, skills, specialisation, password: hashedPassword, 
    photoUrl, salary, workHours: {}
  };
  
  employees.push(employee);
  users.push({ email, password: hashedPassword, role: 'employee' });
  
  res.status(201).send('Employee profile created');
});

// Create client profile (admin only)
app.post('/client', authenticateToken, upload.single('photo'), (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  const { name, age, address, socialSecurityNumber, servicesNeeded } = req.body;
  const photoUrl = req.file ? `/uploads/${req.file.filename}` : null;
  
  const client = { name, age, address, socialSecurityNumber, servicesNeeded, photoUrl };
  clients.push(client);
  
  res.status(201).send('Client profile created');
});

// Send schedule (admin only)
app.post('/schedule', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  const { employeeEmail, scheduleDetails, clientId } = req.body;
  
  const employee = employees.find(e => e.email === employeeEmail);
  const client = clients.find(c => c.socialSecurityNumber === clientId);

  if (!employee || !client) {
    return res.status(404).send('Employee or client not found');
  }
  
  // Here you would implement the scheduling logic based on client preferences
  // For simplicity, we're just adding the schedule without checks

  schedules.push({ employeeEmail, scheduleDetails, clientId });
  res.status(201).send('Schedule sent');
});

// Get schedules for an employee
app.get('/schedule', authenticateToken, (req, res) => {
  if (req.user.role !== 'employee') {
    return res.sendStatus(403);
  }
  
  const employeeSchedules = schedules.filter(s => s.employeeEmail === req.user.email);
  res.json(employeeSchedules);
});

// Get all employees (admin only)
app.get('/employees', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  res.json(employees.map(e => ({ ...e, password: undefined })));
});

// Get all clients (admin only)
app.get('/clients', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.sendStatus(403);
  }
  res.json(clients);
});

// Update work hours (employee or admin)
app.post('/workhours', authenticateToken, (req, res) => {
  const { employeeEmail, date, hours } = req.body;
  
  if (req.user.role !== 'admin' && req.user.email !== employeeEmail) {
    return res.sendStatus(403);
  }

  const employee = employees.find(e => e.email === employeeEmail);
  if (!employee) {
    return res.status(404).send('Employee not found');
  }

  if (!employee.workHours) {
    employee.workHours = {};
  }
  employee.workHours[date] = hours;

  res.status(200).send('Work hours updated');
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});