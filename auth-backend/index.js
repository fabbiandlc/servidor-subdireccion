const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000; // Usa el puerto de Render o 3000 localmente

app.use(bodyParser.json());

const USERS_FILE = "./users.json";
const JWT_SECRET = "mi_secreto_jwt"; // Consider moving to environment variable

// Helper function to read users from file
function getUsers() {
  try {
    const data = fs.readFileSync(USERS_FILE, "utf8");
    return JSON.parse(data);
  } catch (error) {
    console.error("Error leyendo users.json:", error);
    return []; // Return empty array if file doesn’t exist or is invalid
  }
}

// Helper function to save users to file
function saveUsers(users) {
  try {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), "utf8");
  } catch (error) {
    console.error("Error guardando users.json:", error);
  }
}

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Acceso denegado. Token no proporcionado." });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido." });
    }
    req.user = user;
    next();
  });
}

// Register endpoint
app.post("/register", async (req, res) => {
  const { username, password, role = "user" } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Nombre de usuario y contraseña son requeridos" });
  }

  const users = getUsers();
  const userExists = users.find((u) => u.username === username);

  if (userExists) {
    return res.status(400).json({ error: "El nombre de usuario ya está registrado" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = { username, password: hashedPassword, role: role || "user" }; // Ensure role defaults to "user"
  users.push(newUser);
  saveUsers(users);

  res.status(201).json({ message: "Usuario registrado exitosamente" });
});

// Login endpoint
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Nombre de usuario y contraseña son requeridos" });
  }

  const users = getUsers();
  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({ error: "Credenciales incorrectas" });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (!isPasswordValid) {
    return res.status(401).json({ error: "Credenciales incorrectas" });
  }

  const userRole = user.role || "user"; // Default to "user" if role is missing
  const token = jwt.sign(
    { username: user.username, role: userRole },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({ message: "Inicio de sesión exitoso", token, role: userRole });
});

// Protected route example
app.get("/protected-route", authenticateToken, (req, res) => {
  res.json({ message: "Esta es una ruta protegida.", user: req.user });
});

// Start server
app.listen(PORT, () => {
  console.log(`Servidor iniciado en puerto ${PORT}`);
});
