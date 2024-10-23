const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const expressJwt = require('express-jwt');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

// Middleware para permitir JSON no corpo das requisições
app.use(bodyParser.json());

// Chave secreta para JWT
const SECRET_KEY = "supersecretkey"; // Troque por uma chave secreta mais forte

// Rota de Registro (Criação de Usuário)
let users = []; // Lista simples de usuários (em produção, use um banco de dados)

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10); // Hashing da senha
  users.push({ username, password: hashedPassword });
  res.json({ message: 'Usuário registrado com sucesso!' });
});

// Rota de Login (Gera o JWT)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Login inválido' });
  }
});

// Middleware para proteger as rotas com JWT
app.use(expressJwt({ secret: SECRET_KEY, algorithms: ['HS256'] }).unless({ path: ['/login', '/register'] }));

// Socket.IO configuração (após autenticação)
io.on('connection', (socket) => {
  console.log('Usuário conectado:', socket.id);

  // Recebe a oferta de SDP de um usuário e a envia para o outro
  socket.on('offer', (offer) => {
    socket.broadcast.emit('offer', offer);
  });

  // Recebe a resposta SDP e a envia de volta
  socket.on('answer', (answer) => {
    socket.broadcast.emit('answer', answer);
  });

  // Envia os ICE candidates entre os pares
  socket.on('ice-candidate', (candidate) => {
    socket.broadcast.emit('ice-candidate', candidate);
  });

  socket.on('disconnect', () => {
    console.log('Usuário desconectado:', socket.id);
  });
});

const port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
