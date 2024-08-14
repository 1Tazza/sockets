import express from "express"
import logger from "morgan"
import dotenv from "dotenv"
import {createClient} from "@libsql/client"
dotenv.config()

import bcrypt from "bcrypt"
import session from "express-session"
import { Server } from "socket.io"
import {createServer} from "node:http"
import { hashPassword } from "./config/hashFunction.js"

const port = process.env.PORT ?? 3000


const app = express()

app.use(express.urlencoded({ extended: true }));

app.use(express.json());

const server = createServer(app)

const io = new Server(server, {
    connectionStateRecovery:{}
})
 
const db = createClient({
    url: process.env.DB_URL,
    authToken: process.env.DB_TOKEN
})

await db.execute(`
 CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT,
    user TEXT
 )
`)

await db.execute(`
 CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  email TEXT,
  password TEXT
 )
`)

io.on("connection", async(socket) => {
    console.log("a user has connected!")

    socket.on("disconnect", () => {
        console.log("an user has disconnected")
    })

    socket.on("chat message", async(msg) => {
        let result
        const username = socket.handshake.auth.username ?? "anonymous"

        console.log({username})
        try{
          result = await db.execute({
            sql: "INSERT INTO messages (content, user) VALUES(:msg, :username)",
            args: { msg, username }
          })
        } catch(e){
           console.error(e)
           return
        }

        io.emit("chat message", msg, result.lastInsertRowid.toString(), username)
    })

    console.log(socket.handshake.auth)

    if(!socket.recovered) {
        try {
         const results = await db.execute({
            sql: "SELECT id, content, user FROM messages WHERE id > ?",
            args: [socket.handshake.auth.serverOffset ?? 0]
         })
         results.rows.forEach(row => {
            socket.emit("chat message", row.content, row.id.toString(), row.user)
         })
        } catch(e) {
         console.error(e)
         return
        }
    }
})

const isAuthenticated = (req, res, next) => {
    if (req.session.isAuthenticated) {
      return next();
    }
    res.redirect('/register');
  };





app.use(logger("dev"))

app.use(session({
  secret: 'secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } 
}));


app.get('/register', (req, res) => {
    res.sendFile(process.cwd() + '/client/register.html'); 
  });

app.post('/register', async (req, res) => {
  const { username, email } = req.body;
  const password = await hashPassword(req.body.password)
  console.log(req.body)
  try {
    await db.execute({
      sql: "INSERT INTO users (username, email, password) VALUES(:username, :email, :password)",
      args: { username, email, password }
    });
    res.redirect('/'); // Redirige al usuario después de registrarse
  } catch (e) {
    console.error(e);
    res.status(500).send("Error al registrar el usuario");
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  console.log("estamos en GET",req.body)
  try {
    const findUser = await db.execute({
      sql: "SELECT * FROM users WHERE email = :email",
      args: {email}
    })

    const user = findUser.rows[0]
    console.log("user",user)
    
    if(!user) {res.status(404).send("Usuario no encontrado")}
    
    const result = await bcrypt.compare(password, user.password)

    if (result) {
      
      req.session.userId = user.id
      req.session.isAuthenticated = true

      res.redirect('/'); // Redirige al usuario si las contraseñas coinciden
    } else {
      res.redirect('/login?error=incorrect-password');
    }

  } catch (e) {
    console.error(e);
    res.status(500).send("Error al registrar el usuario");
  }
});
  

app.get("/", isAuthenticated, (req, res) => {
    res.sendFile(process.cwd() + "/client/index.html")
})

server.listen(port, () => {
    console.log(`Server running on port ${port}`)
})

////