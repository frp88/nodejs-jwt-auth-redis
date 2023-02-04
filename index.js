require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()
// Middleware
app.use(express.json())

// Routes

// Registration

// Login
app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    if (username === 'fernando' && password === '123456'){
        const access_token = jwt.sign(
            {sub: username}, 
            process.env.JWT_ACCESS_SECRET, 
            { expiresIn: process.env.JWT_ACCESS_TIME}
        )
        return res.json({status: true, message: 'Login realizado com sucesso.', data: {access_token}})
    }
    return res.status(401).json({status: false, message: 'Falha ao realizar o login.'})
})

// Dashboard - página que só pode acessar se estiver autenticado / logado
app.get('/dashboard', verifyToken, (req, res) => {
    return res.json({status: true, message: 'Olá página de Dashboard! :-)'})
})

// Middleware para verificar o Token
function verifyToken(req, res, next){
    try{
        // Bearer token string
        const token = req.headers.authorization.split(' ')[1];
        
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET)
        req.userData = decoded;
        next()

    } catch (error) {
        return  res.status(401).json({status: false, message: 'Access Token (sessão) inválido.', data: error})
    }
}


app.listen(3000, () => console.log('Servidor está executando...'))
