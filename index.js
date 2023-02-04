require('dotenv').config()
const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()
// Middleware
app.use(express.json())

let refreshTokens = []

// Routes

// Registration

// Login
app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    if (username === 'fernando' && password === '123456'){
        const access_token = jwt.sign({sub: username}, process.env.JWT_ACCESS_SECRET, {expiresIn: process.env.JWT_ACCESS_TIME})
        const refresh_token = generateRefreshToken(username)

        return res.json({status: true, message: 'Login realizado com sucesso.', data: {access_token, refresh_token}})
    }
    return res.status(401).json({status: false, message: 'Falha ao realizar o login.'})
})

// Refresh Token
app.post('/token', verifyRefreshToken, (req, res) => {
    const username = req.userData.sub
    const access_token = jwt.sign({sub: username}, process.env.JWT_ACCESS_SECRET, 
        {expiresIn: process.env.JWT_ACCESS_TIME})
    const refresh_token = generateRefreshToken(username)

    return res.json({status: true, message: 'Novo refresh token gerado com sucesso.', data: {access_token, refresh_token}})
  
})

// Dashboard - página que só pode acessar se estiver autenticado / logado
app.get('/dashboard', verifyToken, (req, res) => {
    return res.json({status: true, message: 'Olá página de Dashboard! :-)'})
})

// Logout
app.get('/logout', verifyToken, (req, res) => {
    const username = req.userData.sub

    // Remove o refresh token
    refreshTokens = refreshTokens.filter(x => x.username !== username)

    console.log('--------------------- REFRESH TOKENS ARMAZENADOS -----------------------')
    console.log(refreshTokens)

    return res.json({status: true, message: 'Refresh token removido com sucesso.'})
})


// Middleware para verificar o Token
function verifyToken(req, res, next){
    try{
        // Bearer token string
        const token = req.headers.authorization.split(' ')[1];
        
        const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET)
        req.userData = decoded
        next()

    } catch (error) {
        return  res.status(401).json({status: false, message: 'Access Token (sessão) inválido.', data: error})
    }
}

// Middleware para verificar o Refresh Token
function verifyRefreshToken(req, res, next){
    const token = req.body.token;
    if (token === null){
        return  res.status(401).json({status: false, message: 'Refresh Token não enviado.'})
    }
    try{
        const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET)
        req.userData = decoded
        
        // Verifica se o refresh token está armazenado ou não
        let storedRefreshToken = refreshTokens.find(x => x.username === decoded.sub)
        if (storedRefreshToken === undefined){
            return res.status(401).json({status: false, message: 'Refresh Token não armazenado.'})
        }
        // Verifica se o refresh token enviado for direrente do refresh token armazenado
        if (storedRefreshToken.token != token){
            return res.status(401).json({status: false, message: 'Refresh Token recebido é diferente do refresh token armazenado.'})
        }

        next()

    } catch (error) {
        return  res.status(401).json({status: false, message: 'Refresh Token (sessão) inválido...', data: error})
    }
}

function generateRefreshToken(username){
    const refresh_token = jwt.sign({sub: username}, process.env.JWT_REFRESH_SECRET, 
        { expiresIn: process.env.JWT_REFRESH_TIME})

    // Verifica se o refresh token está armazenado ou não
    let storedRefreshToken = refreshTokens.find(x => x.username === username)
    // Se o refresh token não estiver armazenado, adiciona-o no vetor de refresh token
    if (storedRefreshToken === undefined){
        //return res.status(401).json({status: false, message: 'Refresh Token não armazenado.'})
        refreshTokens.push({
            username: username, token: refresh_token
        })
    } else { // Se o refresh token já estiver armazenado, atualiza-o
        // Encontra o ínidice do token que precisa ser atualizado pelo nome do usuário
        let index = refreshTokens.findIndex(x => x.username === username)
        // Atualiza refresh token do usuário selecionado pelo índice
        refreshTokens[index].token = refresh_token
    }
    console.log('--------------------- REFRESH TOKENS ARMAZENADOS -----------------------')
    console.log(refreshTokens)
    return refresh_token
}


app.listen(3000, () => console.log('Servidor em execução...'))
