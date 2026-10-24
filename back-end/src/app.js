import dotenv from 'dotenv'
dotenv.config() // Carrega as variáveis de ambiente do arquivo .env


import express, { json, urlencoded } from 'express'
import cookieParser from 'cookie-parser'
import logger from 'morgan'


const app = express()


import cors from 'cors'


app.use(cors({
 origin: process.env.ALLOWED_ORIGINS.split(','),
 // credentials: true
}))


// OWASP Top 10:2025 A09 - Falhas nos Logs de Segurança e no Sistema de Alertas:
// o log HTTP não registra autor e mudanças de privilégios nem gera alertas de abuso.
app.use(logger('dev'))
// OWASP Top 10:2025 A02 - Configuração Inadequada de Segurança:
// sem tratamento próprio de erros, JSON inválido expõe stack trace no modo development.
app.use(json())
app.use(urlencoded({ extended: false }))
app.use(cookieParser())


/*********** ROTAS DA API **************/


import carsRouter from './routes/cars.js'
app.use('/cars', carsRouter)


import customersRouter from './routes/customers.js'
app.use('/customers', customersRouter)


import usersRouter from './routes/users.js'
app.use('/users', usersRouter)


// OWASP Top 10:2025 A02 - Configuração Inadequada de Segurança:
// os módulos vulneráveis de treinamento também ficam ativos se o app for usado em produção.
import xssRouter from './routes/xss.js'
app.use('/challenges/xss', xssRouter)


import sqliRouter from './routes/sqli.js'
app.use('/challenges/sqli', sqliRouter)


export default app
