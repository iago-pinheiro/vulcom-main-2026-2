import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import argon2 from 'argon2'
import argon2Options from '../config/argon2.js'

const controller = {}     // Objeto vazio

controller.create = async function(req, res) {
  try {

    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // atribuição em massa permite ao cliente definir campos sensíveis, como is_admin.
    if(typeof req.body?.password !== 'string' || req.body.password.length === 0) {
      return res.status(400).send({ error: 'Informe uma senha válida.' })
    }

    const data = { ...req.body }
    data.password = await argon2.hash(data.password, argon2Options)
    await prisma.user.create({ data })

    // HTTP 201: Created
    res.status(201).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveAll = async function(req, res) {
  try {
    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // a consulta expõe todos os campos dos usuários, incluindo o hash da senha.
    const result = await prisma.user.findMany()

    // HTTP 200: OK (implícito)
    res.send(result)
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveOne = async function(req, res) {
  try {
    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // o ID recebido permite consultar qualquer usuário, incluindo seu campo password.
    const result = await prisma.user.findUnique({
      where: { id: Number(req.params.id) }
    })

    // Encontrou ~> retorna HTTP 200: OK (implícito)
    if(result) res.send(result)
    // Não encontrou ~> retorna HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.update = async function(req, res) {
  try {

    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // o cliente pode alterar is_admin e password de qualquer usuário por atribuição em massa.
    const data = { ...req.body }
    // Sem o campo password, a senha atual é mantida.
    if(data.password !== undefined) {
      if(typeof data.password !== 'string' || data.password.length === 0) {
        return res.status(400).send({ error: 'Informe uma senha válida.' })
      }
      data.password = await argon2.hash(data.password, argon2Options)
    }

    const result = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data
    })

    // Encontrou e atualizou ~> HTTP 204: No Content
    if(result) res.status(204).end()
    // Não encontrou (e não atualizou) ~> HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.delete = async function(req, res) {
  try {
    await prisma.user.delete({
      where: { id: Number(req.params.id) }
    })

    // Encontrou e excluiu ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      // Não encontrou e não excluiu ~> HTTP 404: Not Found
      res.status(404).end()
    }
    else {
      // Outros tipos de erro
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}

controller.login = async function(req, res) {
  try {

      if(typeof req.body?.password !== 'string' || req.body.password.length === 0 ||
        (!req.body?.username && !req.body?.email)) return res.status(401).end()

      // Busca o usuário no BD usando o valor dos campos
      // "username" OU "email"
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            { username: req.body?.username },
            { email: req.body?.email }
          ]
        }
      })

      // Se o usuário não for encontrado, retorna
      // HTTP 401: Unauthorized
      if(! user) return res.status(401).end()

      // Senhas antigas em texto claro precisam ser cadastradas novamente.
      if(!user.password.startsWith('$argon2id$')) return res.status(401).end()
      const passwordIsValid = await argon2.verify(user.password, req.body.password)

      // Se a senha estiver errada, retorna
      // HTTP 401: Unauthorized
      if(! passwordIsValid) return res.status(401).end()

      // Usuário e senha OK, passamos ao procedimento de gerar o token
      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // o JWT ainda inclui password (agora um hash); a assinatura não oculta o conteúdo.
      const token = jwt.sign(
        user,                       // Dados do usuário
        process.env.TOKEN_SECRET,   // Senha para criptografar o token
        { expiresIn: '24h' }        // Prazo de validade do token
      )

      // Formamos o cookie para enviar ao front-end
      res.cookie(process.env.AUTH_COOKIE_NAME, token, {
        httpOnly: true, // O cookie ficará inacessível para o JS no front-end
        secure: true,   // O cookie será criptografado em conexões https
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 100  // 24h
      })

      // Retorna o token e o usuário autenticado com
      // HTTP 200: OK (implícito)
      res.send({token, user})

  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.me = function(req, res) {
  // Retorna as informações do usuário autenticado
  // HTTP 200: OK (implícito)
  res.send(req?.authUser)
}

export default controller
