import prisma from '../database/client.js'

// *** SOLUÇÃO XSS 2: Importação e configuração do DOMPurify ***
import createDOMPurify from 'dompurify'
import { JSDOM } from 'jsdom'

const window = new JSDOM('').window
const DOMPurify = createDOMPurify(window)

const controller = {}

controller.retrieveComments = async function(req, res) {
  try {
    const comments = await prisma.xssComment.findMany({
      orderBy: { id: 'asc' }
    })

    res.send(comments)
  }
  catch(error) {
    console.error(error)
    res.status(500).end()
  }
}

controller.createComment = async function(req, res) {
 try {
   // Sanitização com DOMPurify
   const comment = DOMPurify.sanitize(req.body?.content ?? '')

   // OWASP Top 10:2025 A05 - Injeção (XSS armazenado):
   // o conteúdo é persistido sem sanitização e depois interpretado como HTML em XssChallenge.jsx.
   await prisma.xssComment.create({
     data: { content: comment }
   })

   res.status(201).end()
 }
 catch(error) {
   console.error(error)
   res.status(500).end()
 }
}

export default controller
