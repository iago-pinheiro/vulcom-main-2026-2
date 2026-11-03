import { faker } from '@faker-js/faker/locale/pt_BR'
import { PrismaClient } from '@prisma/client'
import argon2 from 'argon2'
import argon2Options from '../src/config/argon2.js'

const prisma = new PrismaClient();

const colors = [
  'AMARELO',
  'AZUL',
  'BRANCO',
  'CINZA',
  'DOURADO',
  'LARANJA',
  'MARROM',
  'PRATA',
  'PRETO',
  'ROSA',
  'ROXO',
  'VERDE',
  'VERMELHO'
]

async function main() {
  // Comentário inicial do desafio de XSS
  await prisma.xssComment.create({
    data: { content: 'Bem-vindo ao desafio de XSS!' }
  })

  // Criar usuários
  const users = [];
  const numberOfUsers = 4;

 // Cria o administrador somente se o e-mail ainda não existir
  const user = await prisma.user.upsert({
    where: {
      email: 'admin@vulcom.com.br'
    },
    update: {},
    create: {
      fullname: 'Administrador do Sistema',
      username: 'admin',
      email: 'admin@vulcom.com.br',
      password: await argon2.hash('Vulcom@DSM', argon2Options),
      is_admin: true
    }
  })

  users.push(user)
  
  for (let i = 0; i < numberOfUsers; i++) {
    const user = await prisma.user.create({
      data: {
        fullname: faker.person.fullName(),
        username: faker.internet.username(),
        email: faker.internet.email(),
        // OWASP Top 10:2025 A07 - Falhas de Autenticação: senha fraca e compartilhada entre contas.
        password: await argon2.hash('senha123', argon2Options),
        is_admin: i === 0,
      },
    });
    users.push(user);
  }

  // Criar clientes
  const customers = [];
  const numberOfCustomers = 10;
  
  for (let i = 0; i < numberOfCustomers; i++) {
    const customer = await prisma.customer.create({
      data: {
        name: faker.person.fullName(),
        ident_document: faker.helpers.replaceSymbols('###.###.###-##'), // CPF formatado
        birth_date: faker.date.birthdate({ min: 18, max: 65, mode: 'age' }),
        street_name: faker.location.street(),
        house_number: faker.location.buildingNumber(),
        complements: faker.location.secondaryAddress(),
        municipality: faker.location.city(),
        state: faker.location.state({ abbreviated: true }),
        phone: faker.phone.number('(##) 9#### ####'),
        email: faker.internet.email(),
      },
    });
    customers.push(customer);
  }

  // Criar carros
  const numberOfCars = 20;
  
  for (let i = 0; i < numberOfCars; i++) {
    const hasCustomer = faker.datatype.boolean({ probability: 0.7 });
    const customer = hasCustomer ? faker.helpers.arrayElement(customers) : null;
    const willBeSold = faker.datatype.boolean({ probability: 0.5 });
    
    await prisma.car.create({
      data: {
        brand: faker.vehicle.manufacturer(),
        model: faker.vehicle.model(),
        color: faker.helpers.arrayElement(colors),
        year_manufacture: faker.number.int({ min: 2000, max: new Date().getFullYear() }),
        imported: faker.datatype.boolean(),
        plates: `${faker.string.alpha(3).toUpperCase()}-${faker.string.numeric(4)}`, // Formato ABC-1234
        selling_date: willBeSold ? faker.date.past() : null,
        selling_price: willBeSold
          ? faker.number.float({ min: 15000, max: 150000, precision: 0.01 })
          : null,
        customer_id: customer?.id,
        created_user_id: faker.helpers.arrayElement(users).id,
        updated_user_id: faker.helpers.arrayElement(users).id,
      },
    });
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
