import argon2 from 'argon2'

// O sal aleatório é gerado pela biblioteca e já fica incluído no hash.
export default {
  type: argon2.argon2id,
  memoryCost: 65536, // 64 MiB
  timeCost: 3,
  parallelism: 4
}