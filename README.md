cloud-kms-jwt-issuer
===
Sample application for issuing and verifying JWT with Cloud KMS.

## Endpoints

1. `POST /token`

```
$ curl -X POST -d sub=hello http://localhost:8080/token
{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjIifQ.eyJpYXQiOjE1Mzg3MzEzNzksImV4cCI6MTUzODczMjI3OSwic3ViIjoiaGVsbG8ifQ.ANjIIkmj7Hsk1MYHS105SBS6kkfMP9wj6mXkng9ibTcG9BSGHbz9PrgbwDK_S8Tu42QGMWx8PgIdxWBMs5zPEIOS7GV_FaOgWDapJietr_KfZMkvm5AfX-9jCsboq8Chbt_ikk2vFt_GDHqRKHfCUTYrVmJfO9jSpcLCsbM2_hqTk14ecq3OILmo9gYjmX6ErZgHJ7vy0RzQptcW1xCofGK-xh2uTN07mb8TVN3eLjT61KmEID6FBCbG1xExE0h7jGzmA2V7rDjxcbokCZsxFIApN4CYJx4W0UoizWQZnenEP8CIRi75L-C60PZ1D6gpdGzBrcPf0pkeqGr2Yes22g",
  "expires_in": 900
}
```

2. `GET /tokeninfo`

```
$ curl http://localhost:8080/tokeninfo?token=$TOKEN
{
  "active": true,
  "iat": 1538731379,
  "exp": 1538732279,
  "sub": "hello"
}
```

3. `GET /certs`

```
$ curl http://localhost:8080/certs
{
  "keys": [
    {
      "kid": "2",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "mvynaw9v7JLu_9bK0ZpbhpypUFqyVutZOIP73daOqJl58_Q0js0-66kRHQLr0wFW95LfoxPPHC8bqJ2ofsjcZebp4C_Tg5sXiFIs2L-X30CrYz5A4hhXtTtYk1CGY5Qn1jq82f0RVPlUw4OhQudVakAvH6nBr8Prvr--NrCg24WPdXpWSBOTzzXUXIa49hoqcKaShZ77pbHbG9DoIKd-MkjdwvoC8jOz3cNjpLu1G6LBb5YV64R3yCbLeU0Q6Q5HG7YSqqKyVEPL9JjGrqGf_idoD_b7wABUKvqdNAS_MqiwJXItQiKUoMYnXrCfQfWzwy4Vj6zsq2g8xxBzVbNtDw",
      "e": "AQAB"
    }
  ]
}
```

## TODO

* Key rotation
