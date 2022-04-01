# spring security demo
spring security 사용한 인증 데모

## 키 발급
```
keytool -genkeypair -alias 앨리어스명 -keyalg 암호알고리즘 -keypass 키패스워드 -keystore 키스토어명 -storepass 스토어패스워드
keytool -genkeypair -alias proc -keyalg RSA -keypass proc123 -keystore proc.jks -storepass proc
```

## API
### 1. 회원가입
> [POST] /api/v1/join
```
curl -X POST http://localhost:8080/api/v1/join -H 'cache-control: no-cache' -H 'content-type: application/json' -d '{ "email":"abcd123@gmail.com", "password":"abcd1234"}'
```

### 2. 로그인
* 로그인 후 JWT 발급
> [POST] /api/v1/login
```
curl -X POST http://localhost:8080/api/v1/login -H 'cache-control: no-cache' -H 'content-type: application/json' -d '{ "email":"abcd123@gmail.com", "password":"abcd1234"}'
```

### 3. 유저정보 확인
> [GET] /api/v1/user
```
curl -X GET http://localhost:8080/api/v1/user -H 'authorization: Bearer {JWT 토큰}' -H 'cache-control: no-cache' -H 'content-type: application/json'
```