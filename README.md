# spring security demo
spring security 사용한 인증 데모

## 키 발급
```
keytool -genkeypair -alias 앨리어스명 -keyalg 암호알고리즘 -keypass 키패스워드 -keystore 키스토어명 -storepass 스토어패스워드
keytool -genkeypair -alias proc -keyalg RSA -keypass proc123 -keystore proc.jks -storepass proc
```

## API
* v1 버전에는 로그아웃 기능이 지원 안됨
* 로그인후 헤드에 발급받은 토큰을 세팅하여 접근 가능 (authorization: Bearer {발급받은 토큰})
* WebSecurityConfig 설정에서 OAuth 2.0 리소스 서버(oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)에 대한 JWT 전달자 토큰 지원을 활성화
* JwtDecoder 빈 설정 하여 spring security에서 jwt 토큰을 복호화 할수 있도록 해야 함

### 1. 회원가입_v1
> [POST] /api/v1/join
```
curl -X POST http://localhost:8080/api/v1/join -H 'cache-control: no-cache' -H 'content-type: application/json' -d '{ "email":"abcd123@gmail.com", "password":"abcd1234"}'
```

### 2. 로그인_v1
* 로그인 후 JWT 발급
> [POST] /api/v1/login
```
curl -X POST http://localhost:8080/api/v1/login -H 'cache-control: no-cache' -H 'content-type: application/json' -d '{ "email":"abcd123@gmail.com", "password":"abcd1234"}'
```

### 3. 유저정보 확인_v1
> [GET] /api/v1/user
```
curl -X GET http://localhost:8080/api/v1/user -H 'authorization: Bearer {JWT 토큰}' -H 'cache-control: no-cache' -H 'content-type: application/json'
```