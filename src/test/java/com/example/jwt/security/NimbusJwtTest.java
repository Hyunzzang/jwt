package com.example.jwt.security;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.junit.jupiter.api.Test;

import java.text.ParseException;

import static org.assertj.core.api.Assertions.assertThat;

public class NimbusJwtTest {
    final String secret = "841D8A6C80CBA4FCAD32D5367C18C53B";

    @Test
    public void creatingEncrypter_Test() throws JOSEException {

        // Creating the Payload
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject("test0001")
                .claim("email", "test0001@google.com")
                .claim("name", "hyun zzang")
                .build();
        Payload payload = new Payload(claims.toJSONObject());

        // Creating the Header
        JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        // Creating the Encrypter
        DirectEncrypter encrypter = new DirectEncrypter(secret.getBytes());

        // Creating the Token
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(encrypter);
        String token = jweObject.serialize();
        System.out.println("token: " + token);

        assertThat(token).isNotNull();
    }

    @Test
    public void parsingToken_test() throws BadJOSEException, ParseException, JOSEException {

        // Configuring a JWT Processor
        ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<>(secret.getBytes());
        JWEKeySelector<SimpleSecurityContext> jweKeySelector =
                new JWEDecryptionKeySelector<>(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);
        jwtProcessor.setJWEKeySelector(jweKeySelector);

        // Parsing the Claims
        String token = "eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..IDtgDaH8XgZ7cjpXDkXTUA.hRQFsp4l8RmfU4wjM5Or0I-ZH5NBMH9dzdaDbX8SRi41cHM2FRvus39qUczdfvcuO7Qw8VVrcdAtoUb5XV6_3t9sv5Ou7CuXKuk74W4tg-0.IcQ0dqRfjNEq0gX9dFsu8A";
        JWTClaimsSet claims = jwtProcessor.process(token, null);
        String subject = claims.getSubject();
        String email = (String) claims.getClaim("email");
        String name = (String) claims.getClaim("name");

        assertThat(subject).isEqualTo("test0001");
        assertThat(email).isEqualTo("test0001@google.com");
        assertThat(name).isEqualTo("hyun zzang");
    }
}
