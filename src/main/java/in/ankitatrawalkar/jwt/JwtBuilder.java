package in.ankitatrawalkar.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import in.ankitatrawalkar.utils.PEMUtils;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class JwtBuilder {

    public static void main(String[] args) {
        try {
            RSAPublicKey pubRSA = (RSAPublicKey) PEMUtils.readPublicKeyFromFile("src/main/resources/public-key.pem", "RSA");
            RSAPrivateKey privRSA = (RSAPrivateKey) PEMUtils.readPrivateKeyFromFile("src/main/resources/private-key.pem", "RSA");
            Algorithm algorithm = Algorithm.RSA256(pubRSA, privRSA);
            Calendar currentDate = Calendar.getInstance();
            currentDate.add(Calendar.YEAR, 10);
            Map<String, Object> headerClaims = new HashMap<>();
            // Custom header claim
            headerClaims.put("customHeaderClaim1", "xxxx-xxxx-xxxx-xxxx");
            String token = JWT.create().withIssuer("idp:xxxx-xxxx")
                    .withSubject("resource-server:xxxx-xxxx")
                    .withAudience("https://example.com")
                    .withIssuedAt(new Date())
                    .withJWTId(UUID.randomUUID().toString())
                    .withHeader(headerClaims)
                    .withExpiresAt(currentDate.getTime()).sign(algorithm);
            System.out.println("Token: " + token);
        } catch (JWTCreationException | IOException exception){
            // Invalid Signing configuration / Couldn't convert Claims.
            exception.printStackTrace();
        }
    }

}
