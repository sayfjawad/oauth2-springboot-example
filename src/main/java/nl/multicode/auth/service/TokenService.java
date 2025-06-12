package nl.multicode.auth.service;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import org.apache.hc.client5.http.fluent.Form;
import org.apache.hc.client5.http.fluent.Request;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class TokenService {

  private static final Map<String, String> HOSTS = Map.of(
      "cicd", "acc.idp.cmf.energysector.nl",
      "d", "dev.idp.cmf.energysector.nl",
      "t", "acc.idp.cmf.energysector.nl",
      "a", "acc.idp.cmf.energysector.nl",
      "p", "idp.cmf.energysector.nl"
  );

  @Value("${oauth.env}")
  private String env;

  @Value("${oauth.client-id}")
  private String clientId;

  @Value("${oauth.private-key}")
  private String privateKeyPem;

  public String getAccessToken() throws Exception {

    log.info("Getting access token for env: {}", env);
    log.info("Client ID: {}", clientId);
    log.info("Private key-length: {}", privateKeyPem.length());

    String host = HOSTS.get(env);
    String tokenUrl = "https://" + host + "/am/oauth2/access_token";

    // Step 1: Sign JWT
    String jwt = generateClientAssertion(tokenUrl);

    // Step 2: Send POST request
    return Request.post(tokenUrl)
        .bodyForm(
            Form.form()
                .add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .add("scope", "roles")
                .add("client_assertion", jwt)
                .build(),
            StandardCharsets.UTF_8
        )
        .execute()
        .returnContent()
        .asString(); // Optionally parse the token JSON if needed
  }

  private String generateClientAssertion(String audience) throws Exception {
    Instant now = Instant.now();

    JWTClaimsSet claims = new JWTClaimsSet.Builder()
        .issuer(clientId)
        .subject(clientId)
        .audience(audience)
        .expirationTime(java.util.Date.from(now.plusSeconds(300)))
        .jwtID(UUID.randomUUID().toString())
        .issueTime(java.util.Date.from(now))
        .build();

    JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
        .type(JOSEObjectType.JWT)
        .build();

    SignedJWT signedJWT = new SignedJWT(header, claims);

    RSAPrivateKey rsaPrivateKey = loadPrivateKey(privateKeyPem);
    JWSSigner signer = new RSASSASigner(rsaPrivateKey);
    signedJWT.sign(signer);

    return signedJWT.serialize();
  }

  private RSAPrivateKey loadPrivateKey(String pem) throws Exception {
    String privateKeyContent = pem
        .replaceAll("\\n", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .trim();

    byte[] decoded = Base64.getDecoder().decode(privateKeyContent);
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return (RSAPrivateKey) kf.generatePrivate(spec);
  }
}
