package nl.multicode.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

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
  private final WebClient webClient;
  @Value("${oauth.env}")
  private String env;
  @Value("${oauth.client-id}")
  private String clientId;
  @Value("${oauth.private-key}")
  private String privateKeyPem;

  public TokenService(WebClient webClient) {
    this.webClient = webClient;
  }

  public String getAccessToken() throws Exception {

    log.info("Getting access token for env: {}", env);
    log.info("Client ID: {}", clientId);
    log.info("Private key-length: {}", privateKeyPem.length());

    final var host = HOSTS.get(env);
    final var tokenUrl = "https://" + host + "/am/oauth2/access_token";

    // Step 1: Sign JWT
    final var jwt = generateClientAssertion(tokenUrl);

    // Step 2: Send POST request

    final var responseBody = webClient.post()
        .uri(tokenUrl)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .bodyValue("grant_type=client_credentials" +
            "&client_id=" + clientId +
            "&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" +
            "&scope=roles" +
            "&client_assertion=" + jwt)
        .retrieve()
        .bodyToMono(String.class)
        .block(); // Optional: Use `.block()` only in non-reactive flows

    log.warn("Response length: {}", responseBody.length());
    log.warn("Response string: {}", responseBody);

    final var mapper = new ObjectMapper();
    final var jsonNode = mapper.readTree(responseBody);
    return jsonNode.get("access_token").asText();
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

  @SneakyThrows
  private RSAPrivateKey loadPrivateKey(String pem) {
    try (PemReader pemReader = new PemReader(new StringReader(pem))) {
      PemObject pemObject = pemReader.readPemObject();
      byte[] content = pemObject.getContent();

      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(content);
      KeyFactory kf = KeyFactory.getInstance("RSA");
      return (RSAPrivateKey) kf.generatePrivate(keySpec);
    }
  }


}
