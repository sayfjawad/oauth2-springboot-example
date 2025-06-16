package nl.multicode.auth.controller;

import java.util.List;
import java.util.UUID;
import lombok.extern.slf4j.Slf4j;
import nl.multicode.auth.service.TokenService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@Slf4j
@RestController
public class AuthController {

  private final TokenService tokenService;

  public AuthController(TokenService tokenService) {
    this.tokenService = tokenService;
  }

  @GetMapping("/token")
  public String getAccessToken() {
    try {
      return tokenService.getAccessToken();
    } catch (Exception e) {
      return "Error fetching token: " + e.getMessage();
    }
  }

  @GetMapping("/test-token")
  public String getTestMprWithAccessToken() {
    try {
      String accessToken = tokenService.getAccessToken();

      var headers = new org.springframework.http.HttpHeaders();
      headers.setBearerAuth(accessToken);
      headers.set("X-Request-ID", UUID.randomUUID().toString());
      headers.setAccept(List.of(MediaType.APPLICATION_JSON));
      var request = new org.springframework.http.HttpEntity<>(headers);

      RestTemplate restTemplate = new RestTemplate();
      String url = "https://mpr-v2.levering.acc.local.rhos-ota.tnl-edsn.nl/administer-marketparties/v2/organisations?registration-number-mrid=24289101";
      ResponseEntity<String> response = restTemplate
          .exchange(url,
              org.springframework.http.HttpMethod.GET,
              request,
              String.class);
      String body = response.getBody();
      log.info("Response body: {}", body);
      return body;
    } catch (Exception e) {
      return "Error fetching token: " + e.getMessage();
    }
  }
}
