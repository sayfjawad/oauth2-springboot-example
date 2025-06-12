package nl.multicode.auth.client;

import nl.multicode.auth.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class ApiClient {

  private final TokenService tokenService;

  @Autowired
  public ApiClient(TokenService tokenService) {
    this.tokenService = tokenService;
  }

  public String callProtectedApi() throws Exception {
    String token = tokenService.getAccessToken();

    RestTemplate restTemplate = new RestTemplate();

    var headers = new org.springframework.http.HttpHeaders();
    headers.setBearerAuth(token);

    var request = new org.springframework.http.HttpEntity<>(headers);

    ResponseEntity<String> response = restTemplate
        .exchange("https://api.example.com/endpoint",
            org.springframework.http.HttpMethod.GET,
            request,
            String.class);

    return response.getBody();
  }
}
