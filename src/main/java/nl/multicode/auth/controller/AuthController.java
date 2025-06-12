package nl.multicode.auth.controller;

import nl.multicode.auth.service.TokenService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

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

      return accessToken;
    } catch (Exception e) {
      return "Error fetching token: " + e.getMessage();
    }
  }
}
