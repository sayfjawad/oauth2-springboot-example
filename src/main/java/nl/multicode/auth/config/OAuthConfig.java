package nl.multicode.auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@ConfigurationProperties(prefix = "myapp")
@Component
@Data
public class OAuthConfig {

  private String env;
  private String clientId;
  private String privateKey;
}
