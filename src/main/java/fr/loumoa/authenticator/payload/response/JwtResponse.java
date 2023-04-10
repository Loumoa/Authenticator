package fr.loumoa.authenticator.payload.response;

import lombok.*;

import java.util.List;

@Data
@RequiredArgsConstructor
public class JwtResponse {
  @NonNull
  private String token;
  private String type = "Bearer";
  @NonNull
  private Long id;
  @NonNull
  private String username;
  @NonNull
  private String email;
  @NonNull
  private List<String> roles;
}
