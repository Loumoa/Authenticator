package fr.loumoa.authenticator.payload.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
public class MessageResponse {
  @Getter@Setter
  private String message;
}
