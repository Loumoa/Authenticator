package fr.loumoa.authenticator.payload.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.util.Set;

@Data
public class RolesRequest {
    private Set<String> role;
}
