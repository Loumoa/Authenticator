package fr.loumoa.authenticator.util;

import fr.loumoa.authenticator.model.ERole;
import fr.loumoa.authenticator.model.Role;
import fr.loumoa.authenticator.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

public class RoleUtil {

    public static Set<Role> adaptRoles(Set<String> incomingRoles, RoleRepository roleRepository) {
        Set<Role> roles = new HashSet<>();

        if (incomingRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            incomingRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    case "proprio":
                        Role proprioRole = roleRepository.findByName(ERole.ROLE_PROPRIO)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(proprioRole);

                        break;
                    case "loc":
                        Role locRole = roleRepository.findByName(ERole.ROLE_LOCATAIRE)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(locRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }
        return roles;
    }
}
