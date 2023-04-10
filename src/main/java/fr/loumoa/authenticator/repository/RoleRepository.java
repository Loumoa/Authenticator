package fr.loumoa.authenticator.repository;

import fr.loumoa.authenticator.model.ERole;
import fr.loumoa.authenticator.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
