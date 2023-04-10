package fr.loumoa.authenticator.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table( name = "users", uniqueConstraints =  {
        @UniqueConstraint(columnNames = "username"),
        @UniqueConstraint(columnNames = "email")
})
@NoArgsConstructor(force = true)
@RequiredArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Getter@Setter
    private Long id;

    @NotBlank
    @Size(max = 20)
    @NonNull
    @Getter@Setter
    private String username;

    @NotBlank
    @Size(max = 50)
    @Email
    @NonNull
    @Getter@Setter
    private String email;

    @NotBlank
    @Size(max = 120)
    @NonNull
    @Getter@Setter
    private String password;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id"))
    @Getter@Setter
    private Set<Role> roles = new HashSet<>();
}
