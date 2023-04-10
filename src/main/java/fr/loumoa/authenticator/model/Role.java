package fr.loumoa.authenticator.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "roles")
@NoArgsConstructor(force = true)
@RequiredArgsConstructor
public class Role {
    @Id
    @GeneratedValue()
    @Setter@Getter
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    @NonNull
    @Setter@Getter
    private ERole name;
}
