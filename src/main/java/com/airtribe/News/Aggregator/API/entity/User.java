package com.airtribe.News.Aggregator.API.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User implements UserDetails  {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    @NotBlank
    private String username;

    @NotBlank
    private String password;

    @ElementCollection
    private Set<String> preferences;

    @ElementCollection
    private Set<String> readArticles;

    @ElementCollection
    private Set<String> favoriteArticles;

    public User(String username, String password) {
        this.username = username;
        this.password = password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;  // Account never expires
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;  // Account never locked
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;  // Credentials never expire
    }

    @Override
    public boolean isEnabled() {
        return true;  // Account is always enabled
    }
}
