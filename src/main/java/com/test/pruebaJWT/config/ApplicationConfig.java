package com.test.pruebaJWT.config;

import com.test.pruebaJWT.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository repository;

    @Bean
    public UserDetailsService userDetailsService(){//tambien podria haber implementado la interfaz en vez de usar @Bean
        return username -> repository.findByEmail((username))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
