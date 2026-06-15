package nesrine_dev.hospitalapp.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.autoconfigure.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    @Autowired
    private PasswordEncoder passwordEncoder;

    //avec Bean la methode spring qui s'execute au demarrage
    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        return new InMemoryUserDetailsManager(
//                User.withUsername("user1").password("{noop}1234").roles("USER").build(),
                User.withUsername("user1").password(passwordEncoder.encode("1234")).roles("USER").build(),
                User.withUsername("user2").password(passwordEncoder.encode("1234")).roles("USER").build(),
                User.withUsername("admin").password(passwordEncoder.encode("1234")).roles("USER","ADMIN").build()
        );
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // http.formLogin(Customizer.withDefaults());
        //       ↑              ↑
        //  active le       utilise toute la
        //  form login      config par défaut

        // personnalisation de formulaire dauthentification
        http.formLogin(form -> form.loginPage("/login").permitAll());
        http.rememberMe(rememberMe -> rememberMe.key("une-clé-secrète")          // clé pour signer le cookie
                                                .tokenValiditySeconds(604800));  // durée : 7 jours);

        // authentication only
        // http.authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated());

        // authentication with authorization
        http.authorizeHttpRequests(auth -> auth.requestMatchers("/webjars/**","/h2-console/**").permitAll()
        //                                     .requestMatchers("/user/**").hasRole("USER")
        //                                     .requestMatchers("/admin/**").hasRole("ADMIN")
                                               .anyRequest().authenticated());
        http.exceptionHandling(exp -> exp.accessDeniedPage("/notAuthorized"));

        return http.build();
    }
}

