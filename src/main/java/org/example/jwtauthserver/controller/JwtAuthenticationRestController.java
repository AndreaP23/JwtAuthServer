package org.example.jwtauthserver.controller;

import java.util.Objects;
import jakarta.servlet.http.HttpServletRequest;
import org.example.jwtauthserver.exceptions.AuthenticationException;
import org.example.jwtauthserver.security.CustomUserDetails;
import org.example.jwtauthserver.security.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import lombok.extern.java.Log;

@RestController
@Log
public class JwtAuthenticationRestController {

    @Value("${sicurezza.header}")
    private String tokenHeader;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    @Qualifier("CustomUserDetailsService")
    private UserDetailsService userDetailsService;

    @PostMapping(value = "${sicurezza.uri}")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtTokenRequest authenticationRequest) {
        log.info("Tentativo di autenticazione e generazione del token");
        log.info("Email: " + authenticationRequest.getEmail());
        log.info("Password: " + authenticationRequest.getPassword());


        try {
            // Autentica l'utente
            authenticate(authenticationRequest.getEmail(), authenticationRequest.getPassword());

            // Carica i dettagli dell'utente dal servizio CustomUserDetailsService
            final CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(authenticationRequest.getEmail());

            // Ottieni il ruolo e l'userId dell'utente
            String ruolo = userDetails.getRuolo();
            String userId = String.valueOf(userDetails.getUserId());  // Ottieni l'ID utente dal CustomUserDetails

            // Genera il token JWT usando l'username, il ruolo e l'userId dell'utente
            final String token = jwtTokenUtil.generateToken(userDetails.getUsername(), ruolo, userId);

            log.info("Token generato con successo: " + token);

            // Restituisce il token JWT in una risposta JSON
            return ResponseEntity.ok(new JwtTokenResponse(token));

            //La pipe ti permette di gestire le due eccezzioni
        } catch (BadCredentialsException | AuthenticationException e) {
            log.warning("Errore: Credenziali non valide");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Errore: Credenziali non valide");
        } catch (DisabledException e) {
            log.warning("Errore: Utente disabilitato");
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Errore: Utente disabilitato");
        } catch (Exception e) {
            log.severe("Errore durante l'autenticazione: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Errore durante l'autenticazione. Riprova.");
        }
        //Gestire eccezzione, metti un catch
    }


    // Endpoint per aggiornare il token JWT
    @GetMapping(value = "${sicurezza.refresh}")
    public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
        log.info("Tentativo di refresh del token");

        String authToken = request.getHeader(tokenHeader);

        if (authToken == null || authToken.trim().isEmpty()) {
            return ResponseEntity.badRequest().body("Errore: Token assente o non valido");
        }

        // Estrai il token
        final String token = authToken;

        // Controlla se il token può essere aggiornato
        if (jwtTokenUtil.canTokenBeRefreshed(token)) {
            String refreshedToken = jwtTokenUtil.refreshToken(token);
            log.info("Token rinfrescato con successo");
            return ResponseEntity.ok(new JwtTokenResponse(refreshedToken));
        } else {
            log.warning("Errore: Il token non può essere rinfrescato");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Errore: Il token non può essere rinfrescato");
        }
    }

    // Metodo privato per autenticare l'utente
    private void authenticate(String email, String password) {
        Objects.requireNonNull(email);
        Objects.requireNonNull(password);

        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
        } catch (DisabledException e) {
            log.warning("Utente disabilitato");
            throw new AuthenticationException("Utente disabilitato", e);
        } catch (BadCredentialsException e) {
            log.warning("Credenziali non valide");
            throw new AuthenticationException("Credenziali non valide", e);
        }
    }
}
