package org.example.jwtauthserver.security;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import lombok.SneakyThrows;
import lombok.extern.java.Log;

@Log
@Service("CustomUserDetailsService")
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserConfig config;

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Utenti utente = this.getHttpValue(email);

        if (utente == null) {
            throw new UsernameNotFoundException("Utente non trovato");
        }

        return new CustomUserDetails(
                utente.getUserId(),
                utente.getEmail(),
                utente.getPassword(),
                "ROLE_" + utente.getRuolo(),
                new ArrayList<>()
        );
    }


    private Utenti getHttpValue(String email) {
        URI url = null;

        try {
            String srvUrl = config.getSrvUrl();
            url = new URI(srvUrl + "?email=" + email);
            log.info("URL creato: " + url.toString());
        } catch (URISyntaxException e) {
            log.severe("Errore nella creazione dell'URL: " + e.getMessage());
            return null;
        }

        // Mock l'oggetto
        RestTemplate restTemplate = new RestTemplate();
        // Chiama attraverso l'API di mockito
        restTemplate.getInterceptors().add(new BasicAuthenticationInterceptor(config.getUserId(), config.getPassword()));

        Utenti utente = null;

        try {
            // Esegui la richiesta HTTP e ottieni la risposta come una mappa JSON
            Map<String, Object> response = restTemplate.getForObject(url, Map.class);
            log.info("Risposta ricevuta dal servizio: " + response);

            if (response != null) {
                // Assumiamo che la risposta contenga direttamente i dati dell'utente
                utente = new ObjectMapper().convertValue(response, Utenti.class);
                log.info("Utente trovato: " + (utente != null ? utente.getEmail() : "Nessun utente trovato"));
            } else {
                log.warning("Nessun utente trovato nella risposta del servizio.");
            }
        } catch (Exception e) {
            log.warning("Connessione al servizio di autenticazione non riuscita o servizio assente: " + e.getMessage());
        }

        return utente;
    }

}
