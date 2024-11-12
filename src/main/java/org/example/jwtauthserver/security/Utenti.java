package org.example.jwtauthserver.security;

import java.util.List;

import lombok.Data;

@Data
public class Utenti
{
    private Long userId;
    private String nome;
    private String cognome;
    private String email;
    private String telefono;
    private String password;
    private String dataNascita;
    private Integer ruolo;
    private List<Long> prenotazioniIds;
    private String attivo;
}
