package org.example.jwtauthserver.tests.ServiceTests;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;
import java.util.HashMap;
import java.util.Map;
import org.example.jwtauthserver.security.CustomUserDetailsService;
import org.example.jwtauthserver.security.UserConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.client.RestTemplate;

public class CustomUserDetailsServiceTest {

    //Creo l'istanza della classe ed inietto i Mock creati
    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    @Mock
    private UserConfig userConfig;

    //Crea un'istanza simulata
    @Mock
    private RestTemplate restTemplate;


    //Non mi servono
    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        when(userConfig.getSrvUrl()).thenReturn("http://localhost:8090/auth/cerca/email");
        when(userConfig.getUserId()).thenReturn("Prova");
        when(userConfig.getPassword()).thenReturn("123");
    }


    @Test
    public void loadUserByUsername() {
        String email = "ilenia@live.it";

        // Risposta fake dal Mock
        Map<String, Object> userMap = new HashMap<>();
        userMap.put("userId", 5L);
        userMap.put("email", email);
        userMap.put("password", "hashedpassword");
        userMap.put("ruolo", 2);

        Map<String, Object> response = new HashMap<>();
        response.put("user", userMap);

        //Simulo la riposta
        when(restTemplate.getForObject(any(), eq(Map.class))).thenReturn(response);

        // Test del metodo
        assertNotNull(customUserDetailsService.loadUserByUsername(email));
    }

    @Test
    public void loadUserByUsername_UserNotFound_ThrowsUsernameNotFoundException() {
        String email = "nonexistent@example.com";

        // Mock vuoto
        when(restTemplate.getForObject(any(), eq(Map.class))).thenReturn(null);

        assertThrows(UsernameNotFoundException.class, () -> {
            customUserDetailsService.loadUserByUsername(email);
        });
    }
}


// @Bean, @Component e @Service sono sostanzialmente simili. Informano Spring che dovrebbe gestire questi oggetti come singleton nel suo contesto.
//
//@Autowired è il modo in cui si dice a Spring di utilizzare un bean o un componente all'interno di un altro. Ad esempio, se si avesse un FooService
// contrassegnato con @Bean e avesse bisogno di un FooRepository per funzionare, si annoterebbe il FooRepository come @Repository nella sua definizione
// di classe e si marcherebbe la variabile di istanza in FooService come @Autowired. Questo farebbe sì che Spring istanzi un FooService Singleton e inietterebbe
// (imposterà) automaticamente il proxy Spring per il FooRepository.