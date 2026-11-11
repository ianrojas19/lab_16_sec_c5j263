package ucr.ac.cr.medivault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import ucr.ac.cr.medivault.data.AuditLogRepository;
import ucr.ac.cr.medivault.domain.AuditLog;
import ucr.ac.cr.medivault.security.RateLimitingFilter;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class MedivaultSecurityTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RateLimitingFilter rateLimitingFilter;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void setUp() {
        rateLimitingFilter.resetBuckets();
    }

    private String loginAndGetToken(String username, String password, String ip) throws Exception {
        String body = """
                {
                  "username": "%s",
                  "password": "%s"
                }
                """.formatted(username, password);

        MvcResult res = mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", ip)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode node = objectMapper.readTree(res.getResponse().getContentAsString());
        return node.get("token").asText();
    }

    @Test
    void prueba1y2_autenticacionExitosaYCabecerasDefensivas() throws Exception {
        String body = """
                {
                  "username": "paciente_carlos",
                  "password": "Password123!"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", "10.0.0.10")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("Content-Security-Policy",
                        "default-src 'self'; frame-ancestors 'none'; object-src 'none';"))
                .andExpect(header().exists("Strict-Transport-Security"))
                .andExpect(header().exists("Cache-Control"))
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.username").value("paciente_carlos"))
                .andExpect(jsonPath("$.rol").value("ROLE_PACIENTE"));

        mockMvc.perform(head("/api/v1/auth/login"))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().exists("Strict-Transport-Security"))
                .andExpect(header().exists("Content-Security-Policy"));
    }

    @Test
    void prueba3_consultaLegitimaDeExpedientePropioYRolesAutorizados() throws Exception {
        String tokenCarlos = loginAndGetToken("paciente_carlos", "Password123!", "10.0.0.11");
        String tokenDoctorSmith = loginAndGetToken("doctor_smith", "Password123!", "10.0.0.12");
        String tokenAdmin = loginAndGetToken("admin_root", "Password123!", "10.0.0.13");

        mockMvc.perform(get("/api/v1/expedientes/101")
                        .header("X-Forwarded-For", "10.0.0.11")
                        .header("Authorization", "Bearer " + tokenCarlos))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(101))
                .andExpect(jsonPath("$.codigoExpediente").value("EXP-2026-001"))
                .andExpect(jsonPath("$.pacienteNombre").value("Carlos Mora Jimenez"));

        mockMvc.perform(get("/api/v1/expedientes/mis-expedientes")
                        .header("X-Forwarded-For", "10.0.0.11")
                        .header("Authorization", "Bearer " + tokenCarlos))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(101));

        mockMvc.perform(get("/api/v1/expedientes/101")
                        .header("X-Forwarded-For", "10.0.0.12")
                        .header("Authorization", "Bearer " + tokenDoctorSmith))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(101));

        mockMvc.perform(get("/api/v1/expedientes/102")
                        .header("X-Forwarded-For", "10.0.0.13")
                        .header("Authorization", "Bearer " + tokenAdmin))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(102));
    }

    @Test
    void prueba4yRetoB_bloqueoIdorBolaYRegistroAuditoria() throws Exception {
        String tokenMaria = loginAndGetToken("paciente_maria", "Password123!", "10.0.0.14");
        String tokenDoctoraVargas = loginAndGetToken("doctora_vargas", "Password123!", "10.0.0.15");

        mockMvc.perform(get("/api/v1/expedientes/101")
                        .header("X-Forwarded-For", "10.0.0.14")
                        .header("Authorization", "Bearer " + tokenMaria))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.type").value("https://medivault.ucr.ac.cr/forbidden"))
                .andExpect(jsonPath("$.title").value("Acceso Prohibido (IDOR / BOLA)"))
                .andExpect(jsonPath("$.status").value(403));

        mockMvc.perform(get("/api/v1/expedientes/101")
                        .header("X-Forwarded-For", "10.0.0.15")
                        .header("Authorization", "Bearer " + tokenDoctoraVargas))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.status").value(403));

        List<AuditLog> idorLogs = auditLogRepository
                .findByAccionOrderByFechaEventoDesc("IDOR_ATTEMPT_BLOCKED");
        assertThat(idorLogs).hasSizeGreaterThanOrEqualTo(2);

        boolean mariaRegistrada = idorLogs.stream().anyMatch(l ->
                "paciente_maria".equals(l.getUsername()) &&
                "10.0.0.14".equals(l.getIpOrigen()) &&
                l.getCodigoEstado() == 403 &&
                l.getRecursoSolicitado().contains("101") &&
                l.getFechaEvento() != null);
        assertThat(mariaRegistrada).isTrue();
    }

    @Test
    void prueba5yRetoA_rateLimitingGranularPorIpYAuditoriaLoginFailed() throws Exception {
        String badBody = """
                {
                  "username": "admin_root",
                  "password": "WrongPassword123!"
                }
                """;

        for (int i = 1; i <= 5; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                            .header("X-Forwarded-For", "192.168.1.50")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(badBody))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.title").value("Fallo de Autenticacion"));
        }

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", "192.168.1.50")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(badBody))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "60"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.title").value("Demasiadas Peticiones"));

        String validBody = """
                {
                  "username": "admin_root",
                  "password": "Password123!"
                }
                """;
        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", "192.168.1.51")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(validBody))
                .andExpect(status().isOk());

        List<AuditLog> failedLogs = auditLogRepository
                .findByAccionOrderByFechaEventoDesc("LOGIN_FAILED");
        assertThat(failedLogs).hasSizeGreaterThanOrEqualTo(5);
        AuditLog log = failedLogs.get(0);
        assertThat(log.getUsername()).isEqualTo("admin_root");
        assertThat(log.getIpOrigen()).isEqualTo("192.168.1.50");
        assertThat(log.getCodigoEstado()).isEqualTo(401);
        assertThat(log.getFechaEvento()).isNotNull();
    }

    @Test
    void parte2_actualizacionDefensivaDeNotasClinicas() throws Exception {
        String tokenDoctorSmith = loginAndGetToken("doctor_smith", "Password123!", "10.0.0.20");
        String tokenDoctoraVargas = loginAndGetToken("doctora_vargas", "Password123!", "10.0.0.21");

        mockMvc.perform(patch("/api/v1/expedientes/101/notas")
                        .header("X-Forwarded-For", "10.0.0.20")
                        .header("Authorization", "Bearer " + tokenDoctorSmith)
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("Paciente presenta evolucion favorable tras ajuste de dosis."))
                .andExpect(status().isNoContent());

        mockMvc.perform(patch("/api/v1/expedientes/101/notas")
                        .header("X-Forwarded-For", "10.0.0.21")
                        .header("Authorization", "Bearer " + tokenDoctoraVargas)
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("Intento de modificacion por medico no asignado."))
                .andExpect(status().isForbidden());

        mockMvc.perform(patch("/api/v1/expedientes/101/notas")
                        .header("X-Forwarded-For", "10.0.0.20")
                        .header("Authorization", "Bearer " + tokenDoctorSmith)
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("Corto"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400));
    }

    @Test
    void registroExpedienteValidacionDtoYRfc7807SinFugaDeStackTraces() throws Exception {
        String tokenDoctorSmith = loginAndGetToken("doctor_smith", "Password123!", "10.0.0.30");
        String tokenCarlos = loginAndGetToken("paciente_carlos", "Password123!", "10.0.0.31");

        String nuevoExpediente = """
                {
                  "pacienteId": 4,
                  "codigoExpediente": "EXP-2026-009",
                  "diagnosticoPrincipal": "Control Preventivo Anual",
                  "notasClinicas": "Signos vitales estables y parametros dentro de rangos normales.",
                  "nivelConfidencialidad": "BAJO"
                }
                """;

        mockMvc.perform(post("/api/v1/expedientes")
                        .header("X-Forwarded-For", "10.0.0.30")
                        .header("Authorization", "Bearer " + tokenDoctorSmith)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(nuevoExpediente))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.codigoExpediente").value("EXP-2026-009"));

        mockMvc.perform(post("/api/v1/expedientes")
                        .header("X-Forwarded-For", "10.0.0.31")
                        .header("Authorization", "Bearer " + tokenCarlos)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(nuevoExpediente))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/v1/expedientes/9999")
                        .header("X-Forwarded-For", "10.0.0.30")
                        .header("Authorization", "Bearer " + tokenDoctorSmith))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.title").value("Recurso No Encontrado"));

        String invalidLogin = """
                {
                  "username": "ab",
                  "password": "123"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/login")
                        .header("X-Forwarded-For", "10.0.0.32")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(invalidLogin))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.title").value("Error de Validacion"))
                .andExpect(jsonPath("$.invalid_fields").exists());

        mockMvc.perform(get("/h2-console"))
                .andExpect(status().isForbidden());
    }
}
