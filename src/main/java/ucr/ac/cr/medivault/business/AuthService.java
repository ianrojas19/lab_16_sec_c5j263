package ucr.ac.cr.medivault.business;

import org.springframework.beans.factory.annotation
    .Autowired;
import org.springframework.security.authentication
    .BadCredentialsException;
import org.springframework.security.crypto.password
    .PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation
    .Transactional;
import ucr.ac.cr.medivault.controller.dto.*;
import ucr.ac.cr.medivault.data.UsuarioRepository;
import ucr.ac.cr.medivault.domain.Usuario;
import ucr.ac.cr.medivault.security.JwtTokenProvider;

@Service
public class AuthService {

    private final UsuarioRepository userRepo;
    private final PasswordEncoder encoder;
    private final JwtTokenProvider jwtProvider;
    private SecurityAuditorService auditorService;

    public AuthService(UsuarioRepository userRepo,
                       PasswordEncoder encoder,
                       JwtTokenProvider jwtProvider) {
        this.userRepo = userRepo;
        this.encoder = encoder;
        this.jwtProvider = jwtProvider;
    }

    @Autowired(required = false)
    public void setAuditorService(
            SecurityAuditorService auditorService) {
        this.auditorService = auditorService;
    }

    @Transactional(readOnly = true)
    public LoginResponseDto autenticar(
            LoginRequestDto request) {
        Usuario u = userRepo
            .findByUsername(request.username())
            .orElseThrow(() -> {
                registrarFallo(request.username(),
                    "Credenciales invalidas.");
                return new BadCredentialsException(
                    "Credenciales invalidas.");
            });

        if (!encoder.matches(request.password(),
                             u.getPasswordHash())) {
            registrarFallo(request.username(),
                "Credenciales invalidas.");
            throw new BadCredentialsException(
                "Credenciales invalidas.");
        }

        if (!"ACTIVO".equals(u.getEstado())) {
            registrarFallo(request.username(),
                "Cuenta inactiva o bloqueada.");
            throw new BadCredentialsException(
                "Cuenta inactiva o bloqueada.");
        }

        String token = jwtProvider.generateToken(
            u.getUsername(),
            u.getRol().name());

        return new LoginResponseDto(
            token,
            "Bearer",
            3600000,
            u.getUsername(),
            u.getRol().name()
        );
    }

    private void registrarFallo(
            String username, String detalle) {
        if (auditorService != null) {
            auditorService.registrarFalloAutenticacion(
                username, null,
                "/api/v1/auth/login", detalle);
        }
    }
}

