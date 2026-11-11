package ucr.ac.cr.medivault.controller;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import ucr.ac.cr.medivault.business.AuthService;
import ucr.ac.cr.medivault.controller.dto.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDto> login(
            @Valid @RequestBody LoginRequestDto req) {
        return ResponseEntity.ok(
            authService.autenticar(req)
        );
    }

    @RequestMapping(
        value = "/login",
        method = RequestMethod.HEAD)
    public ResponseEntity<Void> inspectHeaders() {
        return ResponseEntity.ok().build();
    }
}
