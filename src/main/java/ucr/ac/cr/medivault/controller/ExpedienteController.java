package ucr.ac.cr.medivault.controller;

import jakarta.validation.Valid;
import org.springframework.http.*;
import org.springframework.security.core.*;
import org.springframework.web.bind.annotation.*;
import ucr.ac.cr.medivault.business.ExpedienteService;
import ucr.ac.cr.medivault.controller.dto.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/expedientes")
public class ExpedienteController {

    private final ExpedienteService expService;

    public ExpedienteController(
            ExpedienteService expService) {
        this.expService = expService;
    }

    @GetMapping("/{id}")
    public ResponseEntity<ExpedienteResponseDto>
            obtenerPorId(
                @PathVariable("id") Long id,
                Authentication auth) {
        String user = auth.getName();
        return ResponseEntity.ok(
            expService.consultarPorId(id, user)
        );
    }

    @GetMapping("/mis-expedientes")
    public ResponseEntity<
            List<ExpedienteResponseDto>>
            obtenerMisExpedientes(
                Authentication auth) {
        String user = auth.getName();
        return ResponseEntity.ok(
            expService.listarExpedientesPropios(user)
        );
    }

    @PostMapping
    public ResponseEntity<ExpedienteResponseDto>
            crearExpediente(
                @Valid @RequestBody
                ExpedienteRequestDto req,
                Authentication auth) {
        String doc = auth.getName();
        ExpedienteResponseDto creado =
            expService.registrarExpediente(req, doc);
        return ResponseEntity.status(
            HttpStatus.CREATED
        ).body(creado);
    }

    @PatchMapping("/{id}/notas")
    public ResponseEntity<Void> actualizarNotas(
            @PathVariable("id") Long id,
            @RequestBody String nuevasNotas,
            Authentication auth) {
        String doc = auth.getName();
        expService.actualizarNotasDefensivo(
            id, nuevasNotas, doc
        );
        return ResponseEntity.noContent().build();
    }
}
