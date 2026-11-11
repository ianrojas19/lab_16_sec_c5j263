package ucr.ac.cr.medivault.business;

import org.springframework.beans.factory.annotation
    .Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation
    .Transactional;
import ucr.ac.cr.medivault.controller.dto.*;
import ucr.ac.cr.medivault.data.*;
import ucr.ac.cr.medivault.domain.*;
import ucr.ac.cr.medivault.exception.*;

import java.util.List;

@Service
public class ExpedienteService {

    private final ExpedienteMedicoRepository expRepo;
    private final UsuarioRepository userRepo;
    private SecurityAuditorService auditorService;

    public ExpedienteService(
            ExpedienteMedicoRepository expRepo,
            UsuarioRepository userRepo) {
        this.expRepo = expRepo;
        this.userRepo = userRepo;
    }

    @Autowired(required = false)
    public void setAuditorService(
            SecurityAuditorService auditorService) {
        this.auditorService = auditorService;
    }

    @Transactional(readOnly = true)
    public ExpedienteResponseDto consultarPorId(
            Long expedienteId,
            String currentUsername) {
        ExpedienteMedico exp = expRepo
            .findByIdWithDetails(expedienteId)
            .orElseThrow(() ->
                new ResourceNotFoundException(
                    "Expediente no existe: " +
                    expedienteId));

        Usuario solicitante = userRepo
            .findByUsername(currentUsername)
            .orElseThrow(() -> {
                registrarIdor(currentUsername,
                    expedienteId,
                    "Usuario no reconocido.");
                return new AccessDeniedSecurityException(
                    "Usuario no reconocido.");
            });

        // Verificacion de Propiedad (IDOR / BOLA)
        validarPropiedadRecurso(exp, solicitante);

        return mapToResponseDto(exp);
    }

    @Transactional(readOnly = true)
    public List<ExpedienteResponseDto>
            listarExpedientesPropios(
                String currentUsername) {
        Usuario solicitante = userRepo
            .findByUsername(currentUsername)
            .orElseThrow(() -> {
                registrarIdor(currentUsername, null,
                    "Usuario no reconocido.");
                return new AccessDeniedSecurityException(
                    "Usuario no reconocido.");
            });

        return expRepo
            .findByPacienteId(solicitante.getId())
            .stream()
            .map(this::mapToResponseDto)
            .toList();
    }

    @Transactional
    public ExpedienteResponseDto registrarExpediente(
            ExpedienteRequestDto dto,
            String doctorUsername) {
        Usuario doc = userRepo
            .findByUsername(doctorUsername)
            .orElseThrow(() -> {
                registrarIdor(doctorUsername, null,
                    "Doctor no registrado.");
                return new AccessDeniedSecurityException(
                    "Doctor no registrado.");
            });

        if (doc.getRol() != Rol.ROLE_DOCTOR &&
            doc.getRol() != Rol.ROLE_ADMIN) {
            String msg = "Solo medicos autorizados " +
                "pueden registrar expedientes.";
            registrarIdor(doctorUsername, null, msg);
            throw new AccessDeniedSecurityException(msg);
        }

        Usuario pac = userRepo
            .findById(dto.pacienteId())
            .orElseThrow(() ->
                new ResourceNotFoundException(
                    "Paciente no existe: " +
                    dto.pacienteId()));

        ExpedienteMedico e = new ExpedienteMedico();
        e.setPaciente(pac);
        e.setMedicoAsignado(doc);
        e.setCodigoExpediente(dto.codigoExpediente());
        e.setDiagnosticoPrincipal(
            dto.diagnosticoPrincipal());
        e.setNotasClinicas(dto.notasClinicas());
        e.setNivelConfidencialidad(
            dto.nivelConfidencialidad());

        ExpedienteMedico guardado = expRepo.save(e);
        return mapToResponseDto(guardado);
    }

    @Transactional
    public void actualizarNotasDefensivo(
            Long expedienteId,
            String nuevasNotas,
            String currentDoctorUsername) {
        ExpedienteMedico exp = expRepo
            .findByIdWithDetails(expedienteId)
            .orElseThrow(() ->
                new ResourceNotFoundException(
                    "Expediente no encontrado"));

        Usuario doc = userRepo
            .findByUsername(currentDoctorUsername)
            .orElseThrow(() -> {
                registrarIdor(currentDoctorUsername,
                    expedienteId, "Doctor no valido");
                return new AccessDeniedSecurityException(
                    "Doctor no valido");
            });

        if (doc.getRol() != Rol.ROLE_DOCTOR ||
            !exp.getMedicoAsignado().getId()
                .equals(doc.getId())) {
            String msg = "Solo el medico asignado puede " +
                "actualizar las notas.";
            registrarIdor(currentDoctorUsername,
                expedienteId, msg);
            throw new AccessDeniedSecurityException(msg);
        }

        if (nuevasNotas == null ||
            nuevasNotas.trim().length() < 10) {
            throw new IllegalArgumentException(
                "Notas: minimo 10 caracteres.");
        }

        exp.setNotasClinicas(nuevasNotas.trim());
        expRepo.save(exp);
    }

    /**
     * Regla Defensiva de Control de Acceso
     */
    private void validarPropiedadRecurso(
            ExpedienteMedico exp,
            Usuario solicitante) {
        // Regla A: Administrador auditor
        if (solicitante.getRol() == Rol.ROLE_ADMIN) {
            return;
        }

        // Regla B: Paciente dueno del expediente
        if (solicitante.getRol() ==
                Rol.ROLE_PACIENTE) {
            if (!exp.getPaciente().getId()
                    .equals(solicitante.getId())) {
                String msg =
                    "Violacion IDOR: Sin acceso.";
                registrarIdor(
                    solicitante.getUsername(),
                    exp.getId(), msg);
                throw new
                    AccessDeniedSecurityException(msg);
            }
            return;
        }

        // Regla C: Medico asignado al expediente
        if (solicitante.getRol() == Rol.ROLE_DOCTOR) {
            if (!exp.getMedicoAsignado().getId()
                    .equals(solicitante.getId())) {
                String msg =
                    "Violacion BOLA: No asignado.";
                registrarIdor(
                    solicitante.getUsername(),
                    exp.getId(), msg);
                throw new
                    AccessDeniedSecurityException(msg);
            }
        }
    }

    private void registrarIdor(
            String username,
            Long expedienteId,
            String detalle) {
        if (auditorService != null) {
            String recurso = expedienteId != null
                ? "/api/v1/expedientes/" + expedienteId
                : "/api/v1/expedientes";
            auditorService.registrarIntentoIdor(
                username, null, recurso, detalle);
        }
    }

    private ExpedienteResponseDto mapToResponseDto(
            ExpedienteMedico e) {
        return new ExpedienteResponseDto(
            e.getId(),
            e.getCodigoExpediente(),
            e.getPaciente().getNombreCompleto(),
            e.getMedicoAsignado()
                .getNombreCompleto(),
            e.getDiagnosticoPrincipal(),
            e.getNotasClinicas(),
            e.getNivelConfidencialidad(),
            e.getFechaRegistro()
        );
    }
}

