package ucr.ac.cr.medivault.business;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation
    .Propagation;
import org.springframework.transaction.annotation
    .Transactional;
import org.springframework.web.context.request
    .RequestContextHolder;
import org.springframework.web.context.request
    .ServletRequestAttributes;
import ucr.ac.cr.medivault.data.AuditLogRepository;
import ucr.ac.cr.medivault.domain.AuditLog;

import java.util.List;

@Service
public class SecurityAuditorService {

    private static final String AUDIT_LOGGED_ATTR =
        "MEDIVAULT_AUDIT_LOGGED";

    private final AuditLogRepository auditRepo;

    public SecurityAuditorService(
            AuditLogRepository auditRepo) {
        this.auditRepo = auditRepo;
    }

    @Transactional(
        propagation = Propagation.REQUIRES_NEW)
    public void registrarIntentoIdor(
            String username,
            String ipOrigen,
            String recursoSolicitado,
            String detalleEvento) {
        if (yaRegistradoEnRequestActual()) {
            return;
        }
        AuditLog log = new AuditLog(
            username != null && !username.isBlank()
                ? username : "ANONIMO",
            ipOrigen != null && !ipOrigen.isBlank()
                ? ipOrigen : obtenerIpActual(),
            "IDOR_ATTEMPT_BLOCKED",
            recursoSolicitado != null &&
                !recursoSolicitado.isBlank()
                ? recursoSolicitado
                : obtenerRecursoActual("/api/v1/expedientes"),
            403,
            detalleEvento
        );
        auditRepo.save(log);
        marcarRegistradoEnRequestActual();
    }

    @Transactional(
        propagation = Propagation.REQUIRES_NEW)
    public void registrarFalloAutenticacion(
            String username,
            String ipOrigen,
            String recursoSolicitado,
            String detalleEvento) {
        if (yaRegistradoEnRequestActual()) {
            return;
        }
        AuditLog log = new AuditLog(
            username != null && !username.isBlank()
                ? username : "DESCONOCIDO",
            ipOrigen != null && !ipOrigen.isBlank()
                ? ipOrigen : obtenerIpActual(),
            "LOGIN_FAILED",
            recursoSolicitado != null &&
                !recursoSolicitado.isBlank()
                ? recursoSolicitado
                : obtenerRecursoActual("/api/v1/auth/login"),
            401,
            detalleEvento
        );
        auditRepo.save(log);
        marcarRegistradoEnRequestActual();
    }

    @Transactional(readOnly = true)
    public List<AuditLog> listarEventosAuditoria() {
        return auditRepo
            .findAllByOrderByFechaEventoDesc();
    }

    public String extraerIpCliente(
            HttpServletRequest request) {
        if (request == null) {
            return "127.0.0.1";
        }
        String xff = request.getHeader(
            "X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String remoteAddr = request.getRemoteAddr();
        return (remoteAddr != null &&
                !remoteAddr.isBlank())
            ? remoteAddr : "127.0.0.1";
    }

    private String obtenerIpActual() {
        HttpServletRequest req = obtenerRequestActual();
        return extraerIpCliente(req);
    }

    private String obtenerRecursoActual(
            String porDefecto) {
        HttpServletRequest req = obtenerRequestActual();
        if (req != null &&
            req.getRequestURI() != null &&
            !req.getRequestURI().isBlank()) {
            return req.getRequestURI();
        }
        return porDefecto;
    }

    private HttpServletRequest obtenerRequestActual() {
        var attrs = RequestContextHolder
            .getRequestAttributes();
        if (attrs instanceof
                ServletRequestAttributes sra) {
            return sra.getRequest();
        }
        return null;
    }

    private boolean yaRegistradoEnRequestActual() {
        HttpServletRequest req = obtenerRequestActual();
        if (req != null) {
            return Boolean.TRUE.equals(
                req.getAttribute(AUDIT_LOGGED_ATTR));
        }
        return false;
    }

    private void marcarRegistradoEnRequestActual() {
        HttpServletRequest req = obtenerRequestActual();
        if (req != null) {
            req.setAttribute(
                AUDIT_LOGGED_ATTR, Boolean.TRUE);
        }
    }
}

