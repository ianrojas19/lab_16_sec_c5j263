package ucr.ac.cr.medivault.data;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ucr.ac.cr.medivault.domain.AuditLog;

import java.util.List;

@Repository
public interface AuditLogRepository
        extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByAccionOrderByFechaEventoDesc(
            String accion);

    List<AuditLog> findAllByOrderByFechaEventoDesc();
}

