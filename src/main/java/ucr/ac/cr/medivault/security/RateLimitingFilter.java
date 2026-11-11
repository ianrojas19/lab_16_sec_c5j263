package ucr.ac.cr.medivault.security;

import io.github.bucket4j.*;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter
    .OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimitingFilter
        extends OncePerRequestFilter {

    private final Map<String, Bucket> authBuckets =
        new ConcurrentHashMap<>();

    private final Map<String, Bucket> apiBuckets =
        new ConcurrentHashMap<>();

    private Bucket createAuthBucket(String ip) {
        return Bucket.builder()
            .addLimit(Bandwidth.classic(5,
                Refill.intervally(5,
                    Duration.ofMinutes(1))))
            .build();
    }

    private Bucket createApiBucket(String ip) {
        return Bucket.builder()
            .addLimit(Bandwidth.classic(30,
                Refill.intervally(30,
                    Duration.ofMinutes(1))))
            .build();
    }

    public String extractClientIp(
            HttpServletRequest request) {
        String xff = request.getHeader(
            "X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public void resetBuckets() {
        authBuckets.clear();
        apiBuckets.clear();
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();
        String clientIp = extractClientIp(request);
        Bucket target = null;

        if (path.startsWith("/api/v1/auth/login") &&
                !"HEAD".equalsIgnoreCase(method)) {
            target = authBuckets.computeIfAbsent(
                clientIp, this::createAuthBucket);
        } else if (path.startsWith(
                "/api/v1/expedientes")) {
            target = apiBuckets.computeIfAbsent(
                clientIp, this::createApiBucket);
        }

        if (target != null) {
            if (target.tryConsume(1)) {
                filterChain.doFilter(
                    request, response);
            } else {
                // Rate Limit superado: HTTP 429
                response.setStatus(
                    HttpStatus
                        .TOO_MANY_REQUESTS.value()
                );
                response.setContentType(
                    MediaType
                        .APPLICATION_PROBLEM_JSON_VALUE
                );
                response.setHeader(
                    "Retry-After", "60");

                String json = """
                        {
                          "type": "%s",
                          "title": "%s",
                          "status": 429,
                          "detail": "%s",
                          "instance": "%s"
                        }
                        """.formatted(
                        "https://medivault.cr/rl",
                        "Demasiadas Peticiones",
                        "Limite superado. Espere 60s.",
                        path
                );

                response.getWriter().write(json);
            }
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
