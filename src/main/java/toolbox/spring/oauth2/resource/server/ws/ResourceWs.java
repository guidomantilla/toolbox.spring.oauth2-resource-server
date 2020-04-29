package toolbox.spring.oauth2.resource.server.ws;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import toolbox.spring.oauth2.resource.server.model.CustomPrincipal;

@RestController
public class ResourceWs {

    @GetMapping("/admins")
    @PreAuthorize("hasAuthority('role_admin')")
    public String context() {
        CustomPrincipal principal = (CustomPrincipal) SecurityContextHolder.getContext().getAuthentication()
                .getPrincipal();
        return "Admin: "+principal.getUsername() + " " + principal.getEmail();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyAuthority('role_admin','role_user')")
    public String secured(CustomPrincipal principal) {
        return "Authorized User: "+principal.getUsername() + " " + principal.getEmail();
    }

    @GetMapping("/common")
    public String general() {
        return "common api success";
    }
}
