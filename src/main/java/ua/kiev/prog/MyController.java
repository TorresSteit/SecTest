package ua.kiev.prog;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Controller
public class MyController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    public MyController(UserService userService, PasswordEncoder passwordEncoder) {
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/")
    public String index(Model model) {
        User user = getCurrentUser();

        String login = user.getUsername();
        CustomUser dbUser = userService.findByLogin(login);

        model.addAttribute("login", login);
        model.addAttribute("roles", user.getAuthorities());
        model.addAttribute("admin", isAdminOrModerator(user));
        model.addAttribute("email", dbUser.getEmail());
        model.addAttribute("phone", dbUser.getPhone());
        model.addAttribute("address", dbUser.getAddress());

        return "index";
    }

    @PostMapping(value = "/update")
    public String update(@RequestParam(required = false) String email,
                         @RequestParam(required = false) String phone) {
        User user = getCurrentUser();

        String login = user.getUsername();
        userService.updateUser(login, email, phone);

        return "redirect:/";
    }

    @PostMapping(value = "/newuser")
    public String update(@RequestParam String login,
                         @RequestParam String password,
                         @RequestParam(required = false) String email,
                         @RequestParam(required = false) String phone,
                         @RequestParam(required = false) String address,
                         Model model) {
        String passHash = passwordEncoder.encode(password);

        if ( ! userService.addUser(login, passHash, UserRole.USER, email, phone, address)) {
            model.addAttribute("exists", true);
            model.addAttribute("login", login);
            return "register";
        }

        return "redirect:/";
    }

    @PostMapping(value = "/delete")
    public String delete( Model model, @RequestBody Map<String, Object> requestData) {
        User user = getCurrentUser();
        Map<String, String> toDelete = (Map<String, String>) requestData.get("toDelete");
        userService.deleteUsers(toDelete);
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("userRoles", getRolesList());
        model.addAttribute("admin", isAdmin(user));

        return "admin";
    }

    private List<String> getRolesList() {
        return Arrays.stream(UserRole.values())
                .map(UserRole::name)
                .collect(Collectors.toList());
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String register() {
        return "register";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MODERATOR')") // SpEL !!!
    public String admin(Model model) {
        User user = getCurrentUser();
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("userRoles", getRolesList());
        model.addAttribute("admin",isAdmin(user));
        return "admin";
    }

    @PostMapping("/updateRoles")
    public String updateRoles(Model model, @RequestBody Map<String, Object> requestData) {
        User user = getCurrentUser();
        Map<String, String> userRoles = (Map<String, String>) requestData.get("userRoles");
        if(!(requestData.size() == 0)){
            userService.updateRoles(userRoles);
        }
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("userRoles", getRolesList());
        model.addAttribute("admin", isAdmin(user));
        return "admin";
    }
    @GetMapping("/unauthorized")
    public String unauthorized(Model model) {
        User user = getCurrentUser();
        model.addAttribute("login", user.getUsername());
        return "unauthorized";
    }

    // ----

    private User getCurrentUser() {
        return (User)SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();
    }

    private boolean isAdmin(User user) {
        Collection<GrantedAuthority> roles = user.getAuthorities();
        for (GrantedAuthority auth : roles) {
            if ("ROLE_ADMIN".equals(auth.getAuthority()))
                return true;
        }
        return false;
    }
    private boolean isAdminOrModerator(User user) {
        Collection<GrantedAuthority> roles = user.getAuthorities();
        for (GrantedAuthority auth : roles) {
            if (("ROLE_ADMIN".equals(auth.getAuthority()))||("ROLE_MODERATOR".equals(auth.getAuthority())))return true;
        }
        return false;
    }
}