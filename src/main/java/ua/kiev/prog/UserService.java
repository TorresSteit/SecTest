package ua.kiev.prog;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Transactional(readOnly = true)
    public List<CustomUser> getAllUsers() {
        return userRepository.findAll();
    }

    @Transactional(readOnly = true)
    public CustomUser findByLogin(String login) {
        return userRepository.findByLoginOrEmail(login);
    }

    @Transactional(readOnly = true)
    public CustomUser findByLoginOrEmail(String login){return  userRepository.findByLoginOrEmail(login);}

    @Transactional
    public void deleteUsers(Map<String,String> toDelete) {
        for (Map.Entry<String, String> entry : toDelete.entrySet()) {
            Optional<CustomUser> user = userRepository.findById(Long.valueOf(entry.getKey()));
            if (user.isEmpty())return;
            CustomUser customUser = user.get();
            if(!customUser.getRole().equals(UserRole.ADMIN)){
                userRepository.delete(customUser);
            }
        }
    }

    @Transactional
    public boolean addUser(String login, String passHash,
                           UserRole role, String email,
                           String phone,
                           String address) {
        if (userRepository.existsByLogin(login))
            return false;

        CustomUser user = new CustomUser(login, passHash, role, email, phone, address);
        userRepository.save(user);

        return true;
    }

    @Transactional
    public void updateUser(String login, String email, String phone) {
        CustomUser user = userRepository.findByLoginOrEmail(login);
        if (user == null)return;
        user.setEmail(email);
        user.setPhone(phone);
        userRepository.save(user);
    }

    @Transactional
    public void updateRoles(Map<String,String> updateRoles){
        for (Map.Entry<String, String> entry : updateRoles.entrySet()){
            Optional<CustomUser> user = userRepository.findById(Long.valueOf(entry.getKey()));
            if (user.isEmpty())return;
            CustomUser customUser = user.get();
            customUser.setRole(UserRole.valueOf(entry.getValue()));
            userRepository.save(customUser);
        }
    }
}
