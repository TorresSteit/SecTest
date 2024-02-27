package ua.kiev.prog;

public enum UserRole {
    ADMIN, MODERATOR, USER;

    @Override
    public String toString() {
        return "ROLE_" + name();
    }
}
