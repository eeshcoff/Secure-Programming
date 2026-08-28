# -----------------------------
# Role-Based Access - App
# -----------------------------
 

current_user = {
    "username": "emily",
    "role": "admin"   # change this to "user" or "admin" to see access change
}
 

ROLES = {
    "admin": {"view_all_users", "manage_roles"},
    "user":  {"view_own_profile"},
}
 
 
def has_permission(user, permission):
    return permission in ROLES.get(user["role"], set())
 
 
# -----------------------------
# Protected actions
# -----------------------------
 
def admin_dashboard(user):
    if not has_permission(user, "manage_roles"):
        print(f"Access denied: '{user['username']}' is not an admin.")
        return
    print(f"[Admin Dashboard] Welcome, {user['username']}. You can manage roles.")
 
 
def user_profile(user):
    if not has_permission(user, "view_own_profile"):
        print(f"Access denied: '{user['username']}' cannot view a profile.")
        return
    print(f"[User Profile] Welcome, {user['username']}. This is your profile.")
 
 
# -----------------------------
# Run
# -----------------------------
 
if __name__ == "__main__":
    print(f"Logged in as '{current_user['username']}' ({current_user['role']})\n")
    admin_dashboard(current_user)
    user_profile(current_user)