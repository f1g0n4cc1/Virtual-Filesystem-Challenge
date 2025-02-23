import os
import json
from datetime import datetime
from Crypto.Cipher import AES
import base64
import bcrypt

class FileNode:
    def __init__(self, name, is_directory, owner="root", group="root", permissions="rwxr-xr-x", parent=None, is_symlink=False, target=None):
        self.name = name
        self.is_directory = is_directory
        self.children = {} if is_directory else None
        self.content = "" if not is_directory else None
        self.parent = parent
        self.owner = owner
        self.group = group
        self.permissions = permissions
        self.is_symlink = is_symlink  # Flag for symlinks
        self.target = target  # Points to target file/directory for symlinks

class VirtualFileSystem:
    SECRET_KEY = b"thisisaverysecurekey123456"  # 32-byte key for AES-256
    LOG_FILE = "vfs.log"
    SAVE_FILE = "filesystem_state.json"
    DEFAULT_USER_QUOTA = 1024 * 1024  # 1 MB per user
    DEFAULT_GROUP_QUOTA = 5 * 1024 * 1024  # 5 MB per group
    ROLES = {
        "admin": {"read": True, "write": True, "execute": True, "manage_users": True},
        "editor": {"read": True, "write": True, "execute": False, "manage_users": False},
        "viewer": {"read": True, "write": False, "execute": False, "manage_users": False}
    }

    def __init__(self):
        self.root = FileNode("/", True, owner="root", group="root")
        self.current_directory = self.root
        self.users = {"root": {"password": self.hash_password("admin"), "groups": ["root"], "role": "admin", "quota": self.DEFAULT_USER_QUOTA}}
        self.groups = {"root": self.DEFAULT_GROUP_QUOTA}
        self.versions = {}  # Stores file history
        self.current_user = "root"
        self.load_state()  # Load saved state when starting the program

    def hash_password(self, password):
        """ Hashes a password using bcrypt """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def verify_password(self, stored_password, provided_password):
        """ Verifies a password """
        return bcrypt.checkpw(provided_password.encode(), stored_password)

    def pad(self, data):
        """ Pads data for AES encryption """
        return data + (16 - len(data) % 16) * b" "

    def encrypt(self, plaintext):
        """ Encrypts data using AES-256 """
        cipher = AES.new(self.SECRET_KEY, AES.MODE_ECB)
        return base64.b64encode(cipher.encrypt(self.pad(plaintext.encode()))).decode()

    def decrypt(self, encrypted_text):
        """ Decrypts AES-256 encrypted data """
        cipher = AES.new(self.SECRET_KEY, AES.MODE_ECB)
        return cipher.decrypt(base64.b64decode(encrypted_text)).decode().strip()

    def log_action(self, action):
        """ Logs actions with a timestamp """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {self.current_user}: {action}\n"
        
        with open(self.LOG_FILE, "a") as log:
            log.write(log_entry)

    def _resolve_path(self, path):
        """ Resolve relative paths to absolute paths """
        if path.startswith('/'):
            return path  # Already absolute
        if self.current_directory.name == '/':
            return '/' + path
        return self.current_directory.name.rstrip('/') + '/' + path

    def ln_s(self, target, link_name):
        """ Create a symbolic link (ln -s) """
        target_path = self._resolve_path(target)
        link_path = self._resolve_path(link_name)
        
        if link_path in self.current_directory.children:
            print(f"Error: '{link_name}' already exists.")
            return
        if target_path not in self.current_directory.children:
            print(f"Error: Target '{target}' does not exist.")
            return
        # Create symlink node pointing to the target
        self.current_directory.children[link_name] = FileNode(link_name, False, owner=self.current_user, is_symlink=True, target=target_path)
        self.log_action(f"Created symlink '{link_name}' -> '{target}'")

    def read_file(self, filename):
        """ Read a file's content if the user has permission """
        path = self._resolve_path(filename)
        if path not in self.current_directory.children:
            print(f"Error: File '{filename}' does not exist.")
            return

        node = self.current_directory.children[path]
        if node.is_symlink:
            node = self.current_directory.children[node.target]  # Follow symlink

        if node.is_directory:
            print("Error: Cannot read a directory!")
            return

        if not self.has_permission(node, "r"):
            print(f"Permission denied: Cannot read '{filename}'.")
            return

        print(node.content)

    def write_file(self, filename, content):
        """ Write to a file if the user has permission """
        path = self._resolve_path(filename)
        if path not in self.current_directory.children:
            print(f"Error: File '{filename}' does not exist.")
            return

        node = self.current_directory.children[path]
        if node.is_symlink:
            node = self.current_directory.children[node.target]  # Follow symlink

        if node.is_directory:
            print("Error: Cannot write to a directory!")
            return

        if not self.has_permission(node, "w"):
            print(f"Permission denied: Cannot write to '{filename}'.")
            return

        node.content = content
        self.log_action(f"Wrote to file '{filename}'")
        print(f"File '{filename}' updated.")

    def mkdir(self, dirname):
        """ Create a new directory inside the current directory """
        path = self._resolve_path(dirname)
        if path in self.current_directory.children:
            print(f"Error: Directory '{dirname}' already exists.")
            return
        self.current_directory.children[dirname] = FileNode(dirname, True, owner=self.current_user)
        self.log_action(f"Created directory '{dirname}'")
        print(f"Directory '{dirname}' created.")

    def ls(self, path=None):
        """ List files and directories in the current directory """
        path = self._resolve_path(path or self.current_directory.name)
        if path not in self.current_directory.children:
            print(f"Error: Directory '{path}' does not exist.")
            return
        node = self.current_directory.children[path]
        if node.is_directory:
            print(" ".join(node.children.keys()))
        else:
            print(f"{path} is a file, not a directory!")

    def cd(self, dirname):
        """ Change the current directory """
        path = self._resolve_path(dirname)
        if path == "..":
            if self.current_directory.parent:
                self.current_directory = self.current_directory.parent
            else:
                print("Error: Already at the root directory.")
            return
        if path not in self.current_directory.children:
            print(f"Error: Directory '{dirname}' does not exist.")
            return
        node = self.current_directory.children[path]
        if not node.is_directory:
            print(f"Error: '{dirname}' is a file, not a directory!")
            return
        self.current_directory = node
        print(f"Changed directory to '{dirname}'")

    def rm(self, filename):
        """ Remove a file """
        path = self._resolve_path(filename)
        if path not in self.current_directory.children:
            print(f"Error: File '{filename}' does not exist.")
            return
        del self.current_directory.children[path]
        self.log_action(f"Removed file '{filename}'")
        print(f"File '{filename}' removed.")

    def mv(self, src, dest):
        """ Move or rename a file """
        src_path = self._resolve_path(src)
        dest_path = self._resolve_path(dest)
        if src_path not in self.current_directory.children:
            print(f"Error: Source '{src}' does not exist.")
            return
        if dest_path in self.current_directory.children:
            print(f"Error: Destination '{dest}' already exists.")
            return
        self.current_directory.children[dest_path] = self.current_directory.children.pop(src_path)
        self.log_action(f"Moved '{src}' to '{dest}'")
        print(f"Moved '{src}' to '{dest}'")

    def cp(self, src, dest):
        """ Copy a file """
        src_path = self._resolve_path(src)
        dest_path = self._resolve_path(dest)
        if src_path not in self.current_directory.children:
            print(f"Error: Source '{src}' does not exist.")
            return
        if dest_path in self.current_directory.children:
            print(f"Error: Destination '{dest}' already exists.")
            return
        node = self.current_directory.children[src_path]
        if node.is_directory:
            print("Error: Cannot copy a directory!")
            return
        self.current_directory.children[dest_path] = FileNode(dest, False, owner=self.current_user, content=node.content)
        self.log_action(f"Copied '{src}' to '{dest}'")
        print(f"Copied '{src}' to '{dest}'")

    def find(self, name, search_content=False, exact_match=False, case_insensitive=False):
        """ Find a file by name or content """
        results = []
        name_to_search = name.lower() if case_insensitive else name
        
        def search(node, name):
            if node.is_symlink:
                node = self.current_directory.children[node.target]  # Follow symlink
            if node.is_directory:
                for child_name, child_node in node.children.items():
                    search(child_node, name)
            else:
                node_name = child_name.lower() if case_insensitive else child_name
                node_content = node.content.lower() if case_insensitive else node.content
                if exact_match:
                    if name_to_search == node_name or (search_content and name_to_search == node_content):
                        results.append(node.name)
                else:
                    if name_to_search in node_name or (search_content and name_to_search in node_content):
                        results.append(node.name)

        search(self.current_directory, name)
        return results

    def has_permission(self, node, permission_type):
        """ Checks if the current user has the requested permission """
        if self.current_user == "root":
            return True  # Root always has full access

        owner_perms = node.permissions[:3]  # Owner permissions
        group_perms = node.permissions[3:6]  # Group permissions
        other_perms = node.permissions[6:]  # Other permissions

        user_groups = self.users[self.current_user]["groups"]

        if self.current_user == node.owner:
            perms = owner_perms
        elif node.group in user_groups:
            perms = group_perms
        else:
            perms = other_perms

        return permission_type in perms

    def chmod(self, filename, permission_change):
        """ Modifies the permissions of a file (supports group modifications) """
        path = self._resolve_path(filename)
        if path not in self.current_directory.children:
            print(f"Error: File '{filename}' does not exist.")
            return

        node = self.current_directory.children[path]

        if self.current_user != node.owner and self.current_user != "root":
            print(f"Permission denied: Cannot modify '{filename}' permissions.")
            return

        if permission_change.startswith("g+"):
            node.permissions = node.permissions[:3] + "rwx" + node.permissions[6:]
            print(f"Granted full group permissions to '{filename}'")

        elif permission_change.startswith("g-"):
            node.permissions = node.permissions[:3] + "---" + node.permissions[6:]
            print(f"Removed all group permissions from '{filename}'")

        else:
            print("Invalid permission format. Use 'g+w' or 'g-r'.")

    def chown(self, filename, new_owner):
        """ Changes the owner of a file (only root or the current owner can do this) """
        path = self._resolve_path(filename)
        if path not in self.current_directory.children:
            print(f"Error: File '{filename}' does not exist.")
            return

        node = self.current_directory.children[path]

        if self.current_user != node.owner and self.current_user != "root":
            print(f"Permission denied: Cannot change ownership of '{filename}'.")
            return

        if new_owner not in self.users:
            print(f"Error: User '{new_owner}' does not exist.")
            return

        node.owner = new_owner
        print(f"Ownership of '{filename}' changed to '{new_owner}'.")

    def chgrp(self, filename, new_group):
        """ Changes the group ownership of a file (only root or the owner can do this) """
        path = self._resolve_path(filename)
        if path not in self.current_directory.children:
            print(f"Error: File '{filename}' does not exist.")
            return

        node = self.current_directory.children[path]

        if self.current_user != node.owner and self.current_user != "root":
            print(f"Permission denied: Cannot change group of '{filename}'.")
            return

        for user in self.users:
            if new_group in self.users[user]["groups"]:
                node.group = new_group
                print(f"Group of '{filename}' changed to '{new_group}'.")
                return

        print(f"Error: Group '{new_group}' does not exist.")

    def save_state(self):
        """ Saves the filesystem and user data to a JSON file """
        data = {
            "users": {user: {"password": self.users[user]["password"].decode(), "groups": self.users[user]["groups"], "role": self.users[user]["role"], "quota": self.users[user]["quota"]}
                      for user in self.users},
            "files": self.serialize_files(self.root)
        }
        with open(self.SAVE_FILE, "w") as f:
            json.dump(data, f, indent=4)
        print("Filesystem state saved.")

    def load_state(self):
        """ Loads the filesystem and user data from a JSON file """
        if not os.path.exists(self.SAVE_FILE):
            return  # No saved data yet

        with open(self.SAVE_FILE, "r") as f:
            data = json.load(f)

        self.users = {user: {"password": data["users"][user]["password"].encode(), "groups": data["users"][user]["groups"], "role": data["users"][user]["role"], "quota": data["users"][user]["quota"]}
                      for user in data["users"]}
        self.root = self.deserialize_files(data["files"])
        print("Filesystem state loaded.")

    def serialize_files(self, node):
        """ Recursively serialize the filesystem """
        return {
            "name": node.name,
            "is_directory": node.is_directory,
            "owner": node.owner,
            "group": node.group,
            "permissions": node.permissions,
            "content": node.content if not node.is_directory else None,
            "children": {name: self.serialize_files(child) for name, child in node.children.items()} if node.is_directory else None,
            "is_symlink": node.is_symlink,
            "target": node.target
        }

    def deserialize_files(self, data):
        """ Recursively deserialize the filesystem """
        node = FileNode(data["name"], data["is_directory"], data["owner"], data["group"], data["permissions"], is_symlink=data.get("is_symlink", False), target=data.get("target"))
        if data["is_directory"]:
            node.children = {name: self.deserialize_files(child) for name, child in data["children"].items()}
        else:
            node.content = data.get("content", "")
        return node

# Example CLI for testing
def main():
    vfs = VirtualFileSystem()

    while True:
        command = input("VFS> ").strip().split()
        if not command:
            continue

        cmd = command[0]
        args = command[1:]

        if cmd == "mkdir" and args:
            vfs.mkdir(args[0])
        elif cmd == "ls":
            print(vfs.ls(args[0] if args else None))
        elif cmd == "touch" and args:
            vfs.touch(args[0])
        elif cmd == "write" and len(args) >= 2:
            filename = args[0]
            content = " ".join(args[1:])
            vfs.write_file(filename, content)
        elif cmd == "cat" and args:
            vfs.read_file(args[0])
        elif cmd == "cd" and args:
            vfs.cd(args[0])
        elif cmd == "rm" and args:
            vfs.rm(args[0])
        elif cmd == "mv" and len(args) == 2:
            vfs.mv(args[0], args[1])
        elif cmd == "cp" and len(args) == 2:
            vfs.cp(args[0], args[1])
        elif cmd == "ln_s" and len(args) == 2:
            vfs.ln_s(args[0], args[1])
        elif cmd == "find" and args:
            search_content = '--content' in args
            exact_match = '--exact' in args
            case_insensitive = '--case-insensitive' in args
            name = args[0]
            results = vfs.find(name, search_content=search_content, exact_match=exact_match, case_insensitive=case_insensitive)
            print(results)
        elif cmd == "exit":
            print("Exiting Virtual Filesystem.")
            vfs.save_state()
            break
        else:
            print("Invalid command!")

if __name__ == "__main__":
    main()