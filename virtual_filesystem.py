import os
import json
from datetime import datetime
import bcrypt
import sys
import fnmatch

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
        self.is_symlink = is_symlink
        self.target = target

class VirtualFileSystem:
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
        root_password = os.getenv("ROOT_PASSWORD", "admin")
        self.root = FileNode("/", True, owner="root", group="root")
        self.current_directory = self.root
        self.users = {"root": {"password": self.hash_password(root_password), "groups": ["root"], "role": "admin", "quota": self.DEFAULT_USER_QUOTA}}
        self.groups = {"root": self.DEFAULT_GROUP_QUOTA}
        self.versions = {}
        self.current_user = "root"

    def hash_password(self, password):
        """ Hashes a password using bcrypt """
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def verify_password(self, stored_password, provided_password):
        """ Verifies a password """
        return bcrypt.checkpw(provided_password.encode(), stored_password)

    def log_action(self, action):
        """ Logs actions with a timestamp """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {self.current_user}: {action}\n"
        
        # Log to file
        with open(self.LOG_FILE, "a") as log_file:
            log_file.write(log_entry)
        
        # Log to in-memory log
        if not hasattr(self, 'logs'):
            self.logs = []
        self.logs.append(log_entry)

    def _resolve_path(self, path):
        """ Resolve relative paths to absolute paths """
        if path.startswith('/'):
            # Absolute path
            return path
        
        # Split the path into parts
        parts = path.split('/')
        
        # Start from the current directory
        if self.current_directory.name == '/':
            stack = []
        else:
            stack = self.current_directory.name.strip('/').split('/')
        
        # Process each part of the path
        for part in parts:
            if part == '..':
                # Move up to the parent directory
                if stack:
                    stack.pop()
            elif part and part != '.':
                # Add the directory or file to the stack
                stack.append(part)
        
        # Join the stack to form the absolute path
        return '/' + '/'.join(stack)

    def _follow_symlink(self, node):
        """ Follow symlink to the target node """
        while node.is_symlink:
            target = node.target
            parts = target.strip('/').split('/')
            current = self.root
            for part in parts:
                if part in current.children:
                    current = current.children[part]
                else:
                    print(f"Error: Symlink target '{target}' does not exist.")
                    return None
            node = current
        return node

    def _get_node(self, path):
        """ Helper function to get the node from the path """
        if path == '/':
            return self.root
        
        # Resolve the path to an absolute path
        abs_path = self._resolve_path(path)
        parts = abs_path.strip('/').split('/')
        
        # Traverse the filesystem hierarchy
        current = self.root
        for part in parts:
            if part in current.children:
                current = current.children[part]
                if current.is_symlink:
                    current = self._follow_symlink(current)
                    if current is None:
                        return None
            else:
                print(f"Error: Path '{abs_path}' does not exist.")
                return None
        return current

    def _path_exists(self, path):
        """ Check if a path exists """
        return self._get_node(path) is not None

    def _check_permissions(self, node, action):
        """ Check if the current user has the necessary permissions on the node for the given action """
        role = self.users[self.current_user]['role']
        return self.ROLES[role].get(action, False)

    def _check_quota(self, size):
        """ Check if the current user and group have enough quota left """
        user_quota = self.users[self.current_user]['quota']
        group = self.users[self.current_user]['groups'][0]
        group_quota = self.groups.get(group, self.DEFAULT_GROUP_QUOTA)
        
        # Calculate used space (for simplicity, only consider file content size)
        used_space = sum(len(node.content) for node in self._all_files(self.root) if node.owner == self.current_user)
        used_group_space = sum(len(node.content) for node in self._all_files(self.root) if node.group == group)
        
        if used_space + size > user_quota:
            print(f"Error: User '{self.current_user}' has exceeded their quota.")
            return False
        if used_group_space + size > group_quota:
            print(f"Error: Group '{group}' has exceeded its quota.")
            return False
        return True

    def _all_files(self, node):
        """ Generator to yield all files in the filesystem """
        if not node.is_directory:
            yield node
        else:
            for child in node.children.values():
                yield from self._all_files(child)

    def mkdir(self, dirname):
        """ Create a new directory inside the current directory """
        if not dirname:
            print("Error: Directory name cannot be empty.")
            return
        path = self._resolve_path(dirname)
        parts = path.strip('/').split('/')
        current = self.root
        for part in parts[:-1]:
            if part in current.children:
                current = current.children[part]
            else:
                print(f"Error: Parent directory '{'/'.join(parts[:-1])}' does not exist.")
                return
        if parts[-1] in current.children:
            print(f"Error: Directory '{dirname}' already exists.")
            return
        current.children[parts[-1]] = FileNode(parts[-1], True, owner=self.current_user, parent=current)
        self.log_action(f"Created directory '{dirname}'")
        print(f"Directory '{dirname}' created.")

    def touch(self, filename=None):
        """ Create an empty file if it does not exist """
        if not filename:
            print("Error: Missing filename. Usage: touch <filename>")
            return
        path = self._resolve_path(filename)
        parts = path.strip('/').split('/')
        current = self.root
        for part in parts[:-1]:
            if part in current.children:
                current = current.children[part]
            else:
                print(f"Error: Parent directory '{'/'.join(parts[:-1])}' does not exist.")
                return
        if parts[-1] in current.children:
            print(f"Error: File '{filename}' already exists.")
            return
        current.children[parts[-1]] = FileNode(parts[-1], False, owner=self.current_user, parent=current)
        self.log_action(f"Created empty file '{filename}'")
        print(f"File '{filename}' created.")

    def write(self, filename, content):
        """ Write content to a file """
        if not filename:
            print("Error: Filename cannot be empty.")
            return
        # Resolve the file path
        path = self._resolve_path(filename)
        
        # Check if the file exists
        node = self._get_node(path)
        if node is None or node.is_directory:
            print(f"Error: File '{filename}' does not exist or is a directory.")
            return
        if not self._check_permissions(node, 'write'):
            print(f"Error: User '{self.current_user}' does not have write permission for '{filename}'.")
            return
        if not self._check_quota(len(content)):
            return
        
        # Write content to the file
        node.content = content
        self.log_action(f"Written to file '{filename}'")
        print(f"Content written to file '{filename}'.")

    def read(self, filename):
        """ Read content from a file """
        if not filename:
            print("Error: Filename cannot be empty.")
            return
        path = self._resolve_path(filename)
        node = self._get_node(path)
        if node is None or node.is_directory:
            print(f"Error: File '{filename}' does not exist or is a directory.")
            return
        if not self._check_permissions(node, 'read'):
            print(f"Error: User '{self.current_user}' does not have read permission for '{filename}'.")
            return
        self.log_action(f"Read from file '{filename}'")
        return node.content

    def ls(self, *args):
        """ List files and directories in the current directory """
        option = None
        path = None

        # Parse arguments
        for arg in args:
            if arg.startswith('-'):
                option = arg
            else:
                path = arg

        if path is None:
            node = self.current_directory
        else:
            node = self._get_node(self._resolve_path(path))

        if node is None:
            print(f"Error: Directory '{path}' does not exist.")
            return

        if node.is_directory:
            if option == '-l':
                for child_name, child_node in node.children.items():
                    permissions = child_node.permissions
                    owner = child_node.owner
                    size = len(child_node.content) if not child_node.is_directory else 0
                    print(f"{permissions} {owner} {size} {child_name}")
            else:
                print(" ".join(node.children.keys()))
        else:
            if option == '-l':
                permissions = node.permissions
                owner = node.owner
                size = len(node.content)
                print(f"{permissions} {owner} {size} {node.name}")
            else:
                print(f"{path} is a file, not a directory!")

    def cd(self, dirname):
        """ Change the current directory """
        if dirname == ".":
            return  # Stay in the same directory
        elif dirname == "..":
            if self.current_directory.parent:
                self.current_directory = self.current_directory.parent
                print(f"Changed directory to '{self.current_directory.name}'")
            else:
                print("Error: Already at the root directory.")
            return

        path = self._resolve_path(dirname)
        node = self._get_node(path)
        if node is None or not node.is_directory:
            print(f"Error: Directory '{path}' does not exist.")
            return
        self.current_directory = node
        print(f"Changed directory to '{path}'")

    def rm(self, filename):
        """ Remove a file """
        if not filename:
            print("Error: Missing filename. Usage: rm <filename>")
            return
        path = self._resolve_path(filename)
        node = self._get_node(path)
        if node is None or node.is_directory:
            print(f"Error: File '{filename}' does not exist.")
            return
        if not self._check_permissions(node, 'write'):
            print(f"Error: User '{self.current_user}' does not have write permission for '{filename}'.")
            return
        del node.parent.children[filename]
        self.log_action(f"Removed file '{filename}'")
        print(f"File '{filename}' removed.")

    def mv(self, src, dest):
        """ Move or rename a file """
        if not src or not dest:
            print("Error: Source and destination cannot be empty. Usage: mv <source> <destination>")
            return
        src_path = self._resolve_path(src)
        dest_path = self._resolve_path(dest)
        node = self._get_node(src_path)
        if not node:
            print(f"Error: Source '{src}' does not exist.")
            return
        if self._path_exists(dest_path):
            print(f"Error: Destination '{dest}' already exists.")
            return
        if not self._check_permissions(node, 'write'):
            print(f"Error: User '{self.current_user}' does not have write permission for '{src}'.")
            return
        node.name = dest_path.split('/')[-1]
        if node.parent:
            del node.parent.children[src.split('/')[-1]]
        dest_parent_path = '/'.join(dest_path.split('/')[:-1])
        dest_parent = self._get_node(dest_parent_path) or self.root
        dest_parent.children[node.name] = node
        node.parent = dest_parent
        self.log_action(f"Moved '{src}' to '{dest}'")
        print(f"Moved '{src}' to '{dest}'")

    def cp(self, src, dest):
        """ Copy a file """
        if not src or not dest:
            print("Error: Source and destination cannot be empty. Usage: cp <source> <destination>")
            return
        src_path = self._resolve_path(src)
        dest_path = self._resolve_path(dest)
        node = self._get_node(src_path)
        if not node:
            print(f"Error: Source '{src}' does not exist.")
            return
        if self._path_exists(dest_path):
            print(f"Error: Destination '{dest}' already exists.")
            return
        if not self._check_permissions(node, 'read'):
            print(f"Error: User '{self.current_user}' does not have read permission for '{src}'.")
            return
        if node.is_directory:
            print("Error: Cannot copy a directory!")
            return
        if not self._check_quota(len(node.content)):
            return
        dest_parent_path = '/'.join(dest_path.split('/')[:-1])
        dest_parent = self._get_node(dest_parent_path) or self.root
        dest_name = dest_path.split('/')[-1]
        new_file = FileNode(dest_name, False, owner=self.current_user, parent=dest_parent)
        new_file.content = node.content  # Copy the content manually
        dest_parent.children[dest_name] = new_file
        self.log_action(f"Copied '{src}' to '{dest}'")
        print(f"Copied '{src}' to '{dest}'")

    def ln_s(self, target, link_name):
        """ Create a symbolic link """
        target_path = self._resolve_path(target)
        link_path = self._resolve_path(link_name)
        
        if not self._path_exists(target_path):
            print(f"Error: Target '{target}' does not exist.")
            return
        
        if self._path_exists(link_path):
            print(f"Error: Link name '{link_name}' already exists.")
            return
        
        target_node = self._get_node(target_path)
        link_parent_path = '/'.join(link_path.split('/')[:-1])
        link_parent = self._get_node(link_parent_path) or self.root
        link_name = link_path.split('/')[-1]
        
        link_node = FileNode(link_name, target_node.is_directory, owner=self.current_user, parent=link_parent, is_symlink=True, target=target_path)
        link_parent.children[link_name] = link_node
        self.log_action(f"Created symlink '{link_name}' -> '{target}'")
        print(f"Created symlink '{link_name}' -> '{target}'")

    def save_state(self):
        """ Save the current state of the filesystem """
        data = self._serialize_files(self.root)
        with open(self.SAVE_FILE, "w") as f:
            json.dump(data, f)
        self.log_action("Saved filesystem state")
        print("File system state saved.")
    
    def load_state(self):
        """ Load the filesystem state from a saved file """
        if os.path.exists(self.SAVE_FILE):
            with open(self.SAVE_FILE, "r") as f:
                data = json.load(f)
                self.root = self._deserialize_files(data)
                self.current_directory = self.root  # Ensure current directory is reset to root
            self.log_action("Loaded filesystem state")
            print("File system state loaded.")

    def _serialize_files(self, node):
        """ Serializes the file system """
        serialized = {
            "name": node.name,
            "is_directory": node.is_directory,
            "owner": node.owner,
            "group": node.group,
            "permissions": node.permissions,
            "is_symlink": node.is_symlink,
            "target": node.target,
            "children": {k: self._serialize_files(v) for k, v in node.children.items()} if node.is_directory else {},
            "content": node.content if not node.is_directory else None
        }
        return serialized

    def _deserialize_files(self, data):
        """ Deserialize the file system data """
        node = FileNode(data['name'], data['is_directory'], owner=data['owner'], group=data['group'], permissions=data['permissions'], is_symlink=data['is_symlink'], target=data['target'])
        if data['is_directory']:
            node.children = {k: self._deserialize_files(v) for k, v in data['children'].items()}
        else:
            node.content = data.get('content', '')
        return node

    def add_user(self, username, password, role):
        if username in self.users:
            print(f"Error: User '{username}' already exists.")
            return
        if role not in self.ROLES:
            print(f"Error: Role '{role}' does not exist.")
            return
        self.users[username] = {
            "password": self.hash_password(password),
            "groups": ["root"],
            "role": role,
            "quota": self.DEFAULT_USER_QUOTA
        }
        self.log_action(f"Created user '{username}' with role '{role}'")
        print(f"User '{username}' created with role '{role}'")

    def switch_user(self, username, password):
        if username not in self.users:
            print(f"Error: User '{username}' does not exist.")
            return
        if not self.verify_password(self.users[username]['password'], password):
            print("Error: Incorrect password.")
            return
        self.current_user = username
        self.log_action(f"Switched to user '{username}'")
        print(f"Switched to user '{username}'")

    def get_user_list(self):
        """ Return a list of all user names in the system """
        return list(self.users.keys())
    
    def search(self, pattern, path=None):
        """ Search for files and directories matching the pattern """
        if path is None:
            node = self.root
        else:
            node = self._get_node(self._resolve_path(path))
        
        if node is None:
            print(f"Error: Directory '{path}' does not exist.")
            return []
        
        matches = []
        for match in self._search_recursive(node, pattern):
            matches.append(match)
        
        return matches

    def _search_recursive(self, node, pattern, current_path=""):
        """ Helper function to recursively search for files and directories """
        if fnmatch.fnmatch(node.name, pattern):
            yield current_path + "/" + node.name
        
        if node.is_directory:
            for child_name, child_node in node.children.items():
                yield from self._search_recursive(child_node, pattern, current_path + "/" + node.name)

    def quota(self):
        """ Display the current user's quota usage """
        user_quota = self.users[self.current_user]['quota']
        group = self.users[self.current_user]['groups'][0]
        group_quota = self.groups.get(group, self.DEFAULT_GROUP_QUOTA)

        # Calculate used space (for simplicity, only consider file content size)
        used_space = sum(len(node.content) for node in self._all_files(self.root) if node.owner == self.current_user)
        used_group_space = sum(len(node.content) for node in self._all_files(self.root) if node.group == group)

        print(f"User '{self.current_user}' quota usage: {used_space}/{user_quota} bytes")
        print(f"Group '{group}' quota usage: {used_group_space}/{group_quota} bytes")


#Command-Line Interface for the Virtual File System

if __name__ == "__main__":
    vfs = VirtualFileSystem()
    
    while True:
        cmd = input(f"{vfs.current_user}@vfs:{vfs.current_directory.name}$ ").strip().split()
        if not cmd:
            continue
        command = cmd[0]
        args = cmd[1:]
        
        if command == "ls":
            vfs.ls(*args)
        elif command == "cd":
            vfs.cd(*args)
        elif command == "mkdir":
            vfs.mkdir(*args)
        elif command == "touch":
            if len(args) == 1:
                vfs.touch(args[0])
            else:
                print("Usage: touch <filename>")
        elif command == "rm":
            if len(args) == 1:
                vfs.rm(args[0])
            else:
                print("Usage: rm <filename>")
        elif command == "mv":
            if len(args) == 2:
                vfs.mv(args[0], args[1])
            else:
                print("Usage: mv <source> <destination>")
        elif command == "cp":
            if len(args) == 2:
                vfs.cp(args[0], args[1])
            else:
                print("Usage: cp <source> <destination>")
        elif command == "ln":
            if args and args[0] == "-s" and len(args) == 3:
                vfs.ln_s(args[1], args[2])
            else:
                print("Usage: ln -s <target> <link_name>")
        elif command == "write":
            if len(args) >= 2:
                filename = args[0]
                content = " ".join(args[1:])
                vfs.write(filename, content)
                print(f"Content written to file '{filename}'.")
            else:
                print("Usage: write <filename> <content>")
        elif command in ["read", "cat"]:
            if len(args) == 1:
                content = vfs.read(args[0])
                if content is not None:
                    print(content)
            else:
                print(f"Usage: {command} <filename>")
        elif command == "save":
            vfs.save_state()
        elif command == "load":
            vfs.load_state()
        elif command == "exit":
            break
        elif command == "adduser":
            if len(args) == 3:
                vfs.add_user(args[0], args[1], args[2])
            else:
                print("Usage: adduser <username> <password> <role>")
        elif command == "su":
            if len(args) == 2:
                vfs.switch_user(args[0], args[1])
            else:
                print("Usage: su <username> <password>")
        elif command == "listusers":
            users = vfs.get_user_list()
            print("Users:", ", ".join(users))
        elif command == "search":
            if len(args) == 1:
                matches = vfs.search(args[0])
            elif len(args) == 2:
                matches = vfs.search(args[0], args[1])
            else:
                print("Usage: search <pattern> [path]")
                continue
            if matches:
                print("Matches:")
                for match in matches:
                    print(match)
            else:
                print("No matches found.")
        elif command == "file":
            if len(args) == 1:
                node = vfs._get_node(vfs._resolve_path(args[0]))
                if node:
                    permissions = node.permissions
                    owner = node.owner
                    size = len(node.content) if not node.is_directory else 0
                    print(f"{permissions} {owner} {size} {node.name}")
                else:
                    print(f"Error: File '{args[0]}' does not exist.")
            else:
                print("Usage: file <filename>")
        elif command == "quota":
            vfs.quota()
        else:
            print(f"Unknown command: {command}")