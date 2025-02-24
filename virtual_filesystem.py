import os
import json
from datetime import datetime
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

    def touch(self, filename):
        """ Create an empty file if it does not exist """
        if not filename:
            print("Error: Filename cannot be empty.")
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

    def ls(self, path=None):
        """ List files and directories in the current directory """
        if path and path.startswith('-'):  # Handle options like -l
            option = path
            path = None
        else:
            option = None
        
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
            print(f"{path} is a file, not a directory!")

    def cd(self, dirname):
        """ Change the current directory """
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
            print("Error: Filename cannot be empty.")
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
            print("Error: Source and destination cannot be empty.")
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
            print("Error: Source and destination cannot be empty.")
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
        dest_parent.children[dest_name] = FileNode(dest_name, False, owner=self.current_user, content=node.content)
        self.log_action(f"Copied '{src}' to '{dest}'")
        print(f"Copied '{src}' to '{dest}'")

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

# Command-line interface (CLI)
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
            vfs.touch(*args)
        elif command == "rm":
            vfs.rm(*args)
        elif command == "mv":
            vfs.mv(*args)
        elif command == "cp":
            vfs.cp(*args)
        elif command == "ln":
            if args and args[0] == "-s" and len(args) == 3:
                vfs.ln_s(args[1], args[2])
            else:
                print("Usage: ln -s <target> <link_name>")
        elif command == "write":
            if len(args) == 2:
                vfs.write(args[0], args[1])
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
        else:
            print(f"Unknown command: {command}")