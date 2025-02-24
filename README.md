# Virtual Filesystem Challenge

## Overview

The Virtual Filesystem Challenge is an educational project that implements a simple, in-memory virtual filesystem (VFS). It includes user authentication, file and directory management, permission handling, symlinks, and quota enforcement. The project focuses on filesystem structure, security, and user role management.

## Features

- **File and Directory Management**: Create, delete, move, copy, and list files and directories.
- **Permissions & Roles**: Supports admin, editor, and viewer roles with different access levels.
- **User Authentication**: Secure login system using bcrypt for password hashing.
- **Symlinks**: Supports symbolic links for file redirection.
- **Quota Management**: Enforces user and group-based storage limits.
- **Logging**: Keeps track of filesystem actions for auditability.
- **Persistent Storage**: Saves and loads the filesystem state using JSON.
- **Command-Line Interface**: Interactive shell to execute filesystem commands.
- **Access Control Mechanism**: Granular permissions per user and group.
- **File Search**: Search for files and directories based on patterns.

## Installation

### Prerequisites

- Python 3.x
- Required Python libraries: bcrypt

### Install Dependencies


pip install bcrypt


### Usage
Setting Up Environment Variables
Set the ROOT_PASSWORD environment variable to specify the root user's password. This can be done in the terminal before running the script.

### On Windows:
set ROOT_PASSWORD=your_secure_password
python virtual_filesystem.py

### On macOS/Linux:
export ROOT_PASSWORD=your_secure_password
python virtual_filesystem.py

### Running the Filesystem
python virtual_filesystem.py

### Available Commands
mkdir <directory>: Create a new directory.
touch <filename>: Create an empty file.
write <filename> <content>: Write content to a file.
read <filename> or cat <filename>: Read content from a file.
ls [-l] [directory]: List files and directories.
cd <directory>: Change current directory.
rm <filename>: Delete a file.
mv <source> <destination>: Move or rename a file.
cp <source> <destination>: Copy a file.
ln -s <target> <symlink>: Create a symbolic link.
quota: Display user storage quota usage.
search <pattern> [path]: Search for files and directories matching the pattern.
file <filename>: Display information about a specific file.

### User Management
adduser <username> <password> <role>: Add a new user.
passwd <username> <new_password>: Change a user's password.
chown <filename> <new_owner>: Change file owner.
chmod <filename> <permissions>: Modify file permissions.
su <username> <password>: Switch to a different user.
listusers: List all users in the system.

### Security Features
User Authentication: Passwords are securely hashed using bcrypt.
Role-Based Access Control: Ensures restricted file access based on user roles.
Quota Enforcement: Prevents excessive storage usage.
Logging: Tracks user activities for accountability.
Symlink Security Checks: Prevents unauthorized link redirections.

### Future Improvements
Implement ACLs for fine-grained permission control.
Add networked filesystem capabilities.
Improve efficiency with tree-based data structures.
Integrate encryption for enhanced security.
Implement journaling for crash recovery.

### License
This project is released under the MIT License.

### Known Limitations & Areas for Improvement

- **File Search Capabilities**: Currently implemented. The `search` method allows users to search for files and directories based on a given pattern.
- **Error Handling**: Improve error handling by raising exceptions instead of using print statements.
- **Performance**: Optimize data structures and algorithms for better performance with large file systems.
- **User Interface**: Develop a more user-friendly interface, possibly with a graphical UI.
- **Testing**: Add unit tests to ensure the correctness of the implementation.

By following this README, users can set up and use the virtual file system, understand its features, and know where improvements can be made.