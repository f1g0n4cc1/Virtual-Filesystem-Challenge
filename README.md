# Virtual Filesystem (VFS)

## Project Overview

This project is an in-memory virtual filesystem (VFS) that supports standard file operations while remaining independent of physical disk storage. It includes features such as file and directory creation/deletion, content reading/writing, directory listing, metadata tracking, and path navigation. The project also supports symbolic links, user permissions, file search capabilities, state persistence across sessions, and operation logging.

## Features

### Core Filesystem Features
- **File and Directory Management**: Create and delete files and directories.
- **Content Manipulation**: Read and write to files.
- **Directory Listing**: List directory contents.
- **Metadata Tracking**: Track file size, creation time, modification time, etc.
- **Path Navigation**: Support both relative and absolute paths.

### Interface Requirements
- **Programmatic API**: Functions for filesystem operations.
- **Command-Line Interface (CLI)**: A shell-like interface with Unix-like commands (`ls`, `cd`, `mkdir`, etc.).

### Optional Enhancements
- **User Permission System**: Implement file ownership and access control.
- **Symbolic Link Support**: Support soft links (`ln -s`).
- **File Search Capabilities**: Implement searching by filename and content.
- **State Persistence**: Save and restore the filesystem across sessions.
- **Operation Logging**: Track operations for debugging or auditing.

## Technical Constraints
- **Memory-Only**: Everything must be stored in RAM.
- **Consistency**: Ensure the filesystem remains stable and doesn't corrupt data.
- **Error Handling**: Handle invalid commands, missing files, etc.
- **Language Choice**: Implemented in Python.
- **LLM Assistance**: Implementation fully understood by the developer.

## Getting Started

### Prerequisites
- Python 3.x
- `pycryptodome` library for encryption
- `bcrypt` library for password hashing

### Installation
Install the required libraries using pip:
```sh
pip install pycryptodome bcrypt
```

### Running the Virtual Filesystem
Run the `virtual_filesystem.py` script:
```sh
python virtual_filesystem.py
```

### Example Commands
Here are some example commands you can try in the CLI:

- **Create a Directory**: `mkdir mydir`
- **List Directory Contents**: `ls`
- **Create a File**: `touch myfile.txt`
- **Write to a File**: `write myfile.txt "Hello, World!"`
- **Read a File**: `cat myfile.txt`
- **Create a Symbolic Link**: `ln_s myfile.txt mylink.txt`
- **Read a File through Symlink**: `cat mylink.txt`
- **Move a File**: `mv myfile.txt newfile.txt`
- **Copy a File**: `cp newfile.txt copyfile.txt`
- **Remove a File**: `rm copyfile.txt`
- **Change Directory**: `cd mydir`
- **Go Back to Parent Directory**: `cd ..`
- **Find Files by Name**: `find myfile`
- **Find Files by Content**: `find "Hello" --content`
- **Change File Permissions**: `chmod newfile.txt g+w`
- **Change File Owner**: `chown newfile.txt newowner`
- **Change File Group**: `chgrp newfile.txt newgroup`
- **Exit and Save State**: `exit`

## API Design Decisions
- **Filesystem Structure**: Implemented as a tree-like structure using nested dictionaries.
- **FileNode Class**: Represents files and directories.
- **VirtualFileSystem Class**: Manages the filesystem operations and interactions.

## Data Structure Choices
- **FileNode**: Represents each file and directory with attributes such as name, type, owner, permissions, content, etc.
- **VirtualFileSystem**: Manages the overall filesystem, including user management, command execution, and state persistence.

## Known Limitations & Areas for Improvement
- **Advanced Unix Commands**: Commands like `rm -r`, `cp -r`, etc., are not implemented.
- **User Authentication**: Currently uses plaintext storage for demonstration; consider enhancing security.
- **Concurrency**: The current implementation does not support concurrent access.
- **Performance**: The in-memory structure may not be efficient for very large filesystems.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
- The project was developed with assistance from GitHub Copilot.