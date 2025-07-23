"""
Lazy file loading utilities for efficient manifest file processing.
"""
import logging
from typing import List, Tuple, Union, BinaryIO
from io import BytesIO
import os

log = logging.getLogger("socketdev")


class LazyFileLoader:
    """
    A file-like object that only opens the actual file when needed for reading.
    This prevents keeping too many file descriptors open simultaneously.
    
    This class implements the standard file-like interface that requests library
    expects for multipart uploads, making it a drop-in replacement for regular
    file objects.
    """
    
    def __init__(self, file_path: str, name: str):
        self.file_path = file_path
        self.name = name
        self._file = None
        self._closed = False
        self._position = 0
    
    def _ensure_open(self):
        """Ensure the file is open and seek to the correct position."""
        if self._closed:
            raise ValueError("I/O operation on closed file.")
        
        if self._file is None:
            self._file = open(self.file_path, 'rb')
            log.debug(f"Opened file for reading: {self.file_path}")
            # Seek to the current position if we've been reading before
            if self._position > 0:
                self._file.seek(self._position)
    
    def read(self, size: int = -1):
        """Read from the file, opening it if needed."""
        self._ensure_open()
        data = self._file.read(size)
        self._position = self._file.tell()
        return data
    
    def readline(self, size: int = -1):
        """Read a line from the file."""
        self._ensure_open()
        data = self._file.readline(size)
        self._position = self._file.tell()
        return data
    
    def seek(self, offset: int, whence: int = 0):
        """Seek to a position in the file."""
        if self._closed:
            raise ValueError("I/O operation on closed file.")
        
        # Calculate new position for tracking
        if whence == 0:  # SEEK_SET
            self._position = offset
        elif whence == 1:  # SEEK_CUR
            self._position += offset
        elif whence == 2:  # SEEK_END
            # We need to open the file to get its size
            self._ensure_open()
            result = self._file.seek(offset, whence)
            self._position = self._file.tell()
            return result
        
        # If file is already open, seek it too
        if self._file is not None:
            result = self._file.seek(self._position)
            return result
        
        return self._position
    
    def tell(self):
        """Return current file position."""
        if self._closed:
            raise ValueError("I/O operation on closed file.")
        
        if self._file is not None:
            self._position = self._file.tell()
        
        return self._position
    
    def close(self):
        """Close the file if it was opened."""
        if self._file is not None:
            self._file.close()
            log.debug(f"Closed file: {self.file_path}")
            self._file = None
        self._closed = True
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    @property
    def closed(self):
        """Check if the file is closed."""
        return self._closed
    
    @property 
    def mode(self):
        """Return the file mode."""
        return 'rb'
    
    def readable(self):
        """Return whether the file is readable."""
        return not self._closed
    
    def writable(self):
        """Return whether the file is writable."""
        return False
    
    def seekable(self):
        """Return whether the file supports seeking."""
        return True


def load_files_for_sending_lazy(files: List[str], workspace: str) -> List[Tuple[str, Tuple[str, LazyFileLoader]]]:
    """
    Prepares files for sending to the Socket API using lazy loading.
    
    This version doesn't open all files immediately, instead it creates
    LazyFileLoader objects that only open files when they're actually read.
    This prevents "Too many open files" errors when dealing with large numbers
    of manifest files.

    Args:
        files: List of file paths from find_files()
        workspace: Base directory path to make paths relative to

    Returns:
        List of tuples formatted for requests multipart upload:
        [(field_name, (filename, lazy_file_object)), ...]
    """
    send_files = []
    if "\\" in workspace:
        workspace = workspace.replace("\\", "/")
    
    for file_path in files:
        _, name = file_path.rsplit("/", 1)

        if file_path.startswith(workspace):
            key = file_path[len(workspace):]
        else:
            key = file_path

        key = key.lstrip("/")
        key = key.lstrip("./")

        # Create lazy file loader instead of opening file immediately
        # Use the relative path (key) as filename instead of truncated basename
        lazy_file = LazyFileLoader(file_path, key)
        payload = (key, (key, lazy_file))
        send_files.append(payload)

    log.debug(f"Prepared {len(send_files)} files for lazy loading")
    return send_files
