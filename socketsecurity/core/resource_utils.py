"""
System resource utilities for the Socket Security CLI.
"""
import resource
import logging

log = logging.getLogger("socketdev")


def get_file_descriptor_limit():
    """
    Get the current file descriptor limit (equivalent to ulimit -n)
    
    Returns:
        tuple: (soft_limit, hard_limit) or (None, None) if error
    """
    try:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        return soft_limit, hard_limit
    except OSError as e:
        log.error(f"Error getting file descriptor limit: {e}")
        return None, None


def check_file_count_against_ulimit(file_count, buffer_size=100):
    """
    Check if the number of files would exceed the file descriptor limit
    
    Args:
        file_count (int): Number of files to check
        buffer_size (int): Safety buffer to leave for other file operations
    
    Returns:
        dict: Information about the check
    """
    soft_limit, hard_limit = get_file_descriptor_limit()
    
    if soft_limit is None:
        return {
            "can_check": False,
            "error": "Could not determine file descriptor limit",
            "safe_to_process": True  # Assume safe if we can't check
        }
    
    available_fds = soft_limit - buffer_size
    would_exceed = file_count > available_fds
    
    return {
        "can_check": True,
        "file_count": file_count,
        "soft_limit": soft_limit,
        "hard_limit": hard_limit,
        "available_fds": available_fds,
        "would_exceed": would_exceed,
        "safe_to_process": not would_exceed,
        "buffer_size": buffer_size,
        "recommendation": "Consider processing files in batches or increasing ulimit" if would_exceed else "Safe to process all files"
    }
