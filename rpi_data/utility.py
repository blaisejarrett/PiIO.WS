import sys
import uuid


def get_mac():
    """
    Returns hardware mac address in FF:FF:FF:FF:FF:FF string format
    """
    mac_int = uuid.getnode()
    mac_str = hex(mac_int)[2:].zfill(12).upper()
    mac = ':'.join([mac_str[i:i+2] for i in xrange(0, 12, 2)])
    return mac


def trim(docstring):
    if not docstring:
        return ''
        # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    indent = sys.maxint
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
        # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < sys.maxint:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
        # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
        # Return a single string:
    return '\n'.join(trimmed)
