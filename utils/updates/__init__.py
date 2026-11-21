"""Phoenix Desktop updates.

- ``channel``: asks the signed update channel whether a newer build exists
- ``background``: the quiet daily check
- ``installer``: downloads the release and starts it, checked against the
  signed manifest (Windows, macOS; Linux updates from its package repository)
- ``version``: the running version and build
"""
