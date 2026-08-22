"""
Fixture exercising MCP004's derived-value exclusion: a name whose final
underscore-separated word is exactly "hash", "digest", or "checksum"
holds a one-way derived value, not the credential itself. Independently
designed for this repository, not derived from any external corpus.
"""

password_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
token_digest = "a3f5c8d9e2f1b3a7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3"
config_checksum = "b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6"
