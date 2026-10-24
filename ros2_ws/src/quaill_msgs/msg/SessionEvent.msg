# quaill_msgs/SessionEvent (spec v0.0.2, draft)
# Markers that let a checker tell a crash from a cut. Borrowed from car EDRs and flight recorders.

builtin_interfaces/Time stamp
string event            # START | CLEAN_SHUTDOWN | CRASH_NOTE | POWER_LOST
string session_id
string prev_session_id  # on CRASH_NOTE: the session that ended unexpectedly
string software_version
string note
string device_pubkey    # on START: hex of the raw 32-byte Ed25519 public key that signs this session's links; empty when unsigned
