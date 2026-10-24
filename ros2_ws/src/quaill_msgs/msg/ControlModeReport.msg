# quaill_msgs/ControlModeReport (spec v0.0.2, draft)
# Who is in control right now. Emit on every change and as a heartbeat (1 Hz suggested).
# Mode numbering mirrors autoware_vehicle_msgs/ControlModeReport so nothing new is invented.

uint8 NO_COMMAND=0
uint8 AUTONOMOUS=1
uint8 AUTONOMOUS_STEER_ONLY=2
uint8 AUTONOMOUS_VELOCITY_ONLY=3
uint8 MANUAL=4
uint8 DISENGAGED=5
uint8 NOT_READY=6

builtin_interfaces/Time stamp
uint8 mode            # one of the constants above
string mode_name      # human-readable copy of mode
string operator_ref   # pseudonymous operator id; REQUIRED (non-empty) when mode is MANUAL; empty otherwise
string reason         # why control changed; empty on heartbeats
