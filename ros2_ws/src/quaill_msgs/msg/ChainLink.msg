# quaill_msgs/ChainLink (spec v0.0.2, draft)
# One link per message on every other recorded topic, published by a sidecar node that subscribes raw.
# The checker pairs a link to a message by content (msg_sha256), never by the bag's log_time,
# because the sidecar cannot know what time rosbag2 will stamp on the message.
#
#   msg_sha256 = sha256(topic || 0x00 || serialized_bytes)
#   link       = sha256(prev || msg_sha256 || seq (8 bytes BE) || recv_time (8 bytes BE, signed) || topic)
#   prev of the first link = 64 zeros

string session_id  # the recorder session this chain belongs to; a restarted sidecar starts a new chain (seq 1, prev = zeros) under a new id
uint64 seq         # 1, 2, 3, ... in the order the sidecar saw messages
string topic       # topic of the message this link covers
string msg_sha256  # hex
string prev        # hex, previous link
string link        # hex, this link
int64 recv_time    # ns, the sidecar's clock when it saw the message (hashed; checked against the bag's log_time)
string key_id      # first 16 hex of sha256(device public key); empty when unsigned
string sig         # hex Ed25519 signature over the 32 link bytes, by the device key; empty when unsigned
