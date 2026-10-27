# Mapping a profile onto your own topics

A shipped profile names the topics and fields it expects with placeholder names (for example `/stvfernlv/telemetry` and `position.lat`). A real robot records its own topics. A mapping file tells the checker where each item actually lives, without editing the profile.

```bash
quaill verify bag/ --profile stvfernlv-anlage3 --map my-fleet.json
```

`my-fleet.json`:

```json
{
  "profile": "stvfernlv-anlage3",
  "items": {
    "A2":  { "topic": "/vehicle/gnss",  "fields": { "position.lat": "latitude", "position.lon": "longitude", "position.alt": "altitude", "position.heading": "heading_deg" } },
    "A9":  { "topic": "/vehicle/odom",  "fields": { "speed": "twist.twist.linear.x" } },
    "A4":  { "topic": "/ops/driver" },
    "A13": { "required": false }
  },
  "events": {
    "topic": "/ops/events",
    "field": "kind",
    "values": { "REMOTE_DRIVING_START": "session_start", "REMOTE_DRIVING_END": "session_end", "FAULT": "fault" },
    "window_topics": ["/vehicle/gnss"]
  }
}
```

Rules:

- `items.<id>.topic` replaces the item's topic. `fields` renames field paths: the key is the profile's name, the value is the path in your message (dots walk into nested fields). Fields you do not name keep the profile's path. `required: false` makes a missing item informational.
- `events.topic` and `events.field` replace where the event list lives. `events.values` renames the profile's event names to yours; names you do not map keep the profile's spelling. `events.window_topics` replaces the list of topics that must have traffic around an event.
- `profile` is optional; if present it must match the profile being checked, so a mapping for one rule set is not applied to another by mistake.
- The report shows the mapped topic next to each item, so a reader sees what was actually checked.

What a mapping does not do: it does not invent data. If your robot never records a field, the item stays MISSING, and that is the point.
