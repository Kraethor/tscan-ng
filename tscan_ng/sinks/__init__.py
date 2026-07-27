"""
tscan_ng.sinks - Output destinations for tscan-ng findings.

Both sinks expose the same write(finding) interface so pipeline.py's
_emit() can call through to each identically:
    jsonl.py   - JSONLSink, the durable on-disk finding log.
    discord.py - DiscordSink, real-time webhook alerting.
"""
