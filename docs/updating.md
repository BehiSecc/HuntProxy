# Updating

Run `HuntProxy update` to update a native installation. The updater prepares the browser runtime and official plugins, preserves project data, and restarts a running daemon. Customized and third-party plugin folders are preserved; an incompatible preserved Racer package returns a compatibility error.

The MCP bridge refreshes its tool catalog after updates and sends `tools/list_changed` so supported clients can discover changes. It retains the last validated catalog while the daemon is idle or stopped. For an update from v0.1.1, run `HuntProxy stop` before updating and reconnect the MCP client afterward.

Updates keep a private database, configuration, and plugin restore point and the previous executable. Failed preparation or activation triggers restoration; recovery errors are reported if restoration cannot complete. Interrupted v0.2 updates recover before opening project data. Schema migrations also keep a private copy of the earlier database. Browser profiles and the CA are preserved in place rather than included in update restore points.

Active browsers and jobs stop during replacement. Saved projects, history, identities, and browser profile storage remain available. Older `.huntproxy` bundles are upgraded during ordinary import.

`HuntProxy backup` copies only the SQLite database. For an independent full backup, stop HuntProxy and copy `~/.huntproxy` and any configured external paths. See the [release notes](releases/v0.2.0.md) for compatibility changes.
