# gw_bulk

Configure many, many Check Point firewalls

# Scope

Check Point Software, R80.x, R81.x, R82.x Multi-Domain and Standalone Management

# Instructions

1. Move to system in it's own folder and run. 
```python3 gw_bulk.py```

2. Answer required questions. (Email only works with local smtp server)

3. In separate session, follow progress.
```tail -F log.log```

# Folders

- 'output' - CSV and JSON files can be found in output folder

- 'scripts' - Locally generated shell scripts. Removed when code is finished running.

