> [!IMPORTANT]
> **Local Patch Block (2026-02-15)**
>
> This fork includes backend support for full web-based server configuration:
> - Expanded configurable-key handling to expose supported `config.cfg`/CLI options through `/api/config/?full=1`.
> - Added config metadata output (value type, default value, runtime source) for admin UI editing.
> - Added typed parsing/serialization for DB-stored overrides (boolean, number, duration, JSON/list-like values).
> - Applies DB overrides to runtime `app.config` on startup so DB-managed deployments stay configurable.
> - Updated config retrieval paths to read typed DB overrides consistently.
>
> Together with the patched **gramps-web** frontend, admins can manage server settings from the web UI when file-based config is not practical (for example TrueNAS Apps).
>
# Gramps Web API

This is the repository for **Gramps Web API**, a Python REST API for [Gramps](https://gramps-project.org).

It allows to query and manipulate a [Gramps](https://gramps-project.org) family tree database via the web.

Gramps Web API is the backend of [Gramps Web](https://www.grampsweb.org/), a genealogy web app based on Gramps, but can also be used as backend for other tools.

## More information

- API documentation for Gramps Web API: https://gramps-project.github.io/gramps-web-api/
- Developer documentation for Gramps Web API: https://www.grampsweb.org/dev-backend/
- Documentation for Gramps Web: https://www.grampsweb.org

## Related projects

- Gramps Web frontend repository: https://github.com/gramps-project/gramps-web
