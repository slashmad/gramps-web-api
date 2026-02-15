#
# Gramps Web API - A RESTful API for the Gramps genealogy program
#
# Copyright (C) 2022      David Straub
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#

"""User administration resources."""


from flask import abort, current_app, jsonify
from webargs import fields, validate

from ...auth import (
    config_delete,
    config_get,
    config_get_all,
    config_get_all_described,
    config_set,
)
from ...auth.const import PERM_EDIT_SETTINGS, PERM_VIEW_SETTINGS
from ...const import is_db_config_key_allowed
from ..auth import require_permissions
from ..tasks import send_email_confirm_email, send_email_reset_password
from ..util import abort_with_message, use_args
from . import ProtectedResource


class ConfigsResource(ProtectedResource):
    """Resource for configuration settings."""

    @use_args(
        {
            "full": fields.Boolean(load_default=False),
        },
        location="query",
    )
    def get(self, args):
        """Get all config settings."""
        require_permissions([PERM_VIEW_SETTINGS])
        if args["full"]:
            return jsonify(config_get_all_described()), 200
        return jsonify(config_get_all()), 200


class ConfigResource(ProtectedResource):
    """Resource for a single config setting."""

    @staticmethod
    def _is_key_allowed(key: str) -> bool:
        base_config = current_app.config.get("_BASE_CONFIG", current_app.config)
        return is_db_config_key_allowed(key, base_config)

    def get(self, key: str):
        """Get a config setting."""
        require_permissions([PERM_VIEW_SETTINGS])
        if not self._is_key_allowed(key):
            abort(404)
        val = config_get(key)
        if val is None:
            abort(404)
        return jsonify(val), 200

    @use_args(
        {
            "value": fields.Raw(required=True),
        },
        location="json",
    )
    def put(self, args, key: str):
        """Update a config setting."""
        require_permissions([PERM_EDIT_SETTINGS])
        if not self._is_key_allowed(key):
            abort(404)
        try:
            config_set(key=key, value=args["value"])
        except ValueError as exc:
            abort(400, description=str(exc))
        return "", 200

    def delete(self, key: str):
        """Delete a config setting."""
        require_permissions([PERM_EDIT_SETTINGS])
        if not self._is_key_allowed(key):
            abort(404)
        try:
            if config_get(key=key) is None:
                abort(404)
        except ValueError:
            abort(404)
        config_delete(key=key)
        return "", 200


class ConfigEmailTestResource(ProtectedResource):
    """Resource for sending SMTP test e-mails."""

    @use_args(
        {
            "mail_to": fields.Email(required=True),
            "username": fields.Str(required=True),
            "template": fields.Str(
                required=True, validate=validate.OneOf(["confirm-email", "reset-pw"])
            ),
        },
        location="json",
    )
    def post(self, args):
        """Send a test email with the current SMTP settings."""
        require_permissions([PERM_EDIT_SETTINGS])
        try:
            if args["template"] == "confirm-email":
                send_email_confirm_email(args["mail_to"], args["username"], "")
            else:
                send_email_reset_password(args["mail_to"], args["username"], "")
        except ValueError as exc:
            abort_with_message(500, str(exc))
        return jsonify({"status": "sent"}), 200
