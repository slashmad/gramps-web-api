#
# Gramps Web API - A RESTful API for the Gramps genealogy program
#
# Copyright (C) 2020-2022      David Straub
# Copyright (C) 2025           Alexander Bocken
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

"""Define methods of providing authentication for users."""

import copy
import json
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Set, Union

import sqlalchemy as sa
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError, OperationalError, StatementError
from sqlalchemy.orm import mapped_column
from sqlalchemy.sql.functions import coalesce


from ..const import is_db_config_key_allowed, get_db_config_allowed_keys
from .const import PERMISSIONS, PERM_USE_CHAT, ROLE_ADMIN, ROLE_OWNER
from .passwords import hash_password, verify_password
from .sql_guid import GUID

user_db = SQLAlchemy()


def add_user(
    name: str,
    password: str,
    fullname: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[int] = None,
    tree: Optional[str] = None,
):
    """Add a user."""
    if name == "":
        raise ValueError("Username must not be empty")
    if password == "":
        raise ValueError("Password must not be empty")
    try:
        user = User(
            id=uuid.uuid4(),
            name=name,
            fullname=fullname,
            email=email,
            pwhash=hash_password(password),
            role=role,
            tree=tree,
        )
        user_db.session.add(user)  # pylint: disable=no-member
        user_db.session.commit()  # pylint: disable=no-member
    except IntegrityError as exc:
        reason = str(exc.orig.args) if exc.orig else ""
        if "name" in reason:
            message = "User already exists"
        elif "email" in reason:
            message = "E-mail already exists"
        else:
            message = "Unexpected database error while trying to add user"
        raise ValueError(message) from exc


def add_users(
    data: List[Dict[str, Union[str, int]]],
    allow_id: bool = False,
    require_password: bool = False,
    allow_admin: bool = False,
):
    """Add multiple users."""
    if not data:
        raise ValueError("No data provided.")
    for user in data:
        if not user.get("name"):
            raise ValueError("Username must not be empty")
        if require_password and not user.get("password"):
            raise ValueError("Password must not be empty")
        if "id" in user and not allow_id:
            raise ValueError("User ID must not be specified")
        if not allow_admin and int(user.get("role", 0)) > ROLE_OWNER:
            raise ValueError("Insufficient permissions to create admin role")
        if "id" not in user:
            user["id"] = str(uuid.uuid4())
        if not user.get("password"):
            # generate random password
            user["password"] = secrets.token_urlsafe(16)
        user["pwhash"] = hash_password(str(user.pop("password")))
        try:
            user_obj = User(**user)
            user_db.session.add(user_obj)  # pylint: disable=no-member
        except IntegrityError as exc:
            raise ValueError("Invalid or existing user") from exc
    user_db.session.commit()  # pylint: disable=no-member


def get_guid(name: str) -> str:
    """Get the GUID of an existing user by username."""
    query = user_db.session.query(User.id)  # pylint: disable=no-member
    user_id = query.filter_by(name=name).scalar()
    if user_id is None:
        raise ValueError(f"User {name} not found")
    return user_id


def get_name(guid: str) -> str:
    """Get the username of an existing user by GUID."""
    try:
        query = user_db.session.query(User.name)  # pylint: disable=no-member
        user_name = query.filter_by(id=guid).scalar()
    except StatementError as exc:
        raise ValueError(f"User ID {guid} not found") from exc
    if user_name is None:
        raise ValueError(f"User ID {guid} not found")
    return user_name


def get_tree(guid: str) -> Optional[str]:
    """Get the tree of an existing user by GUID."""
    try:
        query = user_db.session.query(User.tree)  # pylint: disable=no-member
        tree = query.filter_by(id=guid).scalar()
    except StatementError as exc:
        raise ValueError(f"User ID {guid} not found") from exc
    return tree


def delete_user(name: str) -> None:
    """Delete an existing user and their associated OIDC accounts."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    user = query.filter_by(name=name).scalar()
    if user is None:
        raise ValueError(f"User {name} not found")

    # Manually delete associated OIDC accounts first.
    # This is needed because SQLite does not enforce foreign key constraints by default.
    user_db.session.query(OIDCAccount).filter_by(
        user_id=user.id
    ).delete()  # pylint: disable=no-member

    user_db.session.delete(user)  # pylint: disable=no-member
    user_db.session.commit()  # pylint: disable=no-member


def modify_user(
    name: str,
    name_new: Optional[str] = None,
    password: Optional[str] = None,
    fullname: Optional[str] = None,
    email: Optional[str] = None,
    role: Optional[int] = None,
    tree: Optional[str] = None,
) -> None:
    """Modify an existing user."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    user = query.filter_by(name=name).one()
    if name_new is not None:
        user.name = name_new
    if password is not None:
        user.pwhash = hash_password(password)
    if fullname is not None:
        user.fullname = fullname
    if email is not None:
        user.email = email
    if role is not None:
        user.role = role
    if tree is not None:
        user.tree = tree
    try:
        user_db.session.commit()  # pylint: disable=no-member
    except IntegrityError as exc:
        user_db.session.rollback()  # pylint: disable=no-member
        reason = str(exc.orig.args) if exc.orig else ""
        # Check for unique constraint violations on username or email
        # PostgreSQL: "users_name_key" or "users_email_key"
        # SQLite: "users.name" or "users.email"
        if "users_name_key" in reason or "users.name" in reason:
            message = "User already exists"
            raise ValueError(message) from exc
        elif "users_email_key" in reason or "users.email" in reason:
            message = "E-mail already exists"
            raise ValueError(message) from exc
        else:
            # Let unexpected database errors bubble up as IntegrityError
            # This will result in a 500 error, which is appropriate for
            # unexpected database issues
            raise


def authorized(username: str, password: str) -> bool:
    """Return true if the user can be authenticated."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    user = query.filter_by(name=username).scalar()
    if user is None:
        return False
    if user.role < 0:
        # users with negative roles cannot login!
        return False
    return verify_password(password=password, salt_hash=user.pwhash)


def get_pwhash(username: str) -> str:
    """Return the current hashed password."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    user = query.filter_by(name=username).one()
    return user.pwhash


def _get_user_detail(
    user, include_guid: bool = False, include_oidc_accounts: bool = False
):
    details = {
        "name": user.name,
        "email": user.email,
        "full_name": user.fullname,
        "role": user.role,
        "tree": user.tree,
    }
    if include_guid:
        details["user_id"] = user.id
    if include_oidc_accounts:
        oidc_accounts = get_user_oidc_accounts(user.id)
        details["oidc_accounts"] = oidc_accounts
        # Add a simplified account source summary for frontend display
        if oidc_accounts:
            oidc_name = current_app.config.get("OIDC_NAME") or "Custom OIDC"
            details["account_source"] = oidc_name
        else:
            details["account_source"] = "Local"
    return details


def get_user_details(username: str) -> Optional[Dict[str, Any]]:
    """Return details about a user."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    user = query.filter_by(name=username).scalar()
    if user is None:
        return None
    return _get_user_detail(user)


def get_all_user_details(
    tree: Optional[str],
    include_treeless=False,
    include_guid: bool = False,
    include_oidc_accounts: bool = False,
) -> List[Dict[str, Any]]:
    """Return details about all users.

    If tree is None, return all users regardless of tree.
    If tree is not None, only return users of given tree.

    If include_treeless is True, include also users with empty tree ID.
    If include_oidc_accounts is True, include OIDC provider information.
    """
    query = user_db.session.query(User)  # pylint: disable=no-member
    if tree:
        if include_treeless:
            query = query.filter(sa.or_(User.tree == tree, User.tree.is_(None)))
        else:
            query = query.filter(User.tree == tree)
    users = query.all()
    return [
        _get_user_detail(
            user, include_guid=include_guid, include_oidc_accounts=include_oidc_accounts
        )
        for user in users
    ]


def get_permissions(username: str, tree: str) -> Set[str]:
    """Get the permissions of a given user."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    user = query.filter_by(name=username).one()
    permissions = PERMISSIONS[user.role].copy()
    # check & add chat permissions
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj = query.filter_by(id=tree).scalar()
    if tree_obj and tree_obj.min_role_ai is not None:
        if user.role >= tree_obj.min_role_ai:
            permissions.add(PERM_USE_CHAT)
    return permissions


def get_owner_emails(
    tree: str, include_admins: bool = False, include_treeless: bool = False
) -> List[str]:
    """Get e-mail addresses of all tree owners (and optionally include site admins)."""
    query = user_db.session.query(User)  # pylint: disable=no-member
    if include_treeless:
        query = query.filter(sa.or_(User.tree == tree, User.tree.is_(None)))
    else:
        query = query.filter(User.tree == tree)
    if include_admins:
        query = query.filter(sa.or_(User.role == ROLE_OWNER, User.role == ROLE_ADMIN))
    else:
        query = query.filter_by(role=ROLE_OWNER)
    users = query.all()
    return [user.email for user in users if user.email]


def get_number_users(
    tree: Optional[str] = None, roles: Optional[Sequence[int]] = None
) -> int:
    """Get the number of users in the database.

    Optionally, provide an iterable of numeric roles and/or a tree ID.
    """
    query = user_db.session.query(User)  # pylint: disable=no-member
    if roles is not None:
        query = query.filter(User.role.in_(roles))
    if tree is not None:
        query = query.filter_by(tree=tree)
    return query.count()


def fill_tree(tree: str) -> None:
    """Fill the tree column with a tree ID, if empty."""
    (
        user_db.session.query(User)  # pylint: disable=no-member
        .filter(coalesce(User.tree, "") == "")  # treat "" and NULL equally
        .update({User.tree: tree}, synchronize_session=False)
    )
    user_db.session.commit()  # pylint: disable=no-member


_TRUE_VALUES = {"1", "true", "t", "yes", "y", "on"}
_FALSE_VALUES = {"0", "false", "f", "no", "n", "off"}


def _get_base_config() -> Dict[str, Any]:
    """Return base app config without DB overrides."""
    return current_app.config.get("_BASE_CONFIG", current_app.config)


def _get_config_template_value(key: str) -> Any:
    """Return the template value used to infer/parse types."""
    base_config = _get_base_config()
    if key in base_config:
        return base_config[key]
    return current_app.config.get(key)


def _parse_bool(value: Any) -> bool:
    """Parse a boolean value from common string/int representations."""
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError("Invalid boolean value")


def _parse_config_value(value: Any, template: Any) -> Any:
    """Parse a config value to match the template type as closely as possible."""
    if isinstance(template, bool):
        return _parse_bool(value)

    if isinstance(template, int) and not isinstance(template, bool):
        if isinstance(value, int):
            return value
        return int(str(value).strip())

    if isinstance(template, float):
        if isinstance(value, float):
            return value
        return float(str(value).strip())

    if isinstance(template, dict):
        parsed = json.loads(value) if isinstance(value, str) else value
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object")
        return parsed

    if isinstance(template, list):
        parsed = json.loads(value) if isinstance(value, str) else value
        if not isinstance(parsed, list):
            raise ValueError("Expected a JSON array")
        return parsed

    if isinstance(template, tuple):
        parsed = json.loads(value) if isinstance(value, str) else value
        if isinstance(parsed, list):
            return tuple(parsed)
        raise ValueError("Expected a JSON array")

    if isinstance(template, set):
        parsed = json.loads(value) if isinstance(value, str) else value
        if isinstance(parsed, list):
            return set(parsed)
        raise ValueError("Expected a JSON array")

    if isinstance(template, timedelta):
        if isinstance(value, timedelta):
            return value
        if isinstance(value, (int, float)):
            return timedelta(seconds=float(value))
        value_str = str(value).strip()
        if value_str == "":
            raise ValueError("Invalid duration value")
        # Allow HH:MM:SS format.
        parts = value_str.split(":")
        if len(parts) == 3:
            try:
                hours = float(parts[0])
                minutes = float(parts[1])
                seconds = float(parts[2])
                return timedelta(hours=hours, minutes=minutes, seconds=seconds)
            except ValueError:
                pass
        # Allow raw numeric seconds, with or without JSON encoding.
        try:
            return timedelta(seconds=float(value_str))
        except ValueError:
            pass
        try:
            parsed = json.loads(value_str)
            if isinstance(parsed, (int, float)):
                return timedelta(seconds=float(parsed))
        except json.JSONDecodeError:
            pass
        raise ValueError("Invalid duration value")

    if template is None:
        if value is None:
            return None
        if isinstance(value, str):
            stripped = value.strip()
            if stripped == "":
                return ""
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return value
        return value

    if isinstance(template, str):
        if value is None:
            return ""
        return str(value)

    # Fallback for unsupported template types: keep the submitted string/value.
    return value


def _serialize_config_value(value: Any) -> str:
    """Serialize a config value for DB storage."""
    if isinstance(value, str):
        return value
    if isinstance(value, tuple):
        value = list(value)
    if isinstance(value, set):
        value = sorted(value)
    if isinstance(value, timedelta):
        return str(value.total_seconds())
    if value is None or isinstance(value, (bool, int, float, list, dict)):
        return json.dumps(value)
    return str(value)


def _get_parsed_config_value(key: str, stored_value: str) -> Any:
    """Parse a stored DB value according to key template."""
    template = _get_config_template_value(key)
    return _parse_config_value(stored_value, template)


def _infer_config_type_name(template: Any) -> str:
    """Infer a frontend-friendly type string."""
    if isinstance(template, bool):
        return "bool"
    if isinstance(template, int) and not isinstance(template, bool):
        return "int"
    if isinstance(template, float):
        return "float"
    if isinstance(template, (dict, list, tuple, set)):
        return "json"
    if isinstance(template, timedelta):
        return "duration"
    if template is None:
        return "str"
    return "str"


def config_get(key: str, typed: bool = False) -> Optional[Any]:
    """Get a single config item.

    Returns:
      - raw stored value string by default
      - parsed value (`typed=True`)
    """
    query = user_db.session.query(Config)  # pylint: disable=no-member
    config = query.filter_by(key=key).scalar()
    if config is None:
        return None
    if typed:
        return _get_parsed_config_value(key, config.value)
    return config.value


def config_get_all() -> Dict[str, str]:
    """Get all config items as dictionary."""
    query = user_db.session.query(Config)  # pylint: disable=no-member
    configs = query.all()
    return {c.key: c.value for c in configs}


def config_get_all_described() -> Dict[str, Dict[str, Any]]:
    """Get all editable config keys with effective values and metadata."""
    base_config = _get_base_config()
    overrides = config_get_all()
    allowed_keys = set(get_db_config_allowed_keys(base_config)) | set(overrides.keys())
    data = {}
    for key in sorted(allowed_keys):
        template = base_config.get(key)
        if key in overrides:
            value = overrides[key]
            overridden = True
        else:
            value = _serialize_config_value(current_app.config.get(key, template))
            overridden = False
        data[key] = {
            "value": value,
            "overridden": overridden,
            "type": _infer_config_type_name(template),
        }
    return data


def config_set(key: str, value: Any) -> None:
    """Set a config item and apply it to the running app config."""
    base_config = _get_base_config()
    if not is_db_config_key_allowed(key, base_config):
        raise ValueError("Config key not allowed.")
    parsed_value = _parse_config_value(value, _get_config_template_value(key))
    stored_value = _serialize_config_value(parsed_value)
    query = user_db.session.query(Config)  # pylint: disable=no-member
    config = query.filter_by(key=key).scalar()
    if config is None:  # does not exist, create
        config = Config(key=str(key), value=stored_value)
    else:  # exists, update
        config.value = stored_value
    user_db.session.add(config)  # pylint: disable=no-member
    user_db.session.commit()  # pylint: disable=no-member
    current_app.config[key] = copy.deepcopy(parsed_value)


def config_delete(key: str) -> None:
    """Delete a config item and restore runtime value from base config."""
    query = user_db.session.query(Config)  # pylint: disable=no-member
    config = query.filter_by(key=key).scalar()
    if config is not None:
        user_db.session.delete(config)  # pylint: disable=no-member
        user_db.session.commit()  # pylint: disable=no-member
    base_config = _get_base_config()
    if key in base_config:
        current_app.config[key] = copy.deepcopy(base_config[key])
    else:
        current_app.config.pop(key, None)


def apply_db_config_overrides() -> None:
    """Apply all persisted DB config overrides to current app config."""
    try:
        query = user_db.session.query(Config)  # pylint: disable=no-member
        configs = query.all()
    except OperationalError:
        # Table does not exist yet during first startup/migration.
        return

    base_config = _get_base_config()
    for config in configs:
        if not is_db_config_key_allowed(config.key, base_config):
            continue
        try:
            parsed_value = _get_parsed_config_value(config.key, config.value)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            current_app.logger.warning(
                "Ignoring invalid persisted config override for %s: %s",
                config.key,
                exc,
            )
            continue
        current_app.config[config.key] = copy.deepcopy(parsed_value)


def get_tree_usage(tree: str) -> Optional[dict[str, int]]:
    """Get tree usage info."""
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj: Tree = query.filter_by(id=tree).scalar()
    if tree_obj is None:
        return None
    return {
        "quota_media": tree_obj.quota_media,
        "quota_people": tree_obj.quota_people,
        "quota_ai": tree_obj.quota_ai,
        "usage_media": tree_obj.usage_media,
        "usage_people": tree_obj.usage_people,
        "usage_ai": tree_obj.usage_ai,
    }


def get_tree_permissions(tree: str) -> Optional[dict[str, int]]:
    """Get tree permissions."""
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj: Tree = query.filter_by(id=tree).scalar()
    if tree_obj is None:
        return None
    return {"min_role_ai": tree_obj.min_role_ai}


def set_tree_usage(
    tree: str,
    usage_media: Optional[int] = None,
    usage_people: Optional[int] = None,
    usage_ai: Optional[int] = None,
) -> None:
    """Set the tree usage data."""
    if usage_media is None and usage_people is None and usage_ai is None:
        return
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj: Tree = query.filter_by(id=tree).scalar()
    if not tree_obj:
        tree_obj = Tree(id=tree)
    if usage_media is not None:
        tree_obj.usage_media = usage_media
    if usage_people is not None:
        tree_obj.usage_people = usage_people
    if usage_ai is not None:
        tree_obj.usage_ai = usage_ai
    user_db.session.add(tree_obj)  # pylint: disable=no-member
    user_db.session.commit()  # pylint: disable=no-member


def set_tree_details(
    tree: str,
    quota_media: Optional[int] = None,
    quota_people: Optional[int] = None,
    min_role_ai: Optional[int] = None,
) -> None:
    """Set the tree details like quotas and minimum role for chat."""
    if quota_media is None and quota_people is None and min_role_ai is None:
        return
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj = query.filter_by(id=tree).scalar()
    if not tree_obj:
        tree_obj = Tree(id=tree)
    if quota_media is not None:
        tree_obj.quota_media = quota_media
    if quota_people is not None:
        tree_obj.quota_people = quota_people
    if min_role_ai is not None:
        tree_obj.min_role_ai = min_role_ai
    user_db.session.add(tree_obj)  # pylint: disable=no-member
    user_db.session.commit()  # pylint: disable=no-member


def disable_enable_tree(tree: str, disabled: bool) -> None:
    """Disable or enable a tree."""
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj = query.filter_by(id=tree).scalar()
    if not tree_obj:
        tree_obj = Tree(id=tree)
    tree_obj.enabled = 0 if disabled else 1
    user_db.session.add(tree_obj)  # pylint: disable=no-member
    user_db.session.commit()  # pylint: disable=no-member


def is_tree_disabled(tree: str) -> bool:
    """Check if tree is disabled."""
    query = user_db.session.query(Tree)  # pylint: disable=no-member
    tree_obj = query.filter_by(id=tree).scalar()
    if not tree_obj:
        return False
    return tree_obj.enabled == 0


def create_oidc_account(
    user_id: str, provider_id: str, subject_id: str, email: Optional[str] = None
) -> None:
    """Create a new OIDC account association."""
    oidc_account = OIDCAccount(
        user_id=user_id,
        provider_id=provider_id,
        subject_id=subject_id,
        email=email,
    )
    user_db.session.add(oidc_account)  # pylint: disable=no-member
    user_db.session.commit()  # pylint: disable=no-member


def get_oidc_account(provider_id: str, subject_id: str) -> Optional[str]:
    """Get user ID by OIDC provider_id and subject_id."""
    query = user_db.session.query(OIDCAccount.user_id)  # pylint: disable=no-member
    oidc_account = query.filter_by(
        provider_id=provider_id, subject_id=subject_id
    ).scalar()
    return oidc_account


def get_user_oidc_accounts(user_id: str) -> List[Dict[str, Any]]:
    """Get all OIDC accounts associated with a user."""
    query = user_db.session.query(OIDCAccount)  # pylint: disable=no-member
    oidc_accounts = query.filter_by(user_id=user_id).all()
    return [
        {
            "provider_id": account.provider_id,
            "subject_id": account.subject_id,
            "email": account.email,
            "created_at": account.created_at,
        }
        for account in oidc_accounts
    ]


class User(user_db.Model):  # type: ignore
    """User table class for sqlalchemy."""

    __tablename__ = "users"

    id = mapped_column(GUID, primary_key=True)
    name = mapped_column(sa.String, unique=True, nullable=False)
    email = mapped_column(sa.String, unique=True)
    fullname = mapped_column(sa.String)
    pwhash = mapped_column(sa.String, nullable=False)
    role = mapped_column(sa.Integer, default=0)
    tree = mapped_column(sa.String, index=True)

    def __repr__(self):
        """Return string representation of instance."""
        return f"<User(name='{self.name}', fullname='{self.fullname}')>"


class Config(user_db.Model):  # type: ignore
    """Config table class for sqlalchemy."""

    __tablename__ = "configuration"

    id = mapped_column(sa.Integer, primary_key=True)
    key = mapped_column(sa.String, unique=True, nullable=False)
    value = mapped_column(sa.String)

    def __repr__(self):
        """Return string representation of instance."""
        return f"<Config(key='{self.key}', value='{self.value}')>"


class Tree(user_db.Model):  # type: ignore
    """Config table class for sqlalchemy."""

    __tablename__ = "trees"

    id = mapped_column(sa.String, primary_key=True)
    quota_media = mapped_column(sa.BigInteger)
    quota_people = mapped_column(sa.Integer)
    quota_ai = mapped_column(sa.Integer)
    usage_media = mapped_column(sa.BigInteger)
    usage_people = mapped_column(sa.Integer)
    usage_ai = mapped_column(sa.Integer)
    min_role_ai = mapped_column(sa.Integer)
    enabled = mapped_column(sa.Integer, default=1, server_default="1")

    def __repr__(self):
        """Return string representation of instance."""
        return f"<Tree(id='{self.id}')>"


class OIDCAccount(user_db.Model):  # type: ignore
    """OIDC account association table for secure provider_id and subject_id mapping."""

    __tablename__ = "oidc_accounts"

    id = mapped_column(sa.Integer, primary_key=True, autoincrement=True)
    user_id = mapped_column(
        GUID, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    provider_id = mapped_column(sa.String(64), nullable=False)
    subject_id = mapped_column(sa.String(255), nullable=False)
    email = mapped_column(sa.String(255), nullable=True, index=True)
    created_at = mapped_column(
        sa.DateTime, nullable=False, server_default=sa.func.now()
    )

    __table_args__ = (
        sa.UniqueConstraint(
            "provider_id", "subject_id", name="uq_oidc_provider_subject"
        ),
    )

    def __repr__(self):
        """Return string representation of instance."""
        return f"<OIDCAccount(provider_id='{self.provider_id}', subject_id='{self.subject_id}', user_id='{self.user_id}')>"
