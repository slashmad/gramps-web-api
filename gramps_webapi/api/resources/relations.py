#
# Gramps Web API - A RESTful API for the Gramps genealogy program
#
# Copyright (C) 2020      Christopher Horn
# Copyright (C) 2025      David Straub
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

"""Relation API Resource."""

from collections import deque
from typing import Dict

from flask import Response
from gramps.gen.display.name import NameDisplay
from gramps.gen.errors import HandleError
from gramps.gen.relationship import get_relationship_calculator
from webargs import fields, validate

from gramps_webapi.api.people_families_cache import CachePeopleFamiliesProxy

from ...types import Handle
from ..cache import request_cache_decorator
from ..util import abort_with_message, get_db_handle, get_locale_for_language, use_args
from . import ProtectedResource
from .emit import GrampsJSONEncoder
from .util import get_one_relationship


def _build_association_reverse_index(db_handle: CachePeopleFamiliesProxy) -> dict:
    """Build reverse association links (target handle -> source handles)."""
    reverse_index = {}
    for source_person in db_handle.iter_people():
        source_handle = source_person.handle
        for person_ref in source_person.get_person_ref_list():
            if person_ref is None:
                continue
            target_handle = person_ref.get_reference_handle()
            if not target_handle:
                continue
            reverse_index.setdefault(target_handle, set()).add(source_handle)
    return reverse_index


def _get_family_neighbor_handles(
    db_handle: CachePeopleFamiliesProxy, person
) -> dict[str, bool]:
    """Return neighbor handles in the person-family graph."""
    handles: dict[str, bool] = {}
    person_handle = person.handle

    def _merge_edge(handle: str | None, is_partner_edge: bool = False) -> None:
        if not handle:
            return
        handles[handle] = handles.get(handle, False) or is_partner_edge

    for family_handle in person.get_family_handle_list():
        try:
            family = db_handle.get_family_from_handle(family_handle)
        except HandleError:
            continue
        if family is None:
            continue

        father_handle = family.get_father_handle()
        mother_handle = family.get_mother_handle()
        _merge_edge(
            father_handle,
            is_partner_edge=(
                mother_handle == person_handle and father_handle != person_handle
            ),
        )
        _merge_edge(
            mother_handle,
            is_partner_edge=(
                father_handle == person_handle and mother_handle != person_handle
            ),
        )

        for child_ref in family.get_child_ref_list():
            if child_ref and child_ref.ref:
                _merge_edge(child_ref.ref)

    for family_handle in person.get_parent_family_handle_list():
        try:
            family = db_handle.get_family_from_handle(family_handle)
        except HandleError:
            continue
        if family is None:
            continue

        father_handle = family.get_father_handle()
        mother_handle = family.get_mother_handle()
        _merge_edge(father_handle)
        _merge_edge(mother_handle)

        for child_ref in family.get_child_ref_list():
            if child_ref and child_ref.ref:
                _merge_edge(child_ref.ref)

    handles.pop(person_handle, None)
    return handles


def _get_association_neighbor_handles(
    person, association_reverse_index: dict
) -> set[str]:
    """Return person handles connected through associations in either direction."""
    handles = set()
    for person_ref in person.get_person_ref_list():
        if person_ref is None:
            continue
        associated_handle = person_ref.get_reference_handle()
        if associated_handle:
            handles.add(associated_handle)
    handles.update(association_reverse_index.get(person.handle, set()))
    handles.discard(person.handle)
    return handles


def _find_association_path(
    db_handle: CachePeopleFamiliesProxy,
    start_handle: str,
    target_handle: str,
    max_depth: int,
    include_associations: bool,
    include_partner_links: bool,
) -> list[str]:
    """
    Find a shortest path that includes at least one configured bridge edge.

    Path can include family links; bridge edges can be:
    - person associations (if include_associations)
    - partner edges in families (if include_partner_links)
    """
    if start_handle == target_handle:
        return []
    if not include_associations and not include_partner_links:
        return []

    association_reverse_index = _build_association_reverse_index(db_handle)

    queue = deque([(start_handle, [start_handle], False)])  # handle, path, used_bridge
    seen = {(start_handle, False)}

    while queue:
        current_handle, path, used_association = queue.popleft()
        if len(path) - 1 >= max_depth:
            continue

        try:
            current_person = db_handle.get_person_from_handle(current_handle)
        except HandleError:
            continue
        if current_person is None:
            continue

        edge_types = {}
        for neighbor, is_partner_edge in _get_family_neighbor_handles(
            db_handle, current_person
        ).items():
            is_bridge_edge = include_partner_links and is_partner_edge
            edge_types[neighbor] = edge_types.get(neighbor, False) or is_bridge_edge

        if include_associations:
            for neighbor in _get_association_neighbor_handles(
                current_person, association_reverse_index
            ):
                edge_types[neighbor] = True

        for neighbor_handle, is_bridge_edge in edge_types.items():
            next_used_bridge = used_association or is_bridge_edge
            state = (neighbor_handle, next_used_bridge)
            if state in seen:
                continue
            next_path = [*path, neighbor_handle]
            if neighbor_handle == target_handle and next_used_bridge:
                return next_path
            seen.add(state)
            queue.append((neighbor_handle, next_path, next_used_bridge))

    return []


def _build_association_via_payload(
    db_handle: CachePeopleFamiliesProxy, path: list[str], locale
) -> dict:
    """Build response payload describing the first hop from the anchor person."""
    if len(path) < 2:
        return {}

    via_handle = path[1]
    try:
        via_person = db_handle.get_person_from_handle(via_handle)
    except HandleError:
        return {}
    if via_person is None:
        return {}

    name_displayer = NameDisplay(xlocale=locale)
    name_displayer.set_name_format(db_handle.name_formats)

    return {
        "handle": via_person.handle,
        "gramps_id": via_person.gramps_id,
        "name_display": name_displayer.display(via_person),
        "path_length": len(path) - 1,
    }


class RelationResource(ProtectedResource, GrampsJSONEncoder):
    """Relation resource."""

    @use_args(
        {
            "depth": fields.Integer(load_default=15, validate=validate.Range(min=2)),
            "locale": fields.Str(
                load_default=None, validate=validate.Length(min=1, max=5)
            ),
            "include_associations": fields.Boolean(load_default=False),
            "include_partner_links": fields.Boolean(load_default=False),
        },
        location="query",
    )
    @request_cache_decorator
    def get(self, args: Dict, handle1: Handle, handle2: Handle) -> Response:
        """Get the most direct relationship between two people."""
        db_handle = CachePeopleFamiliesProxy(get_db_handle())
        try:
            person1 = db_handle.get_person_from_handle(handle1)
        except HandleError:
            abort_with_message(404, f"Person {handle1} not found")
        try:
            person2 = db_handle.get_person_from_handle(handle2)
        except HandleError:
            abort_with_message(404, f"Person {handle2} not found")

        db_handle.cache_people()
        db_handle.cache_families()

        locale = get_locale_for_language(args["locale"], default=True)
        data = get_one_relationship(
            db_handle=db_handle,
            person1=person1,
            person2=person2,
            depth=args["depth"],
            locale=locale,
        )
        response = {
            "relationship_string": data[0],
            "distance_common_origin": data[1],
            "distance_common_other": data[2],
        }

        if (args["include_associations"] or args["include_partner_links"]) and data[
            0
        ] == "":
            association_path = _find_association_path(
                db_handle=db_handle,
                start_handle=handle1,
                target_handle=handle2,
                max_depth=args["depth"],
                include_associations=args["include_associations"],
                include_partner_links=args["include_partner_links"],
            )
            association_via = _build_association_via_payload(
                db_handle, association_path, locale
            )
            if association_via:
                response["association_via"] = association_via

        return self.response(
            200,
            response,
        )


class RelationsResource(ProtectedResource, GrampsJSONEncoder):
    """Relations resource."""

    @use_args(
        {
            "depth": fields.Integer(load_default=15, validate=validate.Range(min=2)),
            "locale": fields.Str(
                load_default=None, validate=validate.Length(min=1, max=5)
            ),
        },
        location="query",
    )
    @request_cache_decorator
    def get(self, args: Dict, handle1: Handle, handle2: Handle) -> Response:
        """Get all possible relationships between two people."""
        db_handle = CachePeopleFamiliesProxy(get_db_handle())

        try:
            person1 = db_handle.get_person_from_handle(handle1)
        except HandleError:
            abort_with_message(404, f"Person {handle1} not found")

        try:
            person2 = db_handle.get_person_from_handle(handle2)
        except HandleError:
            abort_with_message(404, f"Person {handle2} not found")

        db_handle.cache_people()
        db_handle.cache_families()

        locale = get_locale_for_language(args["locale"], default=True)
        calc = get_relationship_calculator(reinit=True, clocale=locale)
        calc.set_depth(args["depth"])

        data = calc.get_all_relationships(db_handle, person1, person2)
        result = []
        index = 0
        while index < len(data[0]):
            result.append(
                {
                    "relationship_string": data[0][index],
                    "common_ancestors": data[1][index],
                }
            )
            index = index + 1
        if result == []:
            result = [{}]
        return self.response(200, result)
