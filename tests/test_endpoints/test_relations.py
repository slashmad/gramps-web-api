#
# Gramps Web API - A RESTful API for the Gramps genealogy program
#
# Copyright (C) 2020      Christopher Horn
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

"""Tests for the /api/relations endpoints using example_gramps."""

import unittest
import uuid

from . import BASE_URL, get_test_client
from .checks import (
    check_invalid_semantics,
    check_requires_token,
    check_resource_missing,
    check_success,
)
from .util import fetch_header

TEST_URL = BASE_URL + "/relations/"


class TestRelations(unittest.TestCase):
    """Test cases for the /api/relations/{handle1}/{handle2} endpoint."""

    @classmethod
    def setUpClass(cls):
        """Test class setup."""
        cls.client = get_test_client()

    def test_get_relations_requires_token(self):
        """Test authorization required."""
        check_requires_token(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L")

    def test_get_relations_expected_result(self):
        """Test request produces expected result."""
        rv = check_success(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L")
        self.assertEqual(
            rv,
            {
                "distance_common_origin": 5,
                "distance_common_other": 1,
                "relationship_string": "second great stepgrandaunt",
            },
        )

    def test_get_relations_missing_content(self):
        """Test response for missing content."""
        check_resource_missing(self, TEST_URL + "9BXKQC1PVLPYFMD6IX")
        check_resource_missing(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR1")
        check_resource_missing(self, TEST_URL + "9BXKQC1PVLPYFMD6I/ORFKQC4KLWEGTGR19L")

    def test_get_relations_validate_semantics(self):
        """Test invalid parameters and values."""
        check_invalid_semantics(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?junk=1"
        )

    def test_get_relations_parameter_depth_validate_semantics(self):
        """Test invalid depth parameter and values."""
        check_invalid_semantics(
            self,
            TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?depth",
            check="number",
        )

    def test_get_relations_parameter_include_associations_validate_semantics(self):
        """Test invalid include_associations parameter and values."""
        check_invalid_semantics(
            self,
            TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?include_associations",
            check="boolean",
        )

    def test_get_relations_parameter_include_partner_links_validate_semantics(self):
        """Test invalid include_partner_links parameter and values."""
        check_invalid_semantics(
            self,
            TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?include_partner_links",
            check="boolean",
        )

    def test_get_relations_parameter_depth_expected_result(self):
        """Test depth parameter working as expected."""
        rv = check_success(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?depth=5"
        )
        self.assertEqual(rv["relationship_string"], "")
        rv = check_success(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?depth=6"
        )
        self.assertEqual(rv["relationship_string"], "second great stepgrandaunt")

    def test_get_relations_parameter_locale_validate_semantics(self):
        """Test invalid locale parameter and values."""
        check_invalid_semantics(
            self,
            TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?locale",
            check="base",
        )

    def test_get_relations_parameter_locale_expected_result(self):
        """Test locale parameter working as expected."""
        rv = check_success(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L")
        self.assertEqual(rv["relationship_string"], "second great stepgrandaunt")
        rv = check_success(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L?locale=de"
        )
        self.assertEqual(rv["relationship_string"], "Stief-/Adoptivalttante")

    def test_get_relations_parameter_locale_expected_result_partner(self):
        """Test locale parameter working as expected."""
        rv = check_success(self, TEST_URL + "cc8205d87831c772e87/cc8205d872f532ab14e")
        self.assertEqual(rv["relationship_string"], "husband")
        rv = check_success(
            self, TEST_URL + "cc8205d87831c772e87/cc8205d872f532ab14e?locale=it"
        )
        self.assertEqual(rv["relationship_string"], "marito")

    def test_get_relations_include_associations_expected_result(self):
        """Test association bridge payload for non-family connected people."""
        headers = fetch_header(self.client)
        handles = {
            "home": str(uuid.uuid4()),
            "bridge": str(uuid.uuid4()),
            "target": str(uuid.uuid4()),
        }

        payload_target = {"_class": "Person", "handle": handles["target"]}
        payload_bridge = {
            "_class": "Person",
            "handle": handles["bridge"],
            "person_ref_list": [
                {"_class": "PersonRef", "rel": "Friend", "ref": handles["target"]}
            ],
        }
        payload_home = {
            "_class": "Person",
            "handle": handles["home"],
            "person_ref_list": [
                {"_class": "PersonRef", "rel": "Friend", "ref": handles["bridge"]}
            ],
        }

        try:
            self.assertEqual(
                self.client.post(
                    "/api/people/", json=payload_target, headers=headers
                ).status_code,
                201,
            )
            self.assertEqual(
                self.client.post(
                    "/api/people/", json=payload_bridge, headers=headers
                ).status_code,
                201,
            )
            self.assertEqual(
                self.client.post(
                    "/api/people/", json=payload_home, headers=headers
                ).status_code,
                201,
            )

            rv = self.client.get(
                TEST_URL
                + f'{handles["home"]}/{handles["target"]}?include_associations=1&depth=5',
                headers=headers,
            )
            self.assertEqual(rv.status_code, 200)
            self.assertEqual(rv.json["relationship_string"], "")
            self.assertIn("association_via", rv.json)
            self.assertEqual(rv.json["association_via"]["handle"], handles["bridge"])
            self.assertEqual(rv.json["association_via"]["path_length"], 2)
        finally:
            self.client.delete(f'/api/people/{handles["home"]}', headers=headers)
            self.client.delete(f'/api/people/{handles["bridge"]}', headers=headers)
            self.client.delete(f'/api/people/{handles["target"]}', headers=headers)


class TestRelationsAll(unittest.TestCase):
    """Test cases for the /api/relations/{handle1}/{handle2}/all endpoint."""

    @classmethod
    def setUpClass(cls):
        """Test class setup."""
        cls.client = get_test_client()

    def test_get_relations_all_requires_token(self):
        """Test authorization required."""
        check_requires_token(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all"
        )

    def test_get_relations_all_expected_result(self):
        """Test response for valid request."""
        rv = check_success(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all")
        self.assertIn("common_ancestors", rv[0])
        self.assertEqual(rv[0]["relationship_string"], "second great stepgrandaunt")

    def test_get_relations_all_missing_content(self):
        """Test response for missing content."""
        check_resource_missing(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/all")
        check_resource_missing(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR1/all"
        )
        check_resource_missing(
            self, TEST_URL + "9BXKQC1PVLPYFMD6I/ORFKQC4KLWEGTGR19L/all"
        )

    def test_get_relations_all_validate_semantics(self):
        """Test invalid parameters and values."""
        check_invalid_semantics(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all?junk=1"
        )

    def test_get_relations_all_parameter_depth_validate_semantics(self):
        """Test invalid depth parameter and values."""
        check_invalid_semantics(
            self,
            TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all?depth",
            check="number",
        )

    def test_get_relations_all_parameter_depth_expected_result(self):
        """Test depth parameter working as expected."""
        rv = check_success(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all?depth=5"
        )
        self.assertEqual(rv, [{}])
        rv = check_success(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all?depth=6"
        )
        self.assertEqual(rv[0]["relationship_string"], "second great stepgrandaunt")

    def test_get_relations_all_parameter_locale_validate_semantics(self):
        """Test invalid locale parameter and values."""
        check_invalid_semantics(
            self,
            TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all?locale",
            check="base",
        )

    def test_get_relations_all_parameter_locale_expected_result(self):
        """Test locale parameter working as expected."""
        rv = check_success(self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all")
        self.assertEqual(rv[0]["relationship_string"], "second great stepgrandaunt")
        rv = check_success(
            self, TEST_URL + "9BXKQC1PVLPYFMD6IX/ORFKQC4KLWEGTGR19L/all?locale=de"
        )
        self.assertEqual(rv[0]["relationship_string"], "Stief-/Adoptivalttante")
