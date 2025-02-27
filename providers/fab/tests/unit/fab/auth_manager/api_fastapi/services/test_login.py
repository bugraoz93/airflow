# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from starlette.exceptions import HTTPException

from airflow.providers.fab.auth_manager.api_fastapi.services.login import FABAuthManagerLogin

if TYPE_CHECKING:
    from airflow.providers.fab.auth_manager.api_fastapi.datamodels.login import LoginResponse

"""
        dummy_security_manager = MagicMock()
        dummy_user = MagicMock()
        mock_fab_auth_manager_login.return_value.security_manager = dummy_security_manager
        dummy_security_manager.find_user.return_value = dummy_user
        dummy_user.password = "dummy"

"""


class TestLogin:
    def setup_method(
        self,
    ):
        self.dummy_auth_manager = MagicMock()
        self.dummy_app_builder = MagicMock()
        self.dummy_app = MagicMock()
        self.dummy_login_body = MagicMock()
        self.dummy_user = MagicMock()
        self.dummy_user.password = "dummy"
        self.dummy_security_manager = MagicMock()
        self.dummy_login_body.username = "dummy"
        self.dummy_login_body.password = "dummy"
        self.dummy_token = "DUMMY_TOKEN"

    @patch("airflow.providers.fab.auth_manager.api_fastapi.services.login.get_auth_manager")
    def test_create_token(self, get_auth_manager):
        get_auth_manager.return_value = self.dummy_auth_manager
        self.dummy_auth_manager.security_manager = self.dummy_security_manager
        self.dummy_security_manager.find_user.return_value = self.dummy_user
        print(f"User in test: {self.dummy_user}")
        self.dummy_auth_manager.get_jwt_token.return_value = self.dummy_token

        login_response: LoginResponse = FABAuthManagerLogin.create_token(
            body=self.dummy_login_body,
            expiration_time_in_sec=1,
        )
        assert login_response.jwt_token == self.dummy_token

    @patch("airflow.providers.fab.auth_manager.api_fastapi.services.login.get_auth_manager")
    def test_create_token_invalid_username(self, get_auth_manager):
        get_auth_manager.return_value = self.dummy_auth_manager
        self.dummy_auth_manager.security_manager = self.dummy_security_manager
        self.dummy_security_manager.find_user.return_value = None

        with pytest.raises(HTTPException) as ex:
            FABAuthManagerLogin.create_token(
                body=self.dummy_login_body,
                expiration_time_in_sec=1,
            )
        assert ex.value.status_code == 401
        assert ex.value.detail == "Invalid username"

    @patch("airflow.providers.fab.auth_manager.api_fastapi.services.login.get_auth_manager")
    def test_create_token_invalid_password(self, get_auth_manager):
        get_auth_manager.return_value = self.dummy_auth_manager
        self.dummy_auth_manager.security_manager = self.dummy_security_manager
        self.dummy_security_manager.find_user.return_value = self.dummy_user
        self.dummy_user.password = "invalid_password"

        with pytest.raises(HTTPException) as ex:
            FABAuthManagerLogin.create_token(
                body=self.dummy_login_body,
                expiration_time_in_sec=1,
            )
        assert ex.value.status_code == 401
        assert ex.value.detail == "Invalid password"

    @patch("airflow.providers.fab.auth_manager.api_fastapi.services.login.get_auth_manager")
    def test_create_token_empty_user_password(self, get_auth_manager):
        get_auth_manager.return_value = self.dummy_auth_manager
        self.dummy_auth_manager.security_manager = self.dummy_security_manager
        self.dummy_security_manager.find_user.return_value = self.dummy_user
        self.dummy_login_body.username = ""
        self.dummy_login_body.password = ""

        with pytest.raises(HTTPException) as ex:
            FABAuthManagerLogin.create_token(
                body=self.dummy_login_body,
                expiration_time_in_sec=1,
            )
        assert ex.value.status_code == 400
        assert ex.value.detail == "Username and password must be provided"
