# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from copy import copy
from datetime import datetime
from unittest.mock import AsyncMock, patch, MagicMock

import pytest
from freezegun import freeze_time
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests

from api.middlewares import _cleanup_detail_field, \
    check_rate_limit, prevent_bruteforce_attack, unlock_ip, ip_block, ip_stats

@pytest.fixture
def request_info(request):
    """Return the dictionary of the parametrize"""
    return request.param if 'prevent_bruteforce_attack' in request.node.name else None

@pytest.fixture
def mock_request(request, request_info):
    """fixture to wrap functions with request"""
    req = MagicMock()
    req.client.host = 'ip'
    if 'prevent_bruteforce_attack' in request.node.name:
        for clave, valor in request_info.items():
            setattr(req, clave, valor)

    return req

class DummyRequest:
    def __init__(self, data: dict):
        self.data = data

        # Set properties
        for k, v in data.items():
            setattr(self, k, v)

    def __contains__(self, item):
        return item in self.data

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def json(self):
        return self.data


handler_mock = AsyncMock()


def test_cleanup_detail_field():
    """Test `_cleanup_detail_field` function."""
    detail = """Testing

    Details field.
    """

    assert _cleanup_detail_field(detail) == "Testing. Details field."


@pytest.mark.asyncio
@patch("api.middlewares.ip_stats", new={'ip': {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
async def test_middlewares_unlock_ip(mock_request):
    """Test unlock_ip function."""
    # Assert they are not empty
    assert ip_stats and ip_block
    await unlock_ip(mock_request, 5)
    # Assert that under these conditions, they have been emptied
    assert not ip_stats and not ip_block


@patch("api.middlewares.ip_stats", new={"ip": {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@freeze_time(datetime(1970, 1, 1))
@pytest.mark.asyncio
async def test_middlewares_unlock_ip_ko(mock_request):
    """Test if `unlock_ip` raises an exception if the IP is still blocked."""
    with patch("api.middlewares.raise_if_exc") as raise_mock:
        await unlock_ip(mock_request, 5)
        raise_mock.assert_called_once_with(WazuhPermissionError(6000))


@pytest.mark.asyncio
@pytest.mark.parametrize('stats', [
    {},
    {'ip': {'attempts': 4}},
])
@pytest.mark.parametrize('request_info', [
    {'path': '/security/user/authenticate', 'method': 'GET'},
    {'path': '/security/user/authenticate', 'method': 'POST'},
    {'path': '/security/user/authenticate/run_as', 'method': 'POST'},
], indirect=True)
async def test_middlewares_prevent_bruteforce_attack(stats, request_info, mock_request):
    """Test `prevent_bruteforce_attack` blocks IPs when reaching max number of attempts."""
    with patch("api.middlewares.ip_stats", new=copy(stats)):
        previous_attempts = ip_stats['ip']['attempts'] if 'ip' in ip_stats else 0
        await prevent_bruteforce_attack(mock_request,
                                        attempts=5)
        if stats:
            # There were previous attempts. This one reached the limit
            assert ip_stats['ip']['attempts'] == previous_attempts + 1
            assert 'ip' in ip_block
        else:
            # There were not previous attempts
            assert ip_stats['ip']['attempts'] == 1
            assert 'ip' not in ip_block


@freeze_time(datetime(1970, 1, 1))
@pytest.mark.parametrize("current_time,max_requests,current_time_key, current_counter_key,expected_error_args", [
    (-80, 300, 'events_current_time', 'events_request_counter', {}),
    (-80, 300, 'general_current_time', 'general_request_counter', {}),
    (0, 0, 'events_current_time', 'events_request_counter', {
        'code': 6005,
        'extra_message': 'For POST /events endpoint the limit is set to 0 requests.'
    }),
    (0, 0, 'general_current_time', 'general_request_counter', {'code': 6001}),
])
@pytest.mark.asyncio
async def test_middlewares_check_rate_limit(
    current_time, max_requests, current_time_key, current_counter_key,
    expected_error_args, mock_request
):
    """Test if the rate limit mechanism triggers when the `max_requests` are reached."""

    with patch(f"api.middlewares.{current_time_key}", new=current_time):
        with patch("api.middlewares.raise_if_exc") as raise_mock:
            await check_rate_limit(
                mock_request,
                current_time_key=current_time_key,
                request_counter_key=current_counter_key,
                max_requests=max_requests)
            if max_requests == 0:
                raise_mock.assert_called_once_with(WazuhTooManyRequests(**expected_error_args))


# @patch("api.middlewares.unlock_ip")
# @patch("api.middlewares.check_rate_limit")
# @pytest.mark.parametrize(
#     "request_body,expected_calls,call_args",
#     [
#         ({"path": "/events"}, 2, ['events_request_counter', 'events_current_time', 5]),
#         ({"path": "some_path"}, 1, ['general_request_counter', 'general_current_time', 5])
#     ]
# )
# @pytest.mark.asyncio
# async def test_middlewares_security_middleware(
#     rate_limit_mock, unlock_mock, request_body, expected_calls, call_args
# ):
#     """Test that all security middlewares are correctly set following the API configuration."""
#     max_req = 5
#     block_time = 10
#     request = DummyRequest(request_body)

#     with patch(
#         "api.middlewares.api_conf",
#         new={'access': {'max_request_per_minute': max_req, 'block_time': block_time}}
#     ):
#         with patch("api.middlewares.MAX_REQUESTS_EVENTS_DEFAULT", max_req):

#             await security_middleware(request, handler_mock)

#             assert rate_limit_mock.call_count == expected_calls
#             rate_limit_mock.assert_called_with(request, *call_args)

#             unlock_mock.assert_called_once_with(request, block_time=block_time)
