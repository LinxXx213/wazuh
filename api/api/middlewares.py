# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import hashlib
import time
import contextlib
import logging

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from connexion import ConnexionMiddleware
from connexion.lifecycle import ConnexionRequest
from secure import Secure, ContentSecurityPolicy, XFrameOptions, Server
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests
from wazuh.core.utils import get_utc_now

from api import configuration
from api.util import raise_if_exc, custom_logging

# Default of the max event requests allowed per minute
MAX_REQUESTS_EVENTS_DEFAULT = 30

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"

# API secure headers
server = Server().set("Wazuh")
csp = ContentSecurityPolicy()
csp.default_src('self')
xfo = XFrameOptions().deny()
secure_headers = Secure(server=server, csp=csp, xfo=xfo)

logger = logging.getLogger('wazuh-api')

class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Set secure headers Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """dispatch secure headers.
        
        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """
        resp = await call_next(request)
        secure_headers.framework.starlette(resp)
        return resp


ip_stats = dict()
ip_block = set()
general_request_counter = 0
general_current_time = None
events_request_counter = 0
events_current_time = None


def unlock_ip(request: Request, block_time: int):
    """This function blocks/unblocks the IPs that are requesting an API token.

    Parameters
    ----------
    request : Request
        HTTP request.
    block_time : int
        Block time used to decide if the IP is going to be unlocked.
    """
    global ip_block, ip_stats
    try:
        if get_utc_now().timestamp() - block_time >= ip_stats[request.client.host]['timestamp']:
            del ip_stats[request.client.host]
            ip_block.remove(request.client.host)
    except (KeyError, ValueError):
        pass

    if request.client.host in ip_block:
        msg = f'IP blocked due to exceeded number of logins attempts: {request.client.host}'
        logger.warning(msg)
        raise_if_exc(WazuhPermissionError(6000))


def check_rate_limit(
    request: Request,
    request_counter_key: str,
    current_time_key: str,
    max_requests: int
) -> None:
    """This function checks that the maximum number of requests per minute
    passed in `max_requests` is not exceeded.

    Parameters
    ----------
    request : Request
        HTTP request.
    request_counter_key : str
        Key of the request counter variable to get from globals() dict.
    current_time_key : str
        Key of the current time variable to get from globals() dict.
    max_requests : int, optional
        Maximum number of requests per minute permitted.
    """

    error_code_mapping = {
        'general_request_counter': {'code': 6001},
        'events_request_counter': {
            'code': 6005,
            'extra_message': f'For POST /events endpoint the limit is set to {max_requests} requests.'
        }
    }
    if not globals()[current_time_key]:
        globals()[current_time_key] = get_utc_now().timestamp()

    if get_utc_now().timestamp() - 60 <= globals()[current_time_key]:
        globals()[request_counter_key] += 1
    else:
        globals()[request_counter_key] = 0
        globals()[current_time_key] = get_utc_now().timestamp()

    if globals()[request_counter_key] > max_requests:
        logger.debug(f'Request rejected due to high request per minute: Source IP: {request.client.host}')
        raise_if_exc(WazuhTooManyRequests(**error_code_mapping[request_counter_key]))


class CheckRateLimitsMiddleware(BaseHTTPMiddleware):
    """Check request Limits Middleware."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """"Check request limits per minute"""
        access_conf = configuration.api_conf['access']
        max_request_per_minute = access_conf['max_request_per_minute']

        if max_request_per_minute > 0:
            check_rate_limit(
                request,
                'general_request_counter',
                'general_current_time',
                max_request_per_minute
            )

            if request.url.path == '/events':
                check_rate_limit(
                    request,
                    'events_request_counter',
                    'events_current_time',
                    MAX_REQUESTS_EVENTS_DEFAULT
                )

        unlock_ip(request, block_time=access_conf['block_time'])
        return await call_next(request)


class WazuhAccessLoggerMiddleware(BaseHTTPMiddleware):
    """Middleware to log custom Access messages."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Log Wazuh access information.

        Additionally, it cleans the output given by connexion's exceptions.
        If no exception is raised during the 'await call_next(request) it means
        the output will be a 200 response and no fields needs to be removed.
        If call_next raises an exception, an error handler will create the response.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Returned response.
        """
        prev_time = time.time()
        body = await request.json() \
                    if 'json' in request.headers.get('content-type', '') and \
                    int(request.headers.get('content-length', '0')) > 0 \
                    else {}
        handler, exc_raised = None, None
        try:
            response = await call_next(request)
        except Exception as exc:
            handler = next((func for e, func in request.app.error_handlers if exc.__class__ == e), None)
            exc_raised = exc
        req = ConnexionRequest.from_starlette_request(request)
        if handler:
            response = await handler(req, exc_raised)
        elif exc_raised:
            raise exc
        time_diff = time.time() - prev_time

        query = dict(req.query_params)
        if 'password' in query:
            query['password'] = '****'
        if 'password' in body:
            body['password'] = '****'
        if 'key' in body and '/agents' in req.scope['path']:
            body['key'] = '****'

        # With permanent redirect, not found responses or any response with no token information,
        # decode the JWT token to get the username
        user = req.context.get('user', UNKNOWN_USER_STRING)

        # Get or create authorization context hash
        hash_auth_context = req.context.get('token_info', {}).get('hash_auth_context', '')
        # Create hash if run_as login
        if not hash_auth_context and req.scope['path'] == RUN_AS_LOGIN_ENDPOINT:
            hash_auth_context = hashlib.blake2b(json.dumps(body).encode(),
                                                digest_size=16).hexdigest()

        custom_logging(user, req.client.host, req.method,
                       req.scope['path'], query, body, time_diff, response.status_code,
                       hash_auth_context=hash_auth_context, headers=req.headers)
        return response


@contextlib.asynccontextmanager
async def lifespan_handler(_: ConnexionMiddleware):
    """Lifespan handler to start tasks at startup."""

    # Log the initial server startup message.
    msg = f'Listening on {configuration.api_conf["host"]}:{configuration.api_conf["port"]}.'
    logger.info(msg)
    yield
    logger.info('Shutdown wazuh-apid server.')
