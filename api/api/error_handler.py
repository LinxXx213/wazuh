# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from connexion.lifecycle import ConnexionRequest
from starlette.responses import Response

from api import configuration
from api.middlewares import ip_block, ip_stats
from wazuh.core.utils import get_utc_now


def prevent_bruteforce_attack(request: ConnexionRequest, attempts: int = 5):
    """This function checks that the IPs that are requesting an API token do not do so repeatedly.

    Parameters
    ----------
    request : ConnexionRequest
        HTTP request.
    attempts : int
        Number of attempts until an IP is blocked.
    """

    if request.scope['path'] in {'/security/user/authenticate',
                                 '/security/user/authenticate/run_as'} and \
            request.method in {'GET', 'POST'}:
        if request.client.host not in ip_stats:
            ip_stats[request.client.host] = dict()
            ip_stats[request.client.host]['attempts'] = 1
            ip_stats[request.client.host]['timestamp'] = get_utc_now().timestamp()
        else:
            ip_stats[request.client.host]['attempts'] += 1

        if ip_stats[request.client.host]['attempts'] >= attempts:
            ip_block.add(request.client.host)


def _cleanup_detail_field(detail: str) -> str:
    """Replace double endlines with '. ' and simple endlines with ''.

    Parameters
    ----------
    detail : str
        String to be modified.

    Returns
    -------
    str
        New value for the detail field.
    """
    return ' '.join(str(detail).replace("\n\n", ". ").replace("\n", "").split())


async def unauthorized_error_handler(request: ConnexionRequest, exc: Exception) -> Response:
    """HTTP Exception Error handler.
    
    Parameters
    ----------
    request : ConnexionRequest
        Incomming request.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": "Unauthorized",
        "type": "about:blank",
    }

    if request.scope['path'] in {'/security/user/authenticate',
                        '/security/user/authenticate/run_as'} and \
        request.method in {'GET', 'POST'}:
        problem["detail"] = "Invalid credentials"

        prevent_bruteforce_attack(
            request=request,
            attempts=configuration.api_conf['access']['max_login_attempts']
        )
    return Response(status_code=exc.status_code,
                    content=json.dumps(problem),
                    media_type="application/problem+json")


async def bad_request_error_handler(_: ConnexionRequest, exc: Exception) -> Response:
    """HTTP Exception Error handler.
    
    Parameters
    ----------
    _: ConnexionRequest
        Incomming request.
        Parameter not used.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """

    problem = {
        "title": 'Bad Request',
        "type": "about:blank",
    }
    if exc.detail:
        problem['detail'] = exc.detail
    return Response(status_code=exc.status_code,
                    content=json.dumps(problem),
                    media_type="application/problem+json")


async def http_error_handler(_: ConnexionRequest, exc: Exception) -> Response:
    """HTTP Exception Error handler.
    
    Parameters
    ----------
    _ : ConnexionRequest
        Incomming request.
        Unnamed parameter not used.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """

    problem = {
        "title": 'HTTPException',
        "type": "about:blank",
    }
    if exc.detail:
        problem['detail'] = exc.detail
    return Response(status_code=exc.status_code,
                    content=json.dumps(problem),
                    media_type="application/problem+json")


async def jwt_error_handler(_: ConnexionRequest, __: Exception) -> Response:
    """JWT Exception Error handler.
    
    Parameters
    ----------
    _ : ConnexionRequest
        Incomming request.
        Unnamed parameter not used.
    __: Exception
        Raised exception.
        Unnamed parameter not used.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": "Unauthorized",
        "type": "about:blank",
        "detail": "Invalid token"
    }

    return Response(status_code=401,
                    content=json.dumps(problem),
                    media_type="application/problem+json")


async def problem_error_handler(_: ConnexionRequest, exc: Exception) -> Response:
    """ProblemException Error handler.
    
    Parameters
    ----------
    request: ConnexionRequest
        Incomming request.
    exc: Exception
        Raised exception.

    Returns
    -------
    Response
        HTTP Response returned to the client.
    """
    problem = {
        "title": exc.__dict__['title'] if exc.__dict__.get('title') else 'Bad Request',
        "type": exc.__dict__.get('type', 'about:blank'),
        "detail": _cleanup_detail_field(exc.__dict__['detail']) \
                        if 'detail' in exc.__dict__ \
                        else ''
    }
    if exc.__dict__.get('ext'):
        problem.update(exc.__dict__.get('ext', {}))

    if isinstance(problem['detail'], dict):
        for field in ['status', 'type']:
            if field in problem['detail']:
                problem['detail'].pop(field)
    elif problem['detail'] == '':
        del problem['detail']
    if 'code' in problem:
        problem['error'] = problem.pop('code')

    return  Response(content=json.dumps(problem),
                     status_code=exc.__dict__['status'],
                     media_type="application/problem+json")
