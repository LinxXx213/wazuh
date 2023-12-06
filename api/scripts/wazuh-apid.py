#!/var/ossec/framework/python/bin/python3

# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import argparse
import os
import signal
import sys
import asyncio
import logging
import logging.config
import ssl

from connexion import AsyncApp
from connexion.options import SwaggerUIOptions
from connexion.exceptions import Unauthorized, HTTPException, BadRequestProblem, ProblemException
from connexion.middleware import MiddlewarePosition
import uvicorn

from starlette.middleware.cors import CORSMiddleware
from content_size_limit_asgi import ContentSizeLimitMiddleware

from jose import JWTError

from api.constants import API_LOG_PATH
from api.api_exception import APIError
from api.configuration import api_conf, read_yaml_config, security_conf, generate_private_key, \
    generate_self_signed_certificate
from api import __path__ as api_path
from api.constants import CONFIG_FILE_PATH
from api.middlewares import SecureHeadersMiddleware, CheckRateLimitsMiddleware, \
    WazuhAccessLoggerMiddleware, lifespan_handler
# from api.signals import modify_response_headers
from api.util import APILoggerSize, to_relative_path
from api import error_handler

from wazuh.rbac.orm import check_database_integrity
from wazuh.core import pyDaemonModule, common, utils
from wazuh.core.cluster import __version__, __author__, __wazuh_name__, __licence__

API_MAIN_PROCESS = 'wazuh-apid'
API_LOCAL_REQUEST_PROCESS = 'wazuh-apid_exec'
API_AUTHENTICATION_PROCESS = 'wazuh-apid_auth'
API_SECURITY_EVENTS_PROCESS = 'wazuh-apid_events'


def spawn_process_pool():
    """Spawn general process pool child."""

    exec_pid = os.getpid()
    pyDaemonModule.create_pid(API_LOCAL_REQUEST_PROCESS, exec_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_events_pool():
    """Spawn events process pool child."""

    events_pid = os.getpid()
    pyDaemonModule.create_pid(API_SECURITY_EVENTS_PROCESS, events_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def spawn_authentication_pool():
    """Spawn authentication process pool child."""

    auth_pid = os.getpid()
    pyDaemonModule.create_pid(API_AUTHENTICATION_PROCESS, auth_pid)

    signal.signal(signal.SIGINT, signal.SIG_IGN)


def assign_wazuh_ownership(filepath):
    """Assign ownership to file."""
    if os.stat(filepath).st_gid != common.wazuh_gid() or \
        os.stat(filepath).st_uid != common.wazuh_uid():
        os.chown(filepath, common.wazuh_uid(), common.wazuh_gid())


def configure_ssl(params):
    """Configure https files and permission, and set the uvicorn dictionary configuration keys.

    Parameters
    ----------
    uvicorn_params : dict
        uvicorn parameter configuration dictionary.

    """
    try:
        # Generate SSL if it does not exist and HTTPS is enabled
        if not os.path.exists(api_conf['https']['key']) \
                or not os.path.exists(api_conf['https']['cert']):
            logger.info('HTTPS is enabled but cannot find the private key and/or certificate. '
                        'Attempting to generate them')
            private_key = generate_private_key(api_conf['https']['key'])
            logger.info(
                f"Generated private key file in WAZUH_PATH/{to_relative_path(api_conf['https']['key'])}")
            generate_self_signed_certificate(private_key, api_conf['https']['cert'])
            logger.info(
                f"Generated certificate file in WAZUH_PATH/{to_relative_path(api_conf['https']['cert'])}")
        
        # Check and assign ownership to wazuh user for server.key and server.crt files
        assign_wazuh_ownership(api_conf['https']['key'])
        assign_wazuh_ownership(api_conf['https']['cert'])

        params['ssl_version'] = ssl.PROTOCOL_TLS_SERVER

        if api_conf['https']['use_ca']:
            params['ssl_cert_reqs'] = ssl.CERT_REQUIRED
            params['ssl_ca_certs'] = api_conf['https']['ca']

        params['ssl_certfile'] = api_conf['https']['cert']
        params['ssl_keyfile'] = api_conf['https']['key']

        # Load SSL ciphers if any has been specified
        if api_conf['https']['ssl_ciphers']:
            params['ssl_ciphers'] = api_conf['https']['ssl_ciphers'].upper()

    except ssl.SSLError as exc:
        error = APIError(
            2003, details='Private key does not match with the certificate')
        logger.error(error)
        raise error from exc
    except IOError as exc:
        if exc.errno == 22:
            error = APIError(2003, details='PEM phrase is not correct')
            logger.error(error)
            raise error from exc
        elif exc.errno == 13:
            error = APIError(2003,
                                details='Ensure the certificates have the correct permissions')
            logger.error(error)
            raise error from exc
        else:
            msg = f'Wazuh API SSL ERROR. Please, ensure ' \
                    f'if path to certificates is correct in the configuration ' \
                    f'file WAZUH_PATH/{to_relative_path(CONFIG_FILE_PATH)}'
            print(msg)
            logger.error(msg)
            raise exc from exc


def start(params):
    """Run the Wazuh API.

    If another Wazuh API is running, this function fails.
    This function exits with 0 if successful or 1 if failed because the API was already running.
    """
    try:
        check_database_integrity()
    except Exception as db_integrity_exc:
        raise APIError(2012, details=str(
            db_integrity_exc)) from db_integrity_exc

    # Spawn child processes with their own needed imports
    if 'thread_pool' not in common.mp_pools.get():
        loop = asyncio.get_event_loop()
        loop.run_until_complete(
            asyncio.wait([loop.run_in_executor(pool,
                                               getattr(sys.modules[__name__], f'spawn_{name}'))
                          for name, pool in common.mp_pools.get().items()]))

    # Set up API
    # asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    app = AsyncApp(
        __name__,
        specification_dir=os.path.join(api_path[0], 'spec'),
        swagger_ui_options=SwaggerUIOptions(swagger_ui=False),
        pythonic_params=True,
        lifespan=lifespan_handler
    )
    app.add_api('spec.yaml',
                arguments={
                    'title': 'Wazuh API',
                    'protocol': 'https' if api_conf['https']['enabled'] else 'http',
                    'host': params['host'],
                    'port': params['port']},
                strict_validation=False,
                validate_responses=False
                )

    # Maximum body size that the API can accept (bytes)
    app.add_middleware(WazuhAccessLoggerMiddleware, MiddlewarePosition.BEFORE_ROUTING)
    app.add_middleware(ContentSizeLimitMiddleware,
                       max_content_size=api_conf['max_upload_size'])
    app.add_middleware(SecureHeadersMiddleware)
    app.add_middleware(CheckRateLimitsMiddleware)
    # Enable CORS
    if api_conf['cors']['enabled']:
        app.add_middleware(
            CORSMiddleware(app=app,
                           allow_origins=api_conf['cors']['source_route'],
                           expose_headers=api_conf['cors']['expose_headers'],
                           allow_headers=api_conf['cors']['allow_headers'],
                           allow_credentials=api_conf['cors']['allow_credentials']),
                           MiddlewarePosition.BEFORE_ROUTING
        )
    # Add error handlers to format exceptions
    app.add_error_handler(JWTError, error_handler.jwt_error_handler)
    app.add_error_handler(Unauthorized, error_handler.unauthorized_error_handler)
    app.add_error_handler(HTTPException, error_handler.http_error_handler)
    app.add_error_handler(BadRequestProblem, error_handler.bad_request_error_handler)
    app.add_error_handler(ProblemException, error_handler.problem_error_handler)

    # API configuration logging
    logger.debug(f'Loaded API configuration: {api_conf}')
    logger.debug(f'Loaded security API configuration: {security_conf}')

    # Start uvicorn server

    try:
        uvicorn.run(app, **params)

    except OSError as exc:
        if exc.errno == 98:
            error = APIError(2010)
            logger.error(error)
            raise error
        else:
            logger.error(exc)
            raise exc


def print_version():
    print("\n{} {} - {}\n\n{}".format(__wazuh_name__,
          __version__, __author__, __licence__))


def test_config(config_file: str):
    """Make an attempt to read the API config file. Exits with 0 code if successful, 1 otherwise.

    Arguments
    ---------
    config_file : str
        Path of the file
    """
    try:
        read_yaml_config(config_file=config_file)
    except Exception as exc:
        print(f"Configuration not valid. ERROR: {exc}")
        sys.exit(1)
    sys.exit(0)


def version():
    """Print API version and exits with 0 code. """
    print_version()
    sys.exit(0)


def exit_handler(signum, frame):
    """Try to kill API child processes and remove their PID files."""
    api_pid = os.getpid()
    pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, api_pid, logger)
    pyDaemonModule.delete_pid(API_MAIN_PROCESS, api_pid)


def add_log_level_debug2():
    """Add a new debug level used by wazuh api and framework."""

    logging.DEBUG2 = 6

    def debug2(self, message, *args, **kws):
        if self.isEnabledFor(logging.DEBUG2):
            self._log(logging.DEBUG2, message, args, **kws)

    def error(self, msg, *args, **kws):
        if self.isEnabledFor(logging.ERROR):
            if 'exc_info' not in kws:
                kws['exc_info'] = self.isEnabledFor(logging.DEBUG2)
            self._log(logging.ERROR, msg, args, **kws)

    logging.addLevelName(logging.DEBUG2, "DEBUG2")

    logging.Logger.debug2 = debug2
    logging.Logger.error = error


def create_log_and_get_config(log_filepath=f'{API_LOG_PATH}.log', log_level='INFO',
                           foreground_mode=False) -> dict():
    """Create a logging configuration dictionary, configure the wazuh-api logger and
    return the config dictionary.
    
    Parameters
    ----------
    log_path : str
        Log file path.
    log_level :  str
        Logger Log level.
    foreground_mode: bool
        Log output to console streams when true
        else Log output to file.

    Returns
    -------
    dict
        Logging configuraction dictionary.
    """
    log_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(asctime)s %(levelname)s: %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
                "use_colors": None,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(asctime)s %(levelname)s: %(client_addr)s - "%(request_line)s" %(status_code)s',
                "datefmt": "%Y-%m-%d %H:%M:%S",
            },
        },
        "filters": {
            'wazuh-filter': {
                '()': 'wazuh.core.wlogging.CustomFilter',
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
            },
        },
        "loggers": {}
    }

    handler = "console" if foreground_mode else "file"
    if foreground_mode:
        log_config['filters']['wazuh-filter']['log_type'] = 'log'
        log_config['handlers']['console'] = {
            'level': log_level,
            'formatter': 'default',
            'class': 'logging.StreamHandler',
            'stream': 'ext://sys.stdout',
            'filters': ['wazuh-filter']
        }
    else:
        if log_filepath.endswith('.json'):
            log_config['filters']['wazuh-filter']['log_type'] = 'json'
            log_config['formatters']['json'] = {
                '()': 'api.alogging.WazuhJsonFormatter',
                'style': '%',
                'datefmt' : "%Y/%m/%d %H:%M:%S"
            }
        else:
            log_config['filters']['wazuh-filter']['log_type'] = 'log'

        log_config['handlers']['file'] = {
            'filename': log_filepath,
            'level': log_level,
            'formatter': 'json' if log_filepath.endswith('.json') else 'default',
            'filters': ['wazuh-filter']
        }

        if api_conf['logs']['max_size']['enabled']:
            max_size = APILoggerSize(api_conf['logs']['max_size']['size']).size
            log_config['handlers']['file']['class'] = \
                'wazuh.core.wlogging.SizeBasedFileRotatingHandler'
            log_config['handlers']['file']['maxBytes'] = max_size
            log_config['handlers']['file']['backupCount'] = 1
        else:
            log_config['handlers']['file']['class'] = \
                'wazuh.core.wlogging.TimeBasedFileRotatingHandler'
            log_config['handlers']['file']['when'] = 'midnight'

    log_config['loggers']['wazuh-api'] = {"handlers": [handler],
                                          "level": log_level,
                                          "propagate": False}

    # Configure and create the wazuh-api logger first
    logging.config.dictConfig(log_config)

    # Configure the uvicorn loggers. They will be created by the uvicorn server.
    log_config['loggers']['uvicorn'] = {"handlers": [handler], "level": 'WARNING',
                                                "propagate": False}
    log_config['loggers']['uvicorn.error'] = {"handlers": [handler], "level": 'WARNING',
                                                "propagate": False}
    log_config['loggers']['uvicorn.access'] = {'level': 'WARNING'}

    return log_config


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    #########################################################################################
    parser.add_argument('-f', help="Run in foreground",
                        action='store_true', dest='foreground')
    parser.add_argument('-V', help="Print version",
                        action='store_true', dest="version")
    parser.add_argument('-t', help="Test configuration",
                        action='store_true', dest='test_config')
    parser.add_argument('-r', help="Run as root",
                        action='store_true', dest='root')
    parser.add_argument('-c', help="Configuration file to use",
                        type=str, metavar='config', dest='config_file')
    parser.add_argument('-d', help="Enable debug messages. Use twice to increase verbosity.", 
                        action='count',
                        dest='debug_level')
    args = parser.parse_args()

    if args.version:
        version()
        sys.exit(0)

    elif args.test_config:
        test_config(args.config_file)
        sys.exit(0)

    try:
        if args.config_file is not None:
            api_conf.update(read_yaml_config(
                config_file=args.config_file))
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)

    # Configure uvicorn parameters dictionary
    uvicorn_params = dict()
    uvicorn_params['host'] = api_conf['host']
    uvicorn_params['port'] = api_conf['port']
    uvicorn_params['loop'] = 'uvloop'

    # Set up logger file
    if not (api_conf['logs']['format'] in ['plain', 'json']):
        print(f"Configuration error in the API log format: {api_conf['logs']['format']}.")
        sys.exit(1)
    elif api_conf['logs']['format'] == 'json':
        log_path = f'{API_LOG_PATH}.json'
    else:
        log_path = f'{API_LOG_PATH}.log'
    assign_wazuh_ownership(log_path)
    add_log_level_debug2()
    json_log = 'json' in api_conf['logs']['format']
    uvicorn_params['log_config'] = create_log_and_get_config(
                                        log_filepath=log_path,
                                        log_level=api_conf['logs']['level'].upper(),
                                        foreground_mode=args.foreground)
    

    logger = logging.getLogger('wazuh-api')

    # Check deprecated options. To delete after expected versions
    if 'use_only_authd' in api_conf:
        del api_conf['use_only_authd']
        logger.warning(
            "'use_only_authd' option was deprecated on v4.3.0. Wazuh Authd will always be used")

    if 'path' in api_conf['logs']:
        del api_conf['logs']['path']
        logger.warning(
            "Log 'path' option was deprecated on v4.3.0. Default path will always be used: "
            f"{API_LOG_PATH}.<log_format>")

    # Configure ssl files
    if api_conf['https']['enabled']:
        configure_ssl(uvicorn_params)

    # Check for unused PID files
    utils.clean_pid_files(API_MAIN_PROCESS)

    # Foreground/Daemon
    if not args.foreground:
        pyDaemonModule.pyDaemon()
    else:
        print('Starting API in foreground')

    # Drop privileges to wazuh
    if not args.root:
        if api_conf['drop_privileges']:
            os.setgid(common.wazuh_gid())
            os.setuid(common.wazuh_uid())
    else:
        print('Starting API as root')

    pid = os.getpid()
    pyDaemonModule.create_pid(API_MAIN_PROCESS, pid)

    signal.signal(signal.SIGTERM, exit_handler)
    try:
        start(uvicorn_params)
    except APIError as e:
        print(f"Error when trying to start the Wazuh API. {e}")
        sys.exit(1)
    except Exception as e:
        print(f'Internal error when trying to start the Wazuh API. {e}')
        sys.exit(1)
    finally:
        pyDaemonModule.delete_child_pids(API_MAIN_PROCESS, pid, logger)
        pyDaemonModule.delete_pid(API_MAIN_PROCESS, pid)
