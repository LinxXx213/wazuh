# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import collections
import logging
import re
from pythonjsonlogger import jsonlogger

# Compile regex when the module is imported so it's not necessary to compile it everytime log.info is called
request_pattern = re.compile(r'\[.+]|\s+\*\s+')

# Variable used to specify an unknown user
UNKNOWN_USER_STRING = "unknown_user"

# Run_as login endpoint path
RUN_AS_LOGIN_ENDPOINT = "/security/user/authenticate/run_as"


class WazuhJsonFormatter(jsonlogger.JsonFormatter):
    """
    Define the custom JSON log formatter used by wlogging.
    """

    def add_fields(self, log_record: collections.OrderedDict, record: logging.LogRecord, message_dict: dict):
        """Implement custom logic for adding fields in a log entry.

        Parameters
        ----------
        log_record : collections.OrderedDict
            Dictionary with custom fields used to generate a log entry.
        record : logging.LogRecord
            Contains all the information to the event being logged.
        message_dict : dict
            Dictionary with a request or exception information.
        """
        # Request handling
        if record.message is None:
            record.message = {
                'type': 'request',
                'payload': message_dict
            }
        else:
            # Traceback handling
            traceback = message_dict.get('exc_info')
            if traceback is not None:
                record.message = {
                    'type': 'error',
                    'payload': f'{record.message}. {traceback}'
                }
            else:
                # Plain text messages
                record.message = {
                    'type': 'informative',
                    'payload': record.message
                }
        log_record['timestamp'] = self.formatTime(record, self.datefmt)
        log_record['levelname'] = record.levelname
        log_record['data'] = record.message
