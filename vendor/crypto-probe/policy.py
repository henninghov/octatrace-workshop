"""Strict response policy for the on-demand synthetic crypto probe."""
import re

FIELDS = {'v', 'id', 'ok', 'type', 'role', 'build', 'hardware', 'boot',
          'run_id', 'state', 'cancel_requested', 'hash', 'signature',
          'agreement', 'random', 'elapsed_ms', 'stack_free_words'}
CHECKS = ('hash', 'signature', 'agreement', 'random')
STATES = ('idle', 'queued', 'running', 'passed', 'failed', 'interrupted')
MAXIMUM = 4294967295


def validate(value, request_id, selected):
    if not isinstance(value, dict) or set(value) != FIELDS:
        raise ValueError('Invalid crypto probe fields')
    if (type(request_id) is not int or not 1 <= request_id <= MAXIMUM or
            type(value['v']) is not int or value['v'] != 1 or
            type(value['id']) is not int or value['id'] != request_id or
            value['ok'] is not True or value['type'] != 'crypto_probe'):
        raise ValueError('Invalid crypto probe envelope')
    if not isinstance(selected, dict):
        raise ValueError('Invalid crypto probe selection')
    for name, length in (('build', 64), ('hardware', 16), ('boot', 32)):
        item = value[name]
        if (not isinstance(item, str) or not re.fullmatch('[0-9a-f]{%d}' % length, item) or
                (name != 'build' and not any(c != '0' for c in item)) or selected.get(name) != item):
            raise ValueError('Invalid crypto probe binding')
    if value['role'] not in ('Link', 'Core') or selected.get('role') != value['role']:
        raise ValueError('Invalid crypto probe role')
    state, run_id = value['state'], value['run_id']
    if (state not in STATES or type(run_id) is not int or not 0 <= run_id <= MAXIMUM or
            (state == 'idle') != (run_id == 0) or type(value['cancel_requested']) is not bool):
        raise ValueError('Invalid crypto probe state')
    completed = state in ('passed', 'failed')
    if completed:
        if (value['cancel_requested'] or any(type(value[name]) is not bool for name in CHECKS) or
                (state == 'passed') != all(value[name] for name in CHECKS)):
            raise ValueError('Invalid crypto probe outcome')
        for name in ('elapsed_ms', 'stack_free_words'):
            item = value[name]
            if item is not None and (type(item) is not int or not 0 <= item <= MAXIMUM):
                raise ValueError('Invalid crypto probe measurement')
    elif (any(value[name] is not None for name in (*CHECKS, 'elapsed_ms', 'stack_free_words')) or
          (state == 'idle' and value['cancel_requested']) or
          (state == 'interrupted' and not value['cancel_requested'])):
        raise ValueError('Invalid incomplete crypto probe result')
    return value
