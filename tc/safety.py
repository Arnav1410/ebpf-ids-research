"""Unprivileged checks of TC command evidence; never perform networking here."""
import json


def require_detach_ack(events, program_id, direction=None):
    if not any(e.get('event') == 'detach_acknowledged'
               and e.get('program_id') == program_id
               and (direction is None or e.get('direction') == direction) for e in events):
        raise RuntimeError('Owned TC detach not acknowledged')


def require_empty_filters(stdout, returncode):
    # A failed command, including EINVAL, is not evidence of absence.
    if returncode != 0:
        raise RuntimeError('TC filter dump failed; absence not established')
    filters = json.loads(stdout)
    if not isinstance(filters, list) or filters:
        raise RuntimeError('Unexpected filter: refusing qdisc deletion')


def require_attached_filter(stdout, program_id):
    filters = json.loads(stdout)
    if not isinstance(filters, list) or not any(
            isinstance(f, dict) and f.get('kind') == 'bpf'
            and f.get('options', {}).get('prog', {}).get('id') == program_id
            and f.get('options', {}).get('direct-action') is True
            and f.get('pref') == 1 and f.get('options', {}).get('handle') == '0x1'
            for f in filters):
        raise RuntimeError('Owned direct-action TC filter ID/handle/priority not established')
