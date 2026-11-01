"""Internal fixed-route sentinels, not serializable execution authority.

Only fixed entry functions choose these objects. Incoming config cannot select
a connector, program, profile object or callback.
"""
NORMAL = object()
RESPONSE_LOSS = object()
RESPONSE_LOSS_MARKER = 'response-unobserved-v3'


def marker(profile):
    if profile is NORMAL:return None
    if profile is RESPONSE_LOSS:return RESPONSE_LOSS_MARKER
    raise ValueError('compose-recovery-profile-v3-rejected') from None
