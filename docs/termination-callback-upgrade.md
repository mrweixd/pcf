# Termination callbacks during upgrade

PCF delivers application-session termination only to the NEF callback matching
a registered NRF service endpoint and a correlation ID. Older sessions may
contain an AF-supplied notification URI instead. PCF skips that notification
before requesting a token or contacting the destination, including when OAuth
is disabled. It does not rewrite the URI or invent a correlation ID.

Deploy the matching NEF fix and re-establish affected Traffic Influence
subscriptions through the upgraded NEF. Skipping an old callback does not
reconcile the old NEF subscription. Plan to drain or reconcile that state.

Compatibility: direct non-NEF policy-authorization consumers no longer receive
termination POSTs through the former unrestricted fallback. If such consumers
are required in a deployment, resolve their trusted recipient identity and
notification contract before rollout. This change does not alter other event
notifications or provide a general outbound URL policy.
