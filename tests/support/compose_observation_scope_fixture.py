"""Purpose-limited observation seam for archive-vs-authorization unit tests."""
from copy import deepcopy
from deployment_compose_observation_host import ComposeObservationHost, _TEST_SEAM


def source_view(observer, reader, live):
    scope = deepcopy(observer._policy)
    scope['protectedContainerIds'] = {name: live['serviceContainerIds'][name]
                                      for name in scope['protectedServices']}
    pins = tuple(sorted([*scope['selectedContainerIds'].values(), *scope['protectedContainerIds'].values()]))
    return ComposeObservationHost._test_host(reader, scope, observer._collect,
        observer._baseline_artifacts, source_container_ids=pins, _token=_TEST_SEAM)
