"""Fixed diagnostic manager entry; JSON cannot select another profile."""
import deployment_compose_owned_recovery_manager_v3_host as manager
from deployment_compose_recovery_profiles_v3_host import RESPONSE_LOSS


def run(config,stdin,stdout,archive,*,timeout=3600):
    return manager._run(config,stdin,stdout,archive,timeout=timeout,_profile=RESPONSE_LOSS)
