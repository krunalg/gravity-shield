from config import *
try:
    from config_local import *
except ImportError:
    pass

import logging
import os

logger = logging.getLogger(__name__)

# mtime-cached user allowlist — reloaded when the file changes, so users can
# recover from a false positive without restarting the daemon.
_allowlist_cache = {"mtime": None, "path": None, "domains": set(), "suffixes": ()}


def _user_allowlist() -> tuple[set, tuple]:
    path = USER_ALLOWLIST_PATH
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return set(), ()
    if _allowlist_cache["mtime"] == mtime and _allowlist_cache["path"] == path:
        return _allowlist_cache["domains"], _allowlist_cache["suffixes"]

    domains, suffixes = set(), []
    try:
        with open(path) as f:
            for line in f:
                entry = line.strip().lower()
                if not entry or entry.startswith("#"):
                    continue
                if entry.startswith("."):
                    suffixes.append(entry)
                else:
                    domains.add(entry)
    except OSError as e:
        logger.warning(f"Could not read user allowlist {path}: {e}")
        return set(), ()

    _allowlist_cache.update(
        mtime=mtime, path=path, domains=domains, suffixes=tuple(suffixes)
    )
    logger.info(f"User allowlist loaded: {len(domains)} domains, {len(suffixes)} suffixes")
    return domains, tuple(suffixes)


def is_never_block_domain(domain: str) -> bool:
    domain = domain.rstrip(".").lower()
    if domain in NEVER_BLOCK_DOMAINS or domain.endswith(tuple(NEVER_BLOCK_SUFFIXES)):
        return True
    user_domains, user_suffixes = _user_allowlist()
    return domain in user_domains or (bool(user_suffixes) and domain.endswith(user_suffixes))


def should_skip_classification(domain: str) -> bool:
    return is_never_block_domain(domain)
