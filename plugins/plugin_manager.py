"""
This script is used to manage the loading and downloading of plugins.
Author: Peres J. and the Resistine Team
Copyright (c) Resistine 2025
Licensed under the GNU General Public License v2 or later
"""

import hashlib
import hmac
import importlib
import os
import requests
import zipfile
import io
import sys
import re
import json
from urllib.parse import urljoin, urlparse
from utils.logger import logger
from utils.settings import get_config_dir

class PluginManager:
    """
    A class to manage the loading and downloading of plugins.
    """

    # URLs for optional plugins metadata (could be used to display available plugins in the UI)
    OPTIONAL_PLUGINS_URL = "https://raw.githubusercontent.com/Resistine/Resistine-Desktop-Plugins/main/plugins/optional_plugins.json"

    # Network timeouts (seconds)
    METADATA_TIMEOUT = 15
    DOWNLOAD_TIMEOUT = 30

    # Plugin downloads are fetched with allow_redirects=False. Redirects are
    # then followed manually, only over HTTPS, at most MAX_DOWNLOAD_REDIRECTS
    # times, and only to the original host or a trusted GitHub host (GitHub
    # release assets always 302 to *.githubusercontent.com, so refusing every
    # redirect would break every install from the published metadata).
    MAX_DOWNLOAD_REDIRECTS = 5
    TRUSTED_REDIRECT_HOSTS = ("github.com", "codeload.github.com")
    TRUSTED_REDIRECT_HOST_SUFFIXES = (".githubusercontent.com",)


    def __init__(self, app):
        """
        Initialize the PluginManager with the given application instance.
        
        :param app: The application instance to which the plugins will be attached.
        """
        self.app = app
        # SHA-256 digests published in the optional-plugins metadata, keyed by
        # download URL and by plugin id (filled by get_available_plugins()).
        self._published_hashes = {}
        self.state_file = os.path.join(get_config_dir(), "plugin_state.json")
        self.user_plugins_path = os.path.join(get_config_dir(), "plugins")
        
        if not os.path.exists(self.user_plugins_path):
            os.makedirs(self.user_plugins_path, exist_ok=True)
            
        self.plugins = sorted(self.load_plugins(), key=lambda x: x.order)

    def get_available_plugins(self):
        """
        Fetch the list of optional plugins from the remote repository.
        """
        try:
            response = requests.get(
                self.OPTIONAL_PLUGINS_URL, timeout=self.METADATA_TIMEOUT, verify=True
            )
            response.raise_for_status()
            data = response.json()
            plugins = data.get("plugins", [])
            self._remember_published_hashes(plugins)
            return plugins
        except Exception as e:
            logger.error(f"Failed to fetch optional plugins: {e}")
            return []

    def _load_state(self):
        """Load persistent plugin state (e.g., uninstalled plugins, download order)."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load plugin state: {e}")
        return {"uninstalled": [], "download_order": {}}

    def _save_state(self, state):
        """Save persistent plugin state."""
        try:
            with open(self.state_file, 'w', encoding='utf-8') as f:
                json.dump(state, f, indent=4, ensure_ascii=False)
            logger.info(f"PluginManager: State saved. Uninstalled list: {state.get('uninstalled', [])}")
            return True
        except Exception as e:
            logger.error(f"Failed to save plugin state: {e}")
            return False

    def uninstall_plugin(self, plugin):
        """
        Mark a plugin as uninstalled and attempt to remove it if it's in the user directory.
        """
        state = self._load_state()
        if plugin.id not in state["uninstalled"]:
            state["uninstalled"].append(plugin.id)
        
        # Remove from download order tracking
        download_order = state.get("download_order", {})
        if plugin.id in download_order:
            del download_order[plugin.id]
            state["download_order"] = download_order
            
        # Call cleanup on the plugin instance before saving state or deleting files
        try:
            if hasattr(plugin, "destroy"):
                plugin.destroy()
        except Exception as e:
            logger.error(f"Error while destroying plugin {plugin.id}: {e}")

        self._save_state(state)
        
        # If the plugin is in the user directory, try to delete it
        # Extract folder name safely
        try:
            module_path = plugin.__class__.__module__
            # Expected format: plugins.<folder>.main
            parts = module_path.split('.')
            if len(parts) >= 2 and parts[0] == 'plugins':
                folder_name = parts[1]
                user_plugin_dir = os.path.join(self.user_plugins_path, folder_name)
            else:
                # Fallback to old heuristic
                logger.warning(f"Uninstallation: Unusual module path '{module_path}', falling back to heuristics.")
                user_plugin_dir = os.path.join(self.user_plugins_path, os.path.basename(os.path.dirname(module_path.replace('.', '/'))))
        except Exception as e:
            logger.error(f"Uninstallation: Failed to calculate directory for {plugin.id}: {e}")
            user_plugin_dir = None

        if user_plugin_dir and os.path.exists(user_plugin_dir):
            logger.info(f"Uninstallation: Deleting directory at {user_plugin_dir}")
            try:
                import shutil
                shutil.rmtree(user_plugin_dir)
                if os.path.exists(user_plugin_dir):
                    logger.error(f"Uninstallation: ❌ Directory still exists after rmtree: {user_plugin_dir}")
                else:
                    logger.info(f"Uninstallation: ✅ Directory deleted: {user_plugin_dir}")
            except Exception as e:
                logger.warning(f"Could not delete plugin directory {user_plugin_dir}: {e}")
        else:
            logger.warning(f"Uninstallation: Directory not found or invalid: {user_plugin_dir}")
        
        # Surgical Update: Remove the plugin from active lists and refresh only the sidebar
        logger.info(f"Uninstallation: Removing {plugin.id} from active memory lists")
        if plugin in self.plugins:
            self.plugins.remove(plugin)
        
        if hasattr(self.app, "frames"):
            frame_name = f"frame_{plugin.get_name()}"
            if frame_name in self.app.frames:
                del self.app.frames[frame_name]

        # Defer the UI refresh to keep the UI responsive
        def refresh_ui():
            if hasattr(self.app, "refresh_navigation"):
                self.app.refresh_navigation()
            elif hasattr(self.app, "refresh_navigation_menu"):
                self.app.refresh_navigation_menu()
            elif hasattr(self.app, "create_dashboard"):
                # Fallback if refresh methods aren't available for some reason
                self.app.create_dashboard()
        
        if hasattr(self.app, "after"):
            self.app.after(100, refresh_ui)
        else:
            refresh_ui()
        return True, "Plugin uninstalled successfully."

    def reinstall_plugin(self, plugin_id):
        """Re-enable a locally-present plugin that was marked uninstalled.

        Bundled plugins are never deleted on uninstall — only flagged in the
        state file — so "installing" one back is just clearing the flag and
        reloading. Nothing to download.
        """
        state = self._load_state()
        if plugin_id in state.get("uninstalled", []):
            state["uninstalled"].remove(plugin_id)
            self._save_state(state)

        # Defer the UI refresh to keep the UI responsive (same pattern as
        # download_plugin).
        def refresh_ui():
            self.plugins = sorted(
                self.load_plugins(reload=True), key=lambda x: x.order)
            if hasattr(self.app, "refresh_navigation"):
                self.app.refresh_navigation()
            elif hasattr(self.app, "create_dashboard"):
                self.app.create_dashboard()

        if hasattr(self.app, "after"):
            self.app.after(100, refresh_ui)
        else:
            refresh_ui()
        return True, "Plugin installed."

    def _remember_published_hashes(self, plugins):
        """Cache the ``sha256`` field of each metadata entry by url and id."""
        if not isinstance(plugins, list):
            return
        for entry in plugins:
            if not isinstance(entry, dict):
                continue
            digest = entry.get("sha256")
            if not isinstance(digest, str) or not digest.strip():
                continue
            digest = digest.strip().lower()
            if entry.get("url"):
                self._published_hashes[entry["url"]] = digest
            if entry.get("id") is not None:
                self._published_hashes[str(entry["id"])] = digest

    def _is_allowed_redirect(self, original_url, location):
        """Return True if a download redirect to ``location`` may be followed."""
        target = urlparse(location)
        if target.scheme != "https" or not target.hostname:
            return False
        host = target.hostname.lower()
        if host == (urlparse(original_url).hostname or "").lower():
            return True
        if host in self.TRUSTED_REDIRECT_HOSTS:
            return True
        return any(host.endswith(sfx) for sfx in self.TRUSTED_REDIRECT_HOST_SUFFIXES)

    def _fetch_plugin_archive(self, url):
        """
        GET a plugin archive with automatic redirects disabled.

        Redirects are only followed after validation by _is_allowed_redirect.
        Raises requests.RequestException on any refused/failed request.
        """
        current = url
        for _ in range(self.MAX_DOWNLOAD_REDIRECTS + 1):
            response = requests.get(
                current,
                allow_redirects=False,
                timeout=self.DOWNLOAD_TIMEOUT,
                verify=True,
            )
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    raise requests.RequestException(
                        "Redirect without Location header refused"
                    )
                location = urljoin(current, location)
                if not self._is_allowed_redirect(url, location):
                    raise requests.RequestException(
                        f"Refusing redirect to untrusted location: "
                        f"{urlparse(location).scheme}://{urlparse(location).hostname}"
                    )
                current = location
                continue
            response.raise_for_status()
            return response
        raise requests.TooManyRedirects(
            f"More than {self.MAX_DOWNLOAD_REDIRECTS} redirects while downloading plugin"
        )

    @staticmethod
    def _check_archive_members(zip_ref, extract_to):
        """
        Zip-slip guard: reject entries that would land outside ``extract_to``
        (absolute paths, drive letters, '..' components).
        """
        base = os.path.realpath(extract_to)
        for member in zip_ref.namelist():
            normalized = member.replace("\\", "/")
            if normalized.startswith("/") or os.path.isabs(member) or re.match(r"^[A-Za-z]:", normalized):
                raise zipfile.BadZipFile(
                    f"Zip slip detected: '{member}' is an absolute path"
                )
            dest = os.path.realpath(os.path.join(base, normalized))
            if os.path.commonpath([base, dest]) != base:
                raise zipfile.BadZipFile(
                    f"Zip slip detected: '{member}' would extract outside plugin directory"
                )

    def download_plugin(self, url, plugin_id=None, plugin_name=None, expected_sha256=None):
        """
        Download a plugin and extract it to the USER'S plugins directory.

        Args:
            url: Download URL for the plugin ZIP.
            plugin_id: Optional plugin identifier.
            plugin_name: Optional human-readable name (used for folder name).
            expected_sha256: SHA-256 hex digest to verify the archive against.
                When omitted, the digest published in the optional-plugins
                metadata (``sha256`` field, looked up by url, then id) is used.
                If neither is available the archive is installed unverified
                (a warning is logged); a mismatch always rejects the install.
        """
        try:
            logger.info(f"Downloading plugin from: {url}")
            response = self._fetch_plugin_archive(url)

            # Verify integrity when a hash is available
            if not expected_sha256:
                expected_sha256 = self._published_hashes.get(url) or (
                    self._published_hashes.get(str(plugin_id)) if plugin_id is not None else None
                )
            if expected_sha256:
                actual_hash = hashlib.sha256(response.content).hexdigest()
                if not hmac.compare_digest(actual_hash, expected_sha256.strip().lower()):
                    logger.error(
                        f"Plugin hash mismatch: expected {expected_sha256}, "
                        f"got {actual_hash}"
                    )
                    return False, "Plugin integrity check failed — download may have been tampered with."
            else:
                logger.warning(
                    f"No SHA-256 published for plugin {plugin_id or url}; "
                    "installing without integrity verification"
                )

            # Determine target directory
            if plugin_name:
                # Slugify the name for folder usage
                folder_name = re.sub(r'[^a-z0-9]+', '_', plugin_name.lower()).strip('_')
            elif plugin_id:
                folder_name = plugin_id
            else:
                folder_name = os.path.splitext(os.path.basename(url))[0]
                
            target_path = os.path.join(self.user_plugins_path, folder_name)
            
            if not os.path.exists(target_path):
                os.makedirs(target_path, exist_ok=True)
            
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_ref:
                # Check if all files in the zip are already inside a single top-level folder
                # with the same name. If so, we extract to self.user_plugins_path directly.
                first_file = zip_ref.namelist()[0]
                top_level_folder = first_file.split('/')[0] if '/' in first_file else ""
                
                # If the zip has a single root folder that matches our target
                # (or we just want to be safe and avoid double nesting)
                is_nested = all(f.startswith(top_level_folder + '/') for f in zip_ref.namelist()) if top_level_folder else False

                extract_to = self.user_plugins_path if is_nested else target_path

                # Guard against zip-slip before writing anything
                self._check_archive_members(zip_ref, extract_to)

                if is_nested:
                    logger.info(f"Zip contains top-level folder '{top_level_folder}', extracting directly to user_plugins_path")
                else:
                    logger.info(f"Extracting to: {target_path}")
                zip_ref.extractall(extract_to)
            
            # If we know the ID, make sure it's not marked as uninstalled
            # and track download order for sidebar positioning
            if plugin_id:
                state = self._load_state()
                if plugin_id in state.get("uninstalled", []):
                    state["uninstalled"].remove(plugin_id)
                
                # Track download order if not already present
                download_order = state.get("download_order", {})
                if plugin_id not in download_order:
                    # Find the next order number (start at 101, after Store which is 100)
                    existing_orders = list(download_order.values())
                    next_order = 101 if not existing_orders else max(existing_orders) + 1
                    download_order[plugin_id] = next_order
                    state["download_order"] = download_order
                
                self._save_state(state)
            
            # Defer the UI refresh to keep the UI responsive
            def refresh_ui():
                # Post-download: reload=True to pick up the newly fetched code.
                self.plugins = sorted(self.load_plugins(reload=True), key=lambda x: x.order)
                if hasattr(self.app, "refresh_navigation"):
                    self.app.refresh_navigation()
                elif hasattr(self.app, "create_dashboard"):
                    self.app.create_dashboard()
            
            if hasattr(self.app, "after"):
                self.app.after(100, refresh_ui)
            else:
                refresh_ui()

            return True, "Plugin downloaded and extracted successfully."
        except requests.RequestException as e:
            error_msg = f"Download failed: {str(e)}"
            if hasattr(e, 'response') and e.response is not None:
                error_msg += f" (Status: {e.response.status_code})"
            logger.error(error_msg)
            return False, error_msg
        except zipfile.BadZipFile as e:
            logger.error(f"Extraction failed: {e}")
            return False, f"Failed to extract plugin: {e}"
        except Exception as e:
            logger.error(f"Unexpected error during plugin install: {e}")
            return False, f"Installation error: {str(e)}"

    def load_plugins(self, include_uninstalled=False, reload=False):
        """
        Load all plugins from both system and user directories.

        :param reload: When True, destroy existing live plugin instances and
            reload their modules to pick up new code (used after a download /
            update). When False (default) this is a NON-DESTRUCTIVE enumeration:
            it must NOT tear down live plugins — the Store calls it just to list
            available plugins, and destroying the currently-visible plugin's
            widget mid-navigation caused a heavy synchronous teardown (a blip).
        """
        state = self._load_state()
        uninstalled_ids = state.get("uninstalled", []) if not include_uninstalled else []
        
        system_plugins_path = self.get_plugins_path()
        user_plugins_path = self.user_plugins_path
        
        # Priority: User plugins override system plugins if folder names collide
        # (Though ID check would be better, we'll start with path-based discovery)
        
        plugins_to_load = {} # path -> module_prefix
        
        # Scan system plugins
        if os.path.exists(system_plugins_path):
            for d in os.listdir(system_plugins_path):
                if os.path.isdir(os.path.join(system_plugins_path, d)):
                    if d.startswith('_') or d == '__pycache__':
                        continue
                    plugins_to_load[d] = "plugins"

        # Scan user plugins (overrides)
        if os.path.exists(user_plugins_path):
            # We need to add user_plugins_path to sys.path to import from it
            if user_plugins_path not in sys.path:
                sys.path.append(user_plugins_path)
                
            for d in os.listdir(user_plugins_path):
                if os.path.isdir(os.path.join(user_plugins_path, d)):
                    if d.startswith('_') or d == '__pycache__':
                        continue
                    plugins_to_load[d] = None # No prefix, it's a top-level in user_plugins_path

        loaded_plugins = []
        seen_ids = set()

        # Load them
        for plugin_dir, prefix in plugins_to_load.items():
            if prefix:
                module_name = f"{prefix}.{plugin_dir}.main"
            else:
                module_name = f"{plugin_dir}.main"
                
            try:
                # Force reload if it was already in sys.modules (relevant for updates/downloads).
                # Only when reload=True — otherwise this is a non-destructive
                # enumeration and we must NOT destroy live plugin instances
                # (doing so tore down the currently-visible plugin's widget).
                if reload and module_name in sys.modules:
                    # If we had a previously loaded instance of this plugin, try to destroy it
                    # by searching in our current plugins list or other sources if necessary.
                    # Since we are about to reload the module and create a new instance,
                    # we want the old code to stop its background tasks.
                    for p in getattr(self, 'plugins', []):
                        if p.__class__.__module__ == module_name:
                            try:
                                if hasattr(p, 'destroy'):
                                    p.destroy()
                            except Exception as e:
                                logger.error(f"Error destroying old plugin instance for {module_name}: {e}")

                    importlib.reload(sys.modules[module_name])

                module = importlib.import_module(module_name)
                plugin_class = getattr(module, "Plugin")
                plugin_instance = plugin_class(self.app)
                
                if plugin_instance.id in uninstalled_ids:
                    logger.info(f"Skipping uninstalled plugin: {plugin_instance.name} ({plugin_instance.id})")
                    continue
                
                # Deduplicate by ID
                if plugin_instance.id in seen_ids:
                    # If we encounter the same ID, the priority logic above (merging dicts)
                    # already handled directory collision, BUT ID collision across different
                    # folder names could still happen. 
                    continue
                
                # Apply download order for user-installed plugins BEFORE appending
                # This ensures they appear between Store (100) and Help (200)
                download_order = state.get("download_order", {})
                if plugin_instance.id in download_order:
                    plugin_instance.order = download_order[plugin_instance.id]
                    
                loaded_plugins.append(plugin_instance)
                seen_ids.add(plugin_instance.id)
                # DEFERRED: Status will be fetched lazily by the UI to prevent blocking the main thread during load
                # plugin_instance.status = plugin_instance.get_status()
                    
            except Exception as e:
                logger.error(f"Failed to load plugin {module_name}: {e}")
                
        # Sort plugins by their defined 'order'
        loaded_plugins.sort(key=lambda p: getattr(p, 'order', 999))
        
        logger.info(f"PluginManager: Loaded {len(loaded_plugins)} plugins: {[f'{p.name} ({p.id})' for p in loaded_plugins]}")
        return loaded_plugins

    def get_plugins_path(self):
        """
        Get the path to the SYSTEM plugins directory.
        """
        if getattr(sys, 'frozen', False):
            return os.path.join(sys._MEIPASS, 'plugins')
        else:
            return os.path.dirname(os.path.realpath(__file__))
