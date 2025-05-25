from fastapi import FastAPI, Request, HTTPException, Header, Body
import uvicorn
import os
import time
from datetime import datetime, timedelta
from loguru import logger
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import asyncio
import cachetools
import hashlib
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse

import pynetbox
import requests

from typing import Tuple, Dict, Any, Optional, List, Union

import ipaddress

app = FastAPI()

from datetime import datetime
import json

import pynetbox
import requests
from loguru import logger

from enum import Enum

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from dotenv import load_dotenv
load_dotenv()

# Thread-local storage for NetboxAPI instances
_thread_local = threading.local()

# Cache configuration
CACHE_TTL = 86400  # 24 hours
CACHE_MAX_SIZE = 10000  # Maximum number of items in cache

# Create thread-safe cache
# This will force cache refresh on invalidation
cache_version = os.getenv("CACHE_VERSION", "1")
cache = cachetools.TTLCache(maxsize=CACHE_MAX_SIZE, ttl=CACHE_TTL)
cache_lock = threading.Lock()

# Add security configuration
security = HTTPBearer()

# Add webhook secret (should be moved to environment variables)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "your-secret-key")

# File-based cache invalidation flag
CACHE_INVALIDATION_FILE = "/tmp/netbox_cache_invalidated"
last_cache_check = 0
CACHE_CHECK_INTERVAL = 30  # seconds

def check_cache_invalidation():
    """Check if cache invalidation has been triggered by another process"""
    global last_cache_check, cache
    
    current_time = time.time()
    if current_time - last_cache_check < CACHE_CHECK_INTERVAL:
        return False
        
    last_cache_check = current_time
    
    try:
        if os.path.exists(CACHE_INVALIDATION_FILE):
            timestamp = os.path.getmtime(CACHE_INVALIDATION_FILE)
            # If file is newer than our last check, invalidate cache
            if timestamp > last_cache_check - CACHE_CHECK_INTERVAL:
                with cache_lock:
                    cache.clear()
                    logger.info("Cache cleared due to invalidation file")
                # Don't delete the file, just let it be overwritten next time
                return True
    except Exception as e:
        logger.error(f"Error checking cache invalidation: {str(e)}")
    
    return False

def touch_invalidation_file():
    """Create or update the invalidation file timestamp"""
    try:
        with open(CACHE_INVALIDATION_FILE, 'w') as f:
            f.write(str(time.time()))
        logger.info(f"Cache invalidation file updated: {CACHE_INVALIDATION_FILE}")
        return True
    except Exception as e:
        logger.error(f"Error updating cache invalidation file: {str(e)}")
        return False

class NetboxDeviceType(Enum):
    DEVICE = "dcim.device"
    VM = "virtualization.virtualmachine"
    INTERFACE_DEVICE = "dcim.interface"
    INTERFACE_VM = "virtualization.vminterface"
    IP_ADDRESS = "ipam.ipaddress"
    VLAN = "ipam.vlan"
    SITE = "dcim.site"
    RACK = "dcim.rack"
    MANUFACTURER = "dcim.manufacturer"
    PLATFORM = "dcim.platform"
    CIRCUIT = "circuits.circuit"
    
class NetboxTypeToName(Enum):
    DEVICE = ("device", "device", "Device")
    VM = ("virtual_machine", "vm", "Virtual Machine")
    INTERFACE_DEVICE = ("interface", "interface", "Interface")
    INTERFACE_VM = ("vminterface", "vminterface", "VM Interface")
    
    def __init__(self, field_name, short_name, display_name):
        self.field_name = field_name
        self.short_name = short_name
        self.display_name = display_name

def is_private_ip(ip_str: str) -> bool:
    """Check if the IP address is a private IPv4 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version == 4:
            return ip.is_private
        return False
    except ValueError:
        return False

def get_primary_ip(ip_list: List[str]) -> Optional[str]:
    """Get the primary IP address from a list, prioritizing private IPv4 addresses."""
    private_ips = [ip for ip in ip_list if is_private_ip(ip)]
    if private_ips:
        return private_ips[0]
    return ip_list[0] if ip_list else None

class NetboxAPI:
    def __init__(self):
        self.netbox_url = os.getenv("NETBOX_URL")
        self.netbox_token = os.getenv("NETBOX_TOKEN")
        self.nb = pynetbox.api(self.netbox_url, token=self.netbox_token)
        self.session = requests.Session()
        self.session.verify = False
        self.nb.http_session = self.session
        self._lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        """Get a thread-local instance of NetboxAPI"""
        if not hasattr(_thread_local, "netbox_api"):
            _thread_local.netbox_api = cls()
        return _thread_local.netbox_api

    def _get_cache_key(self, ip_address: Optional[str]) -> str:
        """Generate a cache key for the IP address."""
        if isinstance(ip_address, list):
            if ip_address is None:
                raise ValueError("No valid IP address found in the list")
        return hashlib.md5(str(ip_address).encode()).hexdigest()

    def get_device_by_ip(self, ip_address):
        with self._lock:
            ip_addresses = self.nb.ipam.ip_addresses.filter(address=ip_address)
            ip_addresses = list(ip_addresses)
            if ip_addresses:
                return ip_addresses[0].assigned_object
            return None
    
    def get_device_by_hostname(self, hostname):
        with self._lock:
            devices = self.nb.dcim.devices.filter(name=hostname)
            devices = list(devices)
            if devices:
                return devices[0]
            return None
    
    def _get_ip_address_info(self, ip_address):
        """Get IP address object and its information from Netbox."""
        with self._lock:
            ip_addresses = self.nb.ipam.ip_addresses.filter(address=ip_address)
            ip_addresses = list(ip_addresses)
            
            if not ip_addresses:
                logger.debug(f"No IP address object found for {ip_address}")
                return None
                
            return ip_addresses[0]

    def _get_parent_prefix_info(self, ip_address):
        """Get parent prefix/subnet information for an IP address."""
        with self._lock:
            parent_prefix = self.nb.ipam.prefixes.filter(contains=ip_address)
            parent_prefix = list(parent_prefix)
            if not parent_prefix:
                logger.debug(f"No parent prefix found for IP {ip_address}")
                return None
            return parent_prefix[0]

    def _build_ip_info(self, ip_obj, parent_prefix):
        """Build IP information dictionary."""
        return {
            "status": ip_obj.status.value,
            "ip": ip_obj.address.split("/")[0],
            "ip_cidr": ip_obj.address,
            "dns_name": ip_obj.dns_name,
            "tags": [str(tag) for tag in ip_obj.tags],
            "tags_str": " ".join([str(tag).lower() for tag in ip_obj.tags]),
            "family": {
                "name": ip_obj.family.label,
                "value": ip_obj.family.value
            },
            "role": {
                "name": parent_prefix.role.name,
                "display_name": parent_prefix.role.display,
                "slug": parent_prefix.role.slug
            },
            "subnet": {
                "prefix": parent_prefix.prefix,
                "tags": [str(tag) for tag in parent_prefix.tags],
                "tags_str": " ".join([str(tag).lower() for tag in parent_prefix.tags]),
                "description": parent_prefix.description,
                "status": parent_prefix.status.value,
                "family": {
                    "name": parent_prefix.family.label,
                    "value": parent_prefix.family.value
                },
                "role": {
                    "name": parent_prefix.role.name,
                    "display_name": parent_prefix.role.display,
                    "slug": parent_prefix.role.slug
                },
                "site": {
                    "name": parent_prefix.site.name,
                    "display_name": parent_prefix.site.display,
                    "slug": parent_prefix.site.slug
                },
                "vlan": {
                    "name": parent_prefix.vlan.name,
                    "display_name": parent_prefix.vlan.display,
                    "id": parent_prefix.vlan.vid
                }
            }
        }

    def _get_device_interface_info(self, interface_id: int) -> Optional[Tuple[Optional[int], Dict[str, Any]]]:
        """Get device interface information."""
        with self._lock:
            _adapter = self.nb.dcim.interfaces.get(id=interface_id)
            if not _adapter:
                return None
            
            device_id: Optional[int] = _adapter.device.id if _adapter.device else None
            
            int_info = {
                "enabled": _adapter.enabled,
                "_netbox_meta": {
                    "type": NetboxDeviceType.INTERFACE_DEVICE.value,
                    "type_field_name": NetboxTypeToName.INTERFACE_DEVICE.field_name,
                    "type_display_name": NetboxTypeToName.INTERFACE_DEVICE.display_name,
                    "type_short_name": NetboxTypeToName.INTERFACE_DEVICE.short_name,
                },
                "name": _adapter.name,
                "label": _adapter.label,
                "mac_address": _adapter.mac_address,
                "description": _adapter.description,
                "vlan": {
                    "untagged": _adapter.untagged_vlan,
                    "tagged": _adapter.tagged_vlans
                },
                'role': _adapter.rf_role.value if _adapter.rf_role else '',
                "role_name": _adapter.rf_role.name if _adapter.rf_role else '',
                "tags": [str(tag) for tag in _adapter.tags],
                "tags_str": " ".join([str(tag).lower() for tag in _adapter.tags])
            }
            
            return device_id, int_info
    


    def _get_vm_interface_info(self, interface_id):
        """Get VM interface information."""
        with self._lock:
            _adapter = self.nb.virtualization.interfaces.get(id=interface_id)
            if not _adapter:
                return None
            
            vm_id = _adapter.virtual_machine.id if _adapter.virtual_machine else None
                
            int_info = {
                "_netbox_meta": {
                    "type": NetboxDeviceType.INTERFACE_VM.value,
                    "type_field_name": NetboxTypeToName.INTERFACE_VM.field_name,
                    "type_display_name": NetboxTypeToName.INTERFACE_VM.display_name,
                    "type_short_name": NetboxTypeToName.INTERFACE_VM.short_name,
                },
                "enabled": _adapter.enabled,
                "name": _adapter.name,
                "mac_address": _adapter.mac_address,
                "description": _adapter.description,
                "vlan": {
                    "untagged": _adapter.untagged_vlan,
                    "tagged": _adapter.tagged_vlans
                },
                "tags": [str(tag) for tag in _adapter.tags],
                "tags_str": " ".join([str(tag).lower() for tag in _adapter.tags])
            }
            
            return vm_id, int_info

    def _get_device_info(self, device_id):
        """Get device information."""
        with self._lock:
            _device = self.nb.dcim.devices.get(id=device_id)
            if not _device:
                return None
                
            return {
                "_netbox_meta": {
                    "type": NetboxDeviceType.DEVICE.value,
                    "type_field_name": NetboxTypeToName.DEVICE.field_name,
                    "type_display_name": NetboxTypeToName.DEVICE.display_name,
                    "type_short_name": NetboxTypeToName.DEVICE.short_name,
                },
                "name": _device.name if _device else '',
                "display_name": _device.display if _device else '',
                "status": _device.status.value if _device else '',
                "tags": [str(tag) for tag in _device.tags] if _device else [],
                "tags_str": " ".join([str(tag).lower() for tag in _device.tags]) if _device else '',
                "type": {
                    "display_name": _device.device_type.display if _device.device_type else '',
                    "name": _device.device_type.model if _device.device_type else '',
                    "slug": _device.device_type.slug if _device.device_type else ''
                },
                "manufacturer": {
                    "display_name": _device.device_type.manufacturer.display if _device.device_type.manufacturer else '',
                    "name": _device.device_type.manufacturer.name if _device.device_type.manufacturer else '',
                    "slug": _device.device_type.manufacturer.slug if _device.device_type.manufacturer else ''
                },
                "role": {
                    "display_name": _device.role.display if _device.role else '',
                    "name": _device.role.name if _device.role else '',
                    "slug": _device.role.slug if _device.role else ''
                },
                "device_role": {
                    "display_name": _device.device_role.display if _device.device_role else '',
                    "name": _device.device_role.name if _device.device_role else '',
                    "slug": _device.device_role.slug if _device.device_role else ''
                },
                "cluster": {
                    "display_name": _device.cluster.display if _device.cluster else '',
                    "name": _device.cluster.name if _device.cluster else '',
                },
                "site": {
                    "display_name": _device.site.display if _device.site else '',
                    "name": _device.site.name if _device.site else '',
                    "slug": _device.site.slug if _device.site else ''
                }
            }

    def _get_vm_info(self, vm_id):
        """Get virtual machine information."""
        with self._lock:
            _vm = self.nb.virtualization.virtual_machines.get(id=vm_id)
            if not _vm:
                return None
                
            return {
                "_netbox_meta": {
                    "type": NetboxDeviceType.VM.value,
                    "type_field_name": NetboxTypeToName.VM.field_name,
                    "type_display_name": NetboxTypeToName.VM.display_name,
                    "type_short_name": NetboxTypeToName.VM.short_name,
                },
                "name": _vm.name,
                "display_name": _vm.display,
                "status": str(_vm.status),
                "tags": [str(tag) for tag in _vm.tags],
                "tags_str": " ".join([str(tag).lower() for tag in _vm.tags]),
                "role": {
                    "display_name": _vm.role.display,
                    "name": _vm.role.name,
                    "slug": _vm.role.slug
                },
                "cluster": {
                    "display_name": _vm.cluster.display,
                    "name": _vm.cluster.name,
                },
                "site": {
                    "display_name": _vm.site.display,
                    "name": _vm.site.name,
                    "slug": _vm.site.slug
                }
            }

    def get_assigned_objects_by_ip(self, ip_address: Union[str, List[str]]) -> Optional[Dict[str, Any]]:
        """
        Get all assigned objects (Device or Virtual Machine) associated with an IP address.
        Uses caching to improve performance.
        """
        if ip_address is None:
            return None
        
        # Check for cache invalidation
        check_cache_invalidation()
        
        # Handle list of IPs and extract primary_ip
        if isinstance(ip_address, list):
            primary_ip = get_primary_ip(ip_address)
            if primary_ip is None:
                logger.warning(f"No valid IP address found in list: {ip_address}")
                return None
        else:
            primary_ip = ip_address
            
        cache_key = self._get_cache_key(primary_ip)
        
        # Try to get from cache first
        with cache_lock:
            cached_result = cache.get(cache_key)
            if cached_result:
                logger.debug(f"Cache hit for IP: {primary_ip}")
                return cached_result

        try:
            logger.info(f"Processing IP: {primary_ip}")

            # Get IP address object
            ip_obj = self._get_ip_address_info(primary_ip)
            if not ip_obj:
                return None

            # Get parent prefix/subnet
            parent_prefix = self._get_parent_prefix_info(ip_obj.address)
            if not parent_prefix:
                return None

            # Build IP information
            ip_info = self._build_ip_info(ip_obj, parent_prefix)

            if not ip_obj.assigned_object:
                logger.debug(f"No assigned object found for IP {primary_ip}")
                return None

            # Get adapter information based on type
            adapter_info: Optional[Dict[str, Any]] = None
            device_id: Optional[int] = None
            
            if NetboxDeviceType.INTERFACE_DEVICE.value == ip_obj.assigned_object_type.lower():
                result = self._get_device_interface_info(ip_obj.assigned_object.id)
                if result is not None:
                    device_id, adapter_info = result
            elif NetboxDeviceType.INTERFACE_VM.value == ip_obj.assigned_object_type.lower():
                result = self._get_vm_interface_info(ip_obj.assigned_object.id)
                if result is not None:
                    vm_id, adapter_info = result

            # Get device/VM information
            device_info: Optional[Dict[str, Any]] = None
            if adapter_info:
                if NetboxDeviceType.INTERFACE_DEVICE.value == ip_obj.assigned_object_type.lower() and device_id:
                    device_info = self._get_device_info(device_id)
                elif NetboxDeviceType.INTERFACE_VM.value == ip_obj.assigned_object_type.lower() and vm_id:
                    device_info = self._get_vm_info(vm_id)

            result: Dict[str, Any] = {
                "ip": ip_info,
                "adapter": adapter_info,
                "device": device_info
            }

            # Store in cache
            with cache_lock:
                cache[cache_key] = result

            return result

        except Exception as e:
            logger.error(f"Error getting assigned objects for IP {primary_ip}: {str(e)}")
            return None

@app.post('/enrich')
async def enrich_log(request: Request):
    try:
        log_data = await request.json()
        
        # Handle nested data - as it is string
        try:
            log_data['host'] = json.loads(log_data['host'])
            log_data['winlog'] = json.loads(log_data['winlog'])
        except json.JSONDecodeError as je:
            logger.error(f"JSON parsing error in nested data: {str(je)}")
            return {
                "_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "service_version": "1.0",
                    "processor_id": "enrichment_service_01",
                    "status": "error",
                    "error": f"JSON parsing error: {str(je)}"
                },
                "ip": None,
                "adapter": None,
                "device": None
            }
        
        # Add error handling for required fields
        if not isinstance(log_data.get('host'), dict):
            return {
                "_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "service_version": "1.0",
                    "processor_id": "enrichment_service_01",
                    "status": "error",
                    "error": "Missing or invalid 'host' field"
                },
                "ip": None,
                "adapter": None,
                "device": None
            }
        
        if not log_data['host'].get('ip'):
            return {
                "_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "service_version": "1.0",
                    "processor_id": "enrichment_service_01",
                    "status": "error",
                    "error": "Missing 'ip' in host data"
                },
                "ip": None,
                "adapter": None,
                "device": None
            }

        # Get thread-local NetboxAPI instance
        nb = NetboxAPI.get_instance()
        
        # Run the enrichment in a thread pool with timeout
        loop = asyncio.get_event_loop()
        try:
            enriched_data = await asyncio.wait_for(
                loop.run_in_executor(
                    app.state.executor,
                    nb.get_assigned_objects_by_ip,
                    log_data['host']['ip']
                ),
                timeout=25.0  # 25 second timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Timeout while enriching data for IP: {log_data['host']['ip']}")
            return {
                "_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "service_version": "1.0",
                    "processor_id": "enrichment_service_01",
                    "status": "error",
                    "error": "Enrichment timeout"
                },
                "ip": None,
                "adapter": None,
                "device": None
            }

        #logger.info(f"Processing log entry - {log_data['@timestamp']} - {log_data['host']['hostname']} - {log_data['host']['ip']}")

        if enriched_data is None:
            enriched_data = {
                "ip": None,
                "adapter": None,
                "device": None
            }

        # Add processing metadata - always create a new dict to avoid modifying cached data
        result = {
            "ip": enriched_data.get("ip"),
            "adapter": enriched_data.get("adapter"),
            "device": enriched_data.get("device"),
            "_metadata": {
                "timestamp": datetime.now().isoformat(),
                "service_version": "1.0",
                "processor_id": "enrichment_service_01",
                "status": "success"
            }
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}", exc_info=True)
        
        return { 
            "_metadata": {
                "timestamp": datetime.now().isoformat(),
                "service_version": "1.0",
                "processor_id": "enrichment_service_01",
                "status": "error",
                "error": str(e)
            },
            "ip": None,
            "adapter": None,
            "device": None
        }

@app.post('/invalidate-cache')
async def invalidate_cache(
    request: Request,
    authorization: Optional[str] = Header(None),
    body: Dict[str, Any] = Body(...)
):
    """
    Endpoint to invalidate the cache.
    This should be called by Netbox webhooks when relevant data changes.
    """
    try:
        # Verify webhook secret if provided
        if WEBHOOK_SECRET and authorization:
            if not authorization.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Invalid authorization format")
            if authorization[7:] != WEBHOOK_SECRET:  # Skip "Bearer " prefix
                raise HTTPException(status_code=401, detail="Invalid webhook secret")
        
        # Try to parse the webhook payload
        try:
            event = body.get("event", "unknown")
            model = body.get("model", "unknown")
            logger.info(f"Processing webhook for {model} {event}")
        except Exception as e:
            logger.error(f"Error parsing webhook payload: {str(e)}")
            # Don't fail, just log the error
        
        # Clear the cache in this process
        with cache_lock:
            cache.clear()
            logger.info("Local cache cleared successfully")
        
        # Signal other processes to clear their caches
        if touch_invalidation_file():
            logger.info("Cache invalidation signal sent to all processes")
        
        return JSONResponse(
            status_code=200,
            content={"status": "success", "message": "Cache invalidation triggered for all processes"}
        )
    except HTTPException as he:
        logger.error(f"HTTP error in webhook: {str(he)}")
        raise he
    except Exception as e:
        logger.error(f"Error in webhook: {str(e)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)}
        )

@app.on_event("startup")
async def startup_event():
    app.state.executor = ThreadPoolExecutor(max_workers=10)
    
    # Ensure the directory for cache invalidation file exists
    os.makedirs(os.path.dirname(CACHE_INVALIDATION_FILE), exist_ok=True)
    
    # Clear existing cache on startup
    if os.path.exists(CACHE_INVALIDATION_FILE):
        try:
            os.remove(CACHE_INVALIDATION_FILE)
            logger.info(f"Removed existing cache invalidation file at startup")
        except Exception as e:
            logger.error(f"Failed to remove existing cache invalidation file: {str(e)}")
    
    # Create a new cache invalidation file
    touch_invalidation_file()
    logger.info("Cache invalidation file initialized at startup")

@app.on_event("shutdown")
async def shutdown_event():
    app.state.executor.shutdown()

if __name__ == '__main__':
    logger.info("Starting Log Enrichment Service...")
    # Run with multiple workers based on CPU cores
    uvicorn.run(
        "enricher_api:app",
        host='0.0.0.0',
        port=5123,
        workers=10,  # Number of worker processes
        loop="uvloop",  # Use uvloop for better performance
        http="httptools",  # Use httptools for better performance
        reload=False
    )
