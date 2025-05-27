<div align="center">
  <img src="assets/logo_netenrich.png" alt="NetEnrich Logo" width="200"/>
</div>

NetEnrich is a FastAPI-based service designed to enrich log data with device and network information from NetBox. It provides a caching mechanism and webhook support for cache invalidation, making it efficient for high-volume log processing environments.

## Features

- Real-time log enrichment with NetBox data
- Thread-safe caching mechanism with TTL
- Webhook support for cache invalidation
- Support for both physical devices and virtual machines
- Integration with Logstash
- Docker support for easy deployment

## Prerequisites

- Python 3.11+
- NetBox instance with API access
- Docker and Docker Compose (for containerized deployment)
- Logstash instance with `http` filter function to call endpoint

## Environment Variables

The following environment variables need to be configured:

- `NETBOX_URL`: URL of your NetBox instance
- `NETBOX_TOKEN`: NetBox API token
- `WEBHOOK_SECRET`: Secret key for webhook authentication (optional)

## Installation and Deployment

### Using Docker (Recommended)

1. Clone the repository
2. Configure environment variables in `docker-compose.yml`:
   ```yaml
   environment:
     - NETBOX_URL=https://<your-netbox-host>
     - NETBOX_TOKEN=<your-netbox-api-token>
   ```
3. Build and run the container:
   ```bash
   docker-compose up -d
   ```

### Manual Installation

1. Create a Python virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python enricher_api.py
   ```

## API Endpoints

### POST /enrich
Enriches log data with NetBox information.

**Request Body Example:**
```json
{
  "host": {
    "ip": ["192.168.1.100"],
    "hostname": "device-1"
  },
  "winlog": {}
}
```

### POST /invalidate-cache
Invalidates the cache when NetBox data changes. Can be configured as a NetBox webhook.

## Enriched Data Fields

The service enriches logs with the following information from NetBox:

### IP Information

| Field | Description |
|-------|-------------|
| `ip` | IP address in CIDR format |
| `dns_name` | DNS name associated with the IP |
| `status` | Current status of the IP |
| `family` | IP version (IPv4/IPv6) |
| `tags` | Associated tags |
| `tags_str` | Tags as space-separated string |

### Subnet Information

| Field | Description |
|-------|-------------|
| `prefix` | Network prefix |
| `description` | Subnet description |
| `status` | Subnet status |
| `role.name` | Role name |
| `role.display_name` | Role display name |
| `role.slug` | Role slug |
| `vlan.name` | VLAN name |
| `vlan.id` | VLAN ID |
| `site.name` | Site name |
| `site.slug` | Site slug |
| `tags` | Associated tags |
| `tags_str` | Tags as space-separated string |

### Device/VM Information

| Field | Description |
|-------|-------------|
| `name` | Device/VM name |
| `display_name` | Display name |
| `status` | Operational status |
| `role.name` | Role name |
| `role.display_name` | Role display name |
| `role.slug` | Role slug |
| `type.name` | Device type (physical devices only) |
| `type.display_name` | Type display name |
| `type.slug` | Type slug |
| `manufacturer.name` | Manufacturer name |
| `manufacturer.display_name` | Manufacturer display name |
| `manufacturer.slug` | Manufacturer slug |
| `cluster.name` | Cluster name |
| `cluster.display_name` | Cluster display name |
| `site.name` | Site name |
| `site.display_name` | Site display name |
| `site.slug` | Site slug |
| `tags` | Associated tags |
| `tags_str` | Tags as space-separated string |

### Interface Information

| Field | Description |
|-------|-------------|
| `name` | Interface name |
| `label` | Interface label |
| `enabled` | Interface status |
| `mac_address` | MAC address |
| `description` | Interface description |
| `vlan.untagged` | Untagged VLAN |
| `vlan.tagged` | Tagged VLANs |
| `role` | Interface role |
| `role_name` | Interface role name |
| `tags` | Associated tags |
| `tags_str` | Tags as space-separated string |

## Logstash Integration

To integrate with Logstash, configure a HTTP filter in your Logstash pipeline:

```ruby
filter {
        http {
            url => "http://log-enricher:5123/enrich"
            verb => "POST"
            body_format => "json"
            target_body => "netbox"
            
            # Add request body mapping
            body => {
                "message" => "%{message}"
                "winlog" => "%{[winlog]}"
                "@timestamp" => "%{@timestamp}"
                "host" => "%{[host]}"
            }
        }
}
```

Example logstash pipeline can be found in `./logstash/pipeline.conf

## Performance Considerations

- The service uses a thread-safe cache with a default TTL of 24 hours
- Cache invalidation is supported via webhooks and file-based signaling
- The service runs with multiple workers (default: 10) for better performance
- Uses uvloop and httptools for improved async performance

## Error Handling

The service includes error handling:
- Invalid JSON data in requests
- Missing required fields
- NetBox API timeouts (25-second default)
- Cache invalidation errors

## Monitoring

The service logs important events and errors using the Loguru logger. Monitor the application logs for:
- Cache invalidations
- API timeouts
- Request processing errors
- Webhook events

## Security

- Webhook endpoints can be secured with a secret key
- HTTPS support for NetBox communication
- Bearer token authentication for webhook endpoints
