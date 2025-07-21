# CSW to FMC Dynamic Objects Synchronization - Simplified Version

This is a simplified, unified version of the CSW to FMC Dynamic Objects synchronization scripts. It combines the functionality of both `csw-all-inventory-processing.py` and `fmc-dynobjects-all-objects.py` into a single, streamlined solution.

## Overview

The script performs the following operations:
1. **CSW Integration**: Connects to Cisco Secure Workload (CSW) to retrieve inventory data based on configured filters
2. **Data Processing**: Converts CSW inventory data into FMC-compatible dynamic object mappings
3. **FMC Synchronization**: Connects to Firepower Management Center (FMC) to synchronize dynamic objects
4. **Continuous Monitoring**: Runs continuously, updating objects every 30 seconds (configurable)

## Features

- **Unified Script**: Single script instead of two separate ones
- **Automatic Token Management**: Handles FMC token refresh automatically
- **Error Handling**: Robust error handling and logging
- **Configurable**: Customizable sync intervals and debug options
- **Clean Code**: Well-structured, documented, and maintainable

## Requirements

### Dependencies
Install the required Python packages:

```bash
pip install -r requirements.txt
```

### Required Files
1. **CSW API Credentials** (`api-csw.json`):
   ```json
   {
     "api_key": "your_csw_api_key",
     "api_secret": "your_csw_api_secret"
   }
   ```

## Usage

### Basic Usage
```bash
python csw-fmc-dynamic-objects-sync.py <csw_cluster> <csw_scope> <fmc_ip> <fmc_username> <fmc_password>
```

### Parameters
- `csw_cluster`: CSW cluster hostname or IP address
- `csw_scope`: CSW scope name to query
- `fmc_ip`: FMC IP address  
- `fmc_username`: FMC username
- `fmc_password`: FMC password

### Optional Parameters
- `--credentials <file>`: CSW API credentials file (default: `api-csw.json`)
- `--interval <seconds>`: Sync interval in seconds (default: 30)
- `--debug`: Enable debug logging

### Examples

**Basic synchronization:**
```bash
python csw-fmc-dynamic-objects-sync.py my-csw-cluster.com MyScope 192.168.1.100 admin password123
```

**With custom settings:**
```bash
python csw-fmc-dynamic-objects-sync.py my-csw-cluster.com MyScope 192.168.1.100 admin password123 \
  --credentials my-api-creds.json \
  --interval 60 \
  --debug
```

## How It Works

### CSW Data Processing
1. Retrieves inventory filters from CSW
2. For each filter, queries inventory data
3. Processes IP addresses and netmasks into CIDR notation
4. Groups data by filter name to create dynamic objects

### FMC Synchronization
1. Authenticates with FMC and manages token refresh
2. Retrieves existing dynamic objects with the `csw-fmc-` prefix
3. Compares CSW data with existing FMC objects
4. Performs synchronization:
   - **Adds** new objects that exist in CSW but not in FMC
   - **Removes** objects that exist in FMC but not in CSW
   - **Updates** mappings for objects that exist in both systems

### Continuous Operation
- Runs in a continuous loop with configurable intervals
- Handles errors gracefully and continues operation
- Logs all activities for monitoring and debugging

## Output Files

The script generates the following files:
- `csw-fmc-sync.log`: Main log file with all activities
- Temporary processing files (handled internally)

## Configuration

### Dynamic Object Naming
- Objects are prefixed with `csw-fmc-` to identify them
- Names are sanitized to comply with FMC requirements
- Spaces are replaced with hyphens, invalid characters removed

### IP Address Processing
- Supports both individual IPs and CIDR notation
- Automatically converts netmask to CIDR notation
- Normalizes all IPs to include CIDR (adds /32 for individual IPs)

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Verify CSW API credentials in `api-csw.json`
   - Check FMC username/password
   - Ensure FMC user has appropriate permissions

2. **Connection Issues**
   - Verify network connectivity to CSW and FMC
   - Check if SSL certificates are valid (script disables SSL verification)
   - Ensure firewall rules allow access

3. **Token Expiration**
   - Script automatically refreshes FMC tokens every 20 minutes
   - Check FMC logs if authentication issues persist

4. **Debugging**
   - Use `--debug` flag for detailed logging
   - Check the log file for specific error messages
   - Verify scope name exists in CSW

### Log Messages
- All activities are logged with timestamps
- Error messages include specific details for troubleshooting
- Debug mode provides additional detailed information

## Differences from Original Scripts

### Improvements
- **Single File**: Eliminates the need to manage two separate scripts
- **Simplified Configuration**: Fewer configuration files to manage
- **Better Error Handling**: More robust error handling and recovery
- **Cleaner Code**: Better organized, documented, and maintainable
- **Flexible Options**: Command-line options for customization

### Removed Complexity
- Eliminated intermediate JSON files
- Simplified data flow between CSW and FMC processing
- Reduced file I/O operations
- Streamlined logging approach

## Security Considerations

- Store CSW API credentials securely in the `api-csw.json` file
- Use environment variables for FMC credentials in production
- Restrict file permissions on credential files
- Consider using encrypted storage for sensitive data
- Monitor log files for security events

## Support

For issues or questions:
1. Check the log file for specific error messages
2. Verify all configuration parameters
3. Test connectivity to both CSW and FMC independently
4. Review the CSW scope and filter configurations
