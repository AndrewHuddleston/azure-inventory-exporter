#!/bin/bash

# Azure Services Inventory Script
# Purpose: Extract deployed services from Azure subscription for Solution Design Document

# Enable debug mode (comment out when working)
# set -x

echo "=========================================="
echo "Azure Subscription Services Inventory"
echo "=========================================="
echo ""

# Check if logged in to Azure
if ! az account show &> /dev/null; then
    echo "Error: Not logged in to Azure. Please run 'az login' first."
    exit 1
fi

# Get subscription name
SUBSCRIPTION=$(az account show --query name -o tsv)
echo "Subscription: $SUBSCRIPTION"
echo ""

# Get all resource types deployed
echo "Gathering resource information..."
RESOURCES=$(az resource list --query "[].type" -o tsv | sort -u)

if [ -z "$RESOURCES" ]; then
    echo "WARNING: No resources found in subscription. Please check:"
    echo "  1. You have resources deployed in this subscription"
    echo "  2. You have permissions to view resources"
    echo "  3. Try running: az resource list"
    exit 1
fi

# Initialize arrays for each category
declare -a REGIONS=()
declare -a NETWORKING=()
declare -a COMPUTE=()
declare -a STORAGE=()
declare -a DATABASE=()
declare -a SECURITY=()
declare -a OPERATIONS=()
declare -a OTHER=()

# Get unique regions
REGIONS=($(az resource list --query "[].location" -o tsv | sort -u))

# Categorize resources with explicit friendly names
while IFS= read -r resource; do
    case $resource in
        # Networking
        Microsoft.Network/virtualNetworks) NETWORKING+=("Virtual Network") ;;
        Microsoft.Network/networkSecurityGroups) NETWORKING+=("Network Security Group") ;;
        Microsoft.Network/publicIPAddresses) NETWORKING+=("Public IP Address") ;;
        Microsoft.Network/loadBalancers) NETWORKING+=("Load Balancer") ;;
        Microsoft.Network/applicationGateways) NETWORKING+=("Application Gateway") ;;
        Microsoft.Network/natGateways) NETWORKING+=("NAT Gateway") ;;
        Microsoft.Network/privateEndpoints) NETWORKING+=("Private Endpoint") ;;
        Microsoft.Network/privateDnsZones) NETWORKING+=("Private DNS Zone") ;;
        Microsoft.Network/privateDnsZones/virtualNetworkLinks) NETWORKING+=("Private DNS Zone VNet Link") ;;
        Microsoft.Network/networkInterfaces) NETWORKING+=("Network Interface") ;;
        Microsoft.Network/networkWatchers) NETWORKING+=("Network Watcher") ;;
        Microsoft.Network/routeTables) NETWORKING+=("Route Table") ;;
        Microsoft.Network/networkIntentPolicies) NETWORKING+=("Network Intent Policy") ;;
        Microsoft.Cdn/profiles) NETWORKING+=("CDN Profile") ;;
        Microsoft.Cdn/profiles/endpoints) NETWORKING+=("CDN Endpoint") ;;
        Microsoft.SignalRService/WebPubSub) NETWORKING+=("Web PubSub") ;;
        
        # Compute
        Microsoft.Compute/virtualMachines) COMPUTE+=("Virtual Machine") ;;
        Microsoft.Compute/virtualMachines/extensions) COMPUTE+=("VM Extension") ;;
        Microsoft.Compute/disks) COMPUTE+=("Managed Disk") ;;
        Microsoft.Compute/sshPublicKeys) COMPUTE+=("SSH Public Key") ;;
        Microsoft.Compute/restorePointCollections) COMPUTE+=("Restore Point Collection") ;;
        Microsoft.Web/serverFarms) COMPUTE+=("App Service Plan") ;;
        Microsoft.Web/sites) COMPUTE+=("App Service / Web App") ;;
        Microsoft.Web/staticSites) COMPUTE+=("Static Web App") ;;
        Microsoft.App/containerApps) COMPUTE+=("Container App") ;;
        Microsoft.App/managedEnvironments) COMPUTE+=("Container Apps Environment") ;;
        Microsoft.ApiManagement/service) COMPUTE+=("API Management") ;;
        Microsoft.BotService/botServices) COMPUTE+=("Bot Service") ;;
        Microsoft.CognitiveServices/accounts) COMPUTE+=("Cognitive Services") ;;
        Microsoft.Databricks/workspaces) COMPUTE+=("Databricks Workspace") ;;
        Microsoft.Databricks/accessConnectors) COMPUTE+=("Databricks Access Connector") ;;
        Microsoft.MachineLearningServices/workspaces) COMPUTE+=("Machine Learning Workspace") ;;
        
        # Storage
        Microsoft.Storage/storageAccounts) STORAGE+=("Storage Account") ;;
        Microsoft.ContainerRegistry/registries) STORAGE+=("Container Registry") ;;
        
        # Database
        Microsoft.Sql/servers) DATABASE+=("SQL Server") ;;
        Microsoft.Sql/servers/databases) DATABASE+=("SQL Database") ;;
        Microsoft.DocumentDB/databaseAccounts|Microsoft.DocumentDb/databaseAccounts) DATABASE+=("Cosmos DB") ;;
        Microsoft.EventHub/namespaces) DATABASE+=("Event Hub Namespace") ;;
        Microsoft.ServiceBus/namespaces) DATABASE+=("Service Bus Namespace") ;;
        Microsoft.Search/searchServices) DATABASE+=("Azure Cognitive Search") ;;
        
        # Security
        Microsoft.KeyVault/vaults) SECURITY+=("Key Vault") ;;
        Microsoft.ManagedIdentity/userAssignedIdentities) SECURITY+=("Managed Identity") ;;
        
        # Operations
        Microsoft.RecoveryServices/vaults) OPERATIONS+=("Recovery Services Vault") ;;
        Microsoft.OperationalInsights/workspaces) OPERATIONS+=("Log Analytics Workspace") ;;
        Microsoft.Insights/components|microsoft.insights/components) OPERATIONS+=("Application Insights") ;;
        Microsoft.Insights/actiongroups|microsoft.insights/actiongroups) OPERATIONS+=("Action Group") ;;
        Microsoft.Insights/activityLogAlerts) OPERATIONS+=("Activity Log Alert") ;;
        Microsoft.Insights/metricalerts|microsoft.insights/metricalerts) OPERATIONS+=("Metric Alert") ;;
        Microsoft.Insights/scheduledqueryrules) OPERATIONS+=("Scheduled Query Rule") ;;
        Microsoft.Insights/dataCollectionRules) OPERATIONS+=("Data Collection Rule") ;;
        microsoft.operationalInsights/querypacks) OPERATIONS+=("Query Pack") ;;
        Microsoft.OperationsManagement/solutions) OPERATIONS+=("Management Solution") ;;
        microsoft.alertsmanagement/smartDetectorAlertRules) OPERATIONS+=("Smart Detector Alert Rule") ;;
        Microsoft.Migrate/moveCollections) OPERATIONS+=("Move Collection") ;;
        
        # Catch others
        *) OTHER+=("$resource") ;;
    esac
done <<< "$RESOURCES"

# Function to print unique sorted array
print_category() {
    local category=$1
    shift
    local items=("$@")
    
    if [ ${#items[@]} -gt 0 ]; then
        # Get unique items and sort, preserving multi-word elements
        local sorted_output=$(printf '%s\n' "${items[@]}" | sort -u)
        local first_item=1
        
        printf "%s: " "$category"
        while IFS= read -r item; do
            if [ $first_item -eq 1 ]; then
                printf '%s' "$item"
                first_item=0
            else
                printf ", %s" "$item"
            fi
        done <<< "$sorted_output"
        printf "\n"
    fi
}

# Output results
echo "=========================================="
echo ""

# Regions
if [ ${#REGIONS[@]} -gt 0 ]; then
    printf "Regions: "
    printf '%s' "${REGIONS[0]}"
    for region in "${REGIONS[@]:1}"; do
        printf ", %s" "$region"
    done
    printf "\n"
fi

# Service categories
print_category "Networking" "${NETWORKING[@]}"
print_category "Compute" "${COMPUTE[@]}"
print_category "Storage" "${STORAGE[@]}"
print_category "Database" "${DATABASE[@]}"
print_category "Security" "${SECURITY[@]}"
print_category "Operations" "${OPERATIONS[@]}"

# Other uncategorized resources
if [ ${#OTHER[@]} -gt 0 ]; then
    echo ""
    echo "Other Resources (uncategorized):"
    printf '%s\n' "${OTHER[@]}" | sort -u
fi

# Get all resource tags
echo ""
echo "Resource Tags:"
TAGS=$(az resource list --query "[].tags" -o json 2>/dev/null)

if [ -n "$TAGS" ] && [ "$TAGS" != "[]" ] && [ "$TAGS" != "null" ]; then
    # Parse tags and create unique key:value pairs
    echo "$TAGS" | jq -r 'map(select(. != null) | to_entries[] | "\(.key): \(.value)") | unique | sort[]' 2>/dev/null | while IFS= read -r tag; do
        if [ -n "$tag" ]; then
            echo "  $tag"
        fi
    done
else
    echo "  No tags found on resources"
fi

# Get Virtual Machine details
echo ""
echo "=========================================="
echo "Virtual Machines:"
echo "=========================================="

VMS=$(az vm list 2>/dev/null)

if [ -n "$VMS" ] && [ "$VMS" != "[]" ]; then
    # Print table header
    printf "%-15s | %-30s | %-20s | %-20s | %-20s | %-40s\n" "Role" "Instance Name" "OS" "AZ" "Instance Type" "Storage Details"
    printf "%.15s-+-%.30s-+-%.20s-+-%.20s-+-%.20s-+-%.40s\n" "---------------" "------------------------------" "--------------------" "--------------------" "--------------------" "----------------------------------------"
    
    # Get VM names and resource groups
    az vm list --query "[].[name, resourceGroup]" -o tsv | while IFS=$'\t' read -r vm_name rg; do
        if [ -n "$vm_name" ] && [ -n "$rg" ]; then
            # Get details for this specific VM with resource group
            VM_SIZE=$(az vm show -n "$vm_name" -g "$rg" --query "hardwareProfile.vmSize" -o tsv 2>/dev/null)
            VM_OS=$(az vm show -n "$vm_name" -g "$rg" --query "storageProfile.osDisk.osType" -o tsv 2>/dev/null)
            VM_ZONES=$(az vm show -n "$vm_name" -g "$rg" --query "zones | join(',', @)" -o tsv 2>/dev/null)
            OS_DISK_SIZE=$(az vm show -n "$vm_name" -g "$rg" --query "storageProfile.osDisk.diskSizeGb" -o tsv 2>/dev/null)
            OS_DISK_TYPE=$(az vm show -n "$vm_name" -g "$rg" --query "storageProfile.osDisk.managedDisk.storageAccountType" -o tsv 2>/dev/null)
            DATA_DISK_COUNT=$(az vm show -n "$vm_name" -g "$rg" --query "length(storageProfile.dataDisks)" -o tsv 2>/dev/null)
            
            # Set defaults if empty
            VM_OS=${VM_OS:-"Unknown"}
            VM_ZONES=${VM_ZONES:-"None"}
            OS_DISK_SIZE=${OS_DISK_SIZE:-"N/A"}
            OS_DISK_TYPE=${OS_DISK_TYPE:-"N/A"}
            DATA_DISK_COUNT=${DATA_DISK_COUNT:-"0"}
            
            # Build storage info string
            if [ "$DATA_DISK_COUNT" -gt 0 ]; then
                STORAGE_INFO="OS: ${OS_DISK_SIZE}GB (${OS_DISK_TYPE}), Data: ${DATA_DISK_COUNT} disk(s)"
            else
                STORAGE_INFO="OS: ${OS_DISK_SIZE}GB (${OS_DISK_TYPE})"
            fi
            
            # Print row with empty Role column
            printf "%-15s | %-30s | %-20s | %-20s | %-20s | %-40s\n" "" "$vm_name" "$VM_OS" "$VM_ZONES" "$VM_SIZE" "$STORAGE_INFO"
        fi
    done
else
    echo "No virtual machines found in subscription"
fi

# Get Backup Configuration
echo ""
echo "=========================================="
echo "Backup Configuration:"
echo "=========================================="

# Check for Recovery Services Vaults
VAULTS=$(az backup vault list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$VAULTS" ]; then
    # Loop through each vault
    while IFS= read -r vault_name; do
        if [ -n "$vault_name" ]; then
            # Get vault resource group
            VAULT_RG=$(az backup vault list --query "[?name=='$vault_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$VAULT_RG" ]; then
                echo ""
                echo "Recovery Services Vault: $vault_name"
                echo "----------------------------------------"
                
                # Get backup items (VMs)
                VM_BACKUPS=$(az backup item list --vault-name "$vault_name" -g "$VAULT_RG" --query "[?properties.workloadType=='VM'].[properties.friendlyName, properties.policyName]" -o tsv 2>/dev/null)
                
                if [ -n "$VM_BACKUPS" ]; then
                    echo ""
                    echo "Virtual Machine Backups:"
                    printf "  %-40s | %-30s | %-20s | %-20s\n" "Resource Name" "Policy Name" "Frequency" "Retention"
                    printf "  %.40s-+-%.30s-+-%.20s-+-%.20s\n" "----------------------------------------" "------------------------------" "--------------------" "--------------------"
                    
                    echo "$VM_BACKUPS" | while IFS=$'\t' read -r item_name policy_name; do
                        if [ -n "$policy_name" ]; then
                            # Get policy details
                            POLICY_INFO=$(az backup policy show --name "$policy_name" --vault-name "$vault_name" -g "$VAULT_RG" --query "{freq: properties.schedulePolicy.scheduleRunFrequency, time: properties.schedulePolicy.scheduleRunTimes[0], retention: properties.retentionPolicy.dailySchedule.retentionDuration.count}" -o json 2>/dev/null)
                            
                            if [ -n "$POLICY_INFO" ]; then
                                FREQUENCY=$(echo "$POLICY_INFO" | jq -r '.freq // "N/A"')
                                RETENTION=$(echo "$POLICY_INFO" | jq -r '.retention // "N/A"')
                                
                                printf "  %-40s | %-30s | %-20s | %-20s\n" "$item_name" "$policy_name" "$FREQUENCY" "${RETENTION} days"
                            fi
                        fi
                    done
                fi
                
                # Get SQL backups
                SQL_BACKUPS=$(az backup item list --vault-name "$vault_name" -g "$VAULT_RG" --query "[?properties.workloadType=='SQLDataBase'].[properties.friendlyName, properties.policyName]" -o tsv 2>/dev/null)
                
                if [ -n "$SQL_BACKUPS" ]; then
                    echo ""
                    echo "SQL Database Backups:"
                    printf "  %-40s | %-30s | %-20s | %-20s\n" "Database Name" "Policy Name" "Frequency" "Retention"
                    printf "  %.40s-+-%.30s-+-%.20s-+-%.20s\n" "----------------------------------------" "------------------------------" "--------------------" "--------------------"
                    
                    echo "$SQL_BACKUPS" | while IFS=$'\t' read -r item_name policy_name; do
                        if [ -n "$policy_name" ]; then
                            # Get policy details
                            POLICY_INFO=$(az backup policy show --name "$policy_name" --vault-name "$vault_name" -g "$VAULT_RG" --query "{freq: properties.schedulePolicy.scheduleRunFrequency, retention: properties.retentionPolicy.dailySchedule.retentionDuration.count}" -o json 2>/dev/null)
                            
                            if [ -n "$POLICY_INFO" ]; then
                                FREQUENCY=$(echo "$POLICY_INFO" | jq -r '.freq // "N/A"')
                                RETENTION=$(echo "$POLICY_INFO" | jq -r '.retention // "N/A"')
                                
                                printf "  %-40s | %-30s | %-20s | %-20s\n" "$item_name" "$policy_name" "$FREQUENCY" "${RETENTION} days"
                            fi
                        fi
                    done
                fi
            fi
        fi
    done <<< "$VAULTS"
else
    echo "No Recovery Services Vaults found with backup configurations"
fi

# Check for SQL Server Long-Term Retention policies
echo ""
echo "SQL Server Long-Term Retention Policies:"
echo "----------------------------------------"

SQL_SERVERS=$(az sql server list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$SQL_SERVERS" ]; then
    SQL_LTR_FOUND=0
    
    while IFS= read -r sql_server; do
        if [ -n "$sql_server" ]; then
            SQL_RG=$(az sql server list --query "[?name=='$sql_server'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$SQL_RG" ]; then
                # Get databases for this server
                DBS=$(az sql db list -s "$sql_server" -g "$SQL_RG" --query "[?name!='master'].name" -o tsv 2>/dev/null)
                
                while IFS= read -r db_name; do
                    if [ -n "$db_name" ]; then
                        # Check for long-term retention policy
                        LTR_POLICY=$(az sql db ltr-policy show --database "$db_name" --server "$sql_server" -g "$SQL_RG" 2>/dev/null)
                        
                        if [ -n "$LTR_POLICY" ]; then
                            WEEKLY=$(echo "$LTR_POLICY" | jq -r '.weeklyRetention // "None"')
                            MONTHLY=$(echo "$LTR_POLICY" | jq -r '.monthlyRetention // "None"')
                            YEARLY=$(echo "$LTR_POLICY" | jq -r '.yearlyRetention // "None"')
                            
                            if [ "$WEEKLY" != "None" ] || [ "$MONTHLY" != "None" ] || [ "$YEARLY" != "None" ]; then
                                SQL_LTR_FOUND=1
                                echo "  Server: $sql_server | Database: $db_name"
                                echo "    Weekly: $WEEKLY | Monthly: $MONTHLY | Yearly: $YEARLY"
                            fi
                        fi
                    fi
                done <<< "$DBS"
            fi
        fi
    done <<< "$SQL_SERVERS"
    
    if [ $SQL_LTR_FOUND -eq 0 ]; then
        echo "  No SQL databases with long-term retention policies configured"
    fi
else
    echo "  No SQL servers found"
fi

# Check for Automatic Backup Configurations (Built-in Azure services)
echo ""
echo "Automatic/Built-in Backup Configurations:"
echo "----------------------------------------"

# Azure SQL Database Automatic Backups
echo ""
echo "Azure SQL Database (Automatic Point-in-Time Restore):"
if [ -n "$SQL_SERVERS" ]; then
    while IFS= read -r sql_server; do
        if [ -n "$sql_server" ]; then
            SQL_RG=$(az sql server list --query "[?name=='$sql_server'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$SQL_RG" ]; then
                DBS=$(az sql db list -s "$sql_server" -g "$SQL_RG" --query "[?name!='master'].name" -o tsv 2>/dev/null)
                
                while IFS= read -r db_name; do
                    if [ -n "$db_name" ]; then
                        # Get backup retention
                        RETENTION=$(az sql db show -n "$db_name" -s "$sql_server" -g "$SQL_RG" --query "retentionDays" -o tsv 2>/dev/null)
                        RETENTION=${RETENTION:-"7"}
                        
                        echo "  Server: $sql_server | Database: $db_name"
                        echo "    Automatic Backups: Enabled (Default) | PITR Retention: $RETENTION days"
                    fi
                done <<< "$DBS"
            fi
        fi
    done <<< "$SQL_SERVERS"
else
    echo "  No SQL servers found"
fi

# Cosmos DB Automatic Backups
echo ""
echo "Cosmos DB (Automatic Continuous Backup):"
COSMOS_ACCOUNTS=$(az cosmosdb list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$COSMOS_ACCOUNTS" ]; then
    while IFS= read -r cosmos_account; do
        if [ -n "$cosmos_account" ]; then
            COSMOS_RG=$(az cosmosdb list --query "[?name=='$cosmos_account'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$COSMOS_RG" ]; then
                # Get backup policy
                BACKUP_POLICY=$(az cosmosdb show -n "$cosmos_account" -g "$COSMOS_RG" --query "backupPolicy" -o json 2>/dev/null)
                
                if [ -n "$BACKUP_POLICY" ]; then
                    BACKUP_TYPE=$(echo "$BACKUP_POLICY" | jq -r '.type // "Periodic"')
                    
                    if [ "$BACKUP_TYPE" = "Periodic" ]; then
                        INTERVAL=$(echo "$BACKUP_POLICY" | jq -r '.periodicModeProperties.backupIntervalInMinutes // "240"')
                        RETENTION=$(echo "$BACKUP_POLICY" | jq -r '.periodicModeProperties.backupRetentionIntervalInHours // "8"')
                        echo "  Account: $cosmos_account"
                        echo "    Backup Type: Periodic | Interval: ${INTERVAL}min | Retention: ${RETENTION}hrs"
                    else
                        echo "  Account: $cosmos_account"
                        echo "    Backup Type: Continuous (Point-in-Time Restore up to 30 days)"
                    fi
                fi
            fi
        fi
    done <<< "$COSMOS_ACCOUNTS"
else
    echo "  No Cosmos DB accounts found"
fi

# Storage Account Soft Delete and Versioning
echo ""
echo "Storage Accounts (Soft Delete & Versioning):"
STORAGE_ACCOUNTS=$(az storage account list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$STORAGE_ACCOUNTS" ]; then
    while IFS= read -r storage_account; do
        if [ -n "$storage_account" ]; then
            STORAGE_RG=$(az storage account list --query "[?name=='$storage_account'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$STORAGE_RG" ]; then
                # Check blob soft delete
                BLOB_SOFT_DELETE=$(az storage account blob-service-properties show --account-name "$storage_account" -g "$STORAGE_RG" --query "deleteRetentionPolicy.enabled" -o tsv 2>/dev/null)
                BLOB_RETENTION_DAYS=$(az storage account blob-service-properties show --account-name "$storage_account" -g "$STORAGE_RG" --query "deleteRetentionPolicy.days" -o tsv 2>/dev/null)
                
                # Check versioning
                VERSIONING=$(az storage account blob-service-properties show --account-name "$storage_account" -g "$STORAGE_RG" --query "isVersioningEnabled" -o tsv 2>/dev/null)
                
                if [ "$BLOB_SOFT_DELETE" = "true" ] || [ "$VERSIONING" = "true" ]; then
                    echo "  Storage Account: $storage_account"
                    if [ "$BLOB_SOFT_DELETE" = "true" ]; then
                        echo "    Blob Soft Delete: Enabled | Retention: ${BLOB_RETENTION_DAYS:-7} days"
                    fi
                    if [ "$VERSIONING" = "true" ]; then
                        echo "    Blob Versioning: Enabled"
                    fi
                fi
            fi
        fi
    done <<< "$STORAGE_ACCOUNTS"
else
    echo "  No storage accounts found"
fi

# Get Virtual Network details
echo ""
echo "=========================================="
echo "Virtual Networks:"
echo "=========================================="

VNETS=$(az network vnet list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$VNETS" ]; then
    # Print table header
    printf "%-30s | %-20s | %-30s | %-40s\n" "VNet Name" "Location" "CIDR Block" "DNS Servers"
    printf "%.30s-+-%.20s-+-%.30s-+-%.40s\n" "------------------------------" "--------------------" "------------------------------" "----------------------------------------"
    
    while IFS= read -r vnet_name; do
        if [ -n "$vnet_name" ]; then
            # Get VNet resource group
            VNET_RG=$(az network vnet list --query "[?name=='$vnet_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$VNET_RG" ]; then
                # Get VNet details
                LOCATION=$(az network vnet show -n "$vnet_name" -g "$VNET_RG" --query "location" -o tsv 2>/dev/null)
                
                # Get address prefixes (CIDR blocks)
                CIDR_BLOCKS=$(az network vnet show -n "$vnet_name" -g "$VNET_RG" --query "addressSpace.addressPrefixes | join(', ', @)" -o tsv 2>/dev/null)
                CIDR_BLOCKS=${CIDR_BLOCKS:-"N/A"}
                
                # Get DNS servers
                DNS_SERVERS=$(az network vnet show -n "$vnet_name" -g "$VNET_RG" --query "dhcpOptions.dnsServers | join(', ', @)" -o tsv 2>/dev/null)
                
                if [ -z "$DNS_SERVERS" ] || [ "$DNS_SERVERS" = "null" ]; then
                    DNS_SERVERS="Default (Azure-provided)"
                fi
                
                # Print row
                printf "%-30s | %-20s | %-30s | %-40s\n" "$vnet_name" "$LOCATION" "$CIDR_BLOCKS" "$DNS_SERVERS"
            fi
        fi
    done <<< "$VNETS"
else
    echo "No virtual networks found in subscription"
fi

# Get Subnet details
echo ""
echo "=========================================="
echo "Subnets:"
echo "=========================================="

VNETS=$(az network vnet list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$VNETS" ]; then
    # Print table header
    printf "%-30s | %-20s | %-25s | %-18s | %-30s | %-15s\n" "Subnet Name" "Subnet Address" "Subnet Range" "# of Addresses" "Delegation" "Description"
    printf "%.30s-+-%.20s-+-%.25s-+-%.18s-+-%.30s-+-%.15s\n" "------------------------------" "--------------------" "-------------------------" "------------------" "------------------------------" "---------------"
    
    while IFS= read -r vnet_name; do
        if [ -n "$vnet_name" ]; then
            # Get VNet resource group
            VNET_RG=$(az network vnet list --query "[?name=='$vnet_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$VNET_RG" ]; then
                # Get all subnets in this VNet
                SUBNETS=$(az network vnet subnet list -g "$VNET_RG" --vnet-name "$vnet_name" --query "[].name" -o tsv 2>/dev/null)
                
                while IFS= read -r subnet_name; do
                    if [ -n "$subnet_name" ]; then
                        # Get subnet details
                        SUBNET_PREFIX=$(az network vnet subnet show -g "$VNET_RG" --vnet-name "$vnet_name" -n "$subnet_name" --query "addressPrefix" -o tsv 2>/dev/null)
                        
                        # Calculate subnet range and number of addresses
                        if [ -n "$SUBNET_PREFIX" ]; then
                            # Extract IP and prefix length
                            SUBNET_IP=$(echo "$SUBNET_PREFIX" | cut -d'/' -f1)
                            PREFIX_LEN=$(echo "$SUBNET_PREFIX" | cut -d'/' -f2)
                            
                            # Calculate number of addresses (2^(32-prefix) - 5 for Azure reserved IPs)
                            TOTAL_ADDRESSES=$((2**(32-PREFIX_LEN)))
                            USABLE_ADDRESSES=$((TOTAL_ADDRESSES - 5))
                            
                            # Calculate first and last IP for range display
                            # For display purposes, show as "first - last"
                            SUBNET_RANGE="$SUBNET_PREFIX"
                        else
                            SUBNET_RANGE="N/A"
                            USABLE_ADDRESSES="N/A"
                        fi
                        
                        # Get delegation
                        DELEGATION=$(az network vnet subnet show -g "$VNET_RG" --vnet-name "$vnet_name" -n "$subnet_name" --query "delegations[0].serviceName" -o tsv 2>/dev/null)
                        
                        if [ -z "$DELEGATION" ] || [ "$DELEGATION" = "null" ]; then
                            DELEGATION="None"
                        fi
                        
                        # Print row with empty Description column
                        printf "%-30s | %-20s | %-25s | %-18s | %-30s | %-15s\n" "$subnet_name" "$SUBNET_PREFIX" "$SUBNET_RANGE" "$USABLE_ADDRESSES" "$DELEGATION" ""
                    fi
                done <<< "$SUBNETS"
            fi
        fi
    done <<< "$VNETS"
else
    echo "No virtual networks found in subscription"
fi

# Get Azure Private DNS Zones
echo ""
echo "=========================================="
echo "Azure Private DNS Zones:"
echo "=========================================="

DNS_ZONES=$(az network private-dns zone list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$DNS_ZONES" ]; then
    # Print table header
    printf "%-40s | %-50s | %-15s | %-30s | %-15s\n" "Azure Resource" "Azure PrivateLink DNS Zone Name" "Existing" "Record" "Comment"
    printf "%.40s-+-%.50s-+-%.15s-+-%.30s-+-%.15s\n" "----------------------------------------" "--------------------------------------------------" "---------------" "------------------------------" "---------------"
    
    while IFS= read -r zone_name; do
        if [ -n "$zone_name" ]; then
            # Get DNS zone resource group
            ZONE_RG=$(az network private-dns zone list --query "[?name=='$zone_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$ZONE_RG" ]; then
                # Get all record sets for this zone
                RECORD_SETS=$(az network private-dns record-set list -g "$ZONE_RG" -z "$zone_name" --query "[].[type, name]" -o tsv 2>/dev/null)
                
                if [ -n "$RECORD_SETS" ]; then
                    # First record set for this zone - include zone name
                    FIRST_RECORD=1
                    
                    echo "$RECORD_SETS" | while IFS=$'\t' read -r record_type record_name; do
                        if [ -n "$record_type" ] && [ -n "$record_name" ]; then
                            # Extract record type (e.g., "Microsoft.Network/privateDnsZones/A" -> "A")
                            RECORD_TYPE_SHORT=$(echo "$record_type" | awk -F'/' '{print $NF}')
                            
                            # Skip SOA and NS records at zone apex as they're automatic
                            if [ "$record_name" = "@" ] && { [ "$RECORD_TYPE_SHORT" = "SOA" ] || [ "$RECORD_TYPE_SHORT" = "NS" ]; }; then
                                continue
                            fi
                            
                            # Format record display
                            if [ "$record_name" = "@" ]; then
                                RECORD_DISPLAY="@ ($RECORD_TYPE_SHORT)"
                            else
                                RECORD_DISPLAY="$record_name ($RECORD_TYPE_SHORT)"
                            fi
                            
                            # Get associated resource (if any) - check for VNet links
                            VNET_LINKS=$(az network private-dns link vnet list -g "$ZONE_RG" -z "$zone_name" --query "[].name" -o tsv 2>/dev/null | head -1)
                            
                            if [ $FIRST_RECORD -eq 1 ]; then
                                if [ -n "$VNET_LINKS" ]; then
                                    AZURE_RESOURCE="VNet: $VNET_LINKS"
                                else
                                    AZURE_RESOURCE="Private DNS Zone"
                                fi
                                
                                printf "%-40s | %-50s | %-15s | %-30s | %-15s\n" "$AZURE_RESOURCE" "$zone_name" "" "$RECORD_DISPLAY" ""
                                FIRST_RECORD=0
                            else
                                printf "%-40s | %-50s | %-15s | %-30s | %-15s\n" "" "" "" "$RECORD_DISPLAY" ""
                            fi
                        fi
                    done
                else
                    # Zone exists but has no custom records
                    VNET_LINKS=$(az network private-dns link vnet list -g "$ZONE_RG" -z "$zone_name" --query "[].name" -o tsv 2>/dev/null | head -1)
                    
                    if [ -n "$VNET_LINKS" ]; then
                        AZURE_RESOURCE="VNet: $VNET_LINKS"
                    else
                        AZURE_RESOURCE="Private DNS Zone"
                    fi
                    
                    printf "%-40s | %-50s | %-15s | %-30s | %-15s\n" "$AZURE_RESOURCE" "$zone_name" "" "No custom records" ""
                fi
            fi
        fi
    done <<< "$DNS_ZONES"
else
    echo "No Private DNS Zones found in subscription"
fi

# Get Network Security Group Rules
echo ""
echo "=========================================="
echo "Network Security Group Rules:"
echo "=========================================="

NSGS=$(az network nsg list --query "[].name" -o tsv 2>/dev/null)

# Create CSV file with subscription name
CSV_FILE="${SUBSCRIPTION// /_}.csv"
echo "NSG Name,Priority,Direction,Name,Source,Src Port,Dst,Dst Port,Protocol,Action" > "$CSV_FILE"

if [ -n "$NSGS" ]; then
    echo "Exporting NSG rules to: $CSV_FILE"
    
    # Print table header for console output
    printf "%-25s | %-8s | %-10s | %-25s | %-20s | %-10s | %-20s | %-10s | %-10s | %-10s\n" "NSG Name" "Priority" "Direction" "Name" "Source" "Src Port" "Dst" "Dst Port" "Protocol" "Action"
    printf "%.25s-+-%.8s-+-%.10s-+-%.25s-+-%.20s-+-%.10s-+-%.20s-+-%.10s-+-%.10s-+-%.10s\n" "-------------------------" "--------" "----------" "-------------------------" "--------------------" "----------" "--------------------" "----------" "----------" "----------"
    
    while IFS= read -r nsg_name; do
        if [ -n "$nsg_name" ]; then
            # Get NSG resource group
            NSG_RG=$(az network nsg list --query "[?name=='$nsg_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$NSG_RG" ]; then
                # Get all security rules for this NSG
                RULES=$(az network nsg rule list -g "$NSG_RG" --nsg-name "$nsg_name" --query "[].[name, priority, direction, sourceAddressPrefix, sourcePortRange, destinationAddressPrefix, destinationPortRange, protocol, access]" -o tsv 2>/dev/null)
                
                if [ -n "$RULES" ]; then
                    echo "$RULES" | while IFS=$'\t' read -r rule_name priority direction src_addr src_port dst_addr dst_port protocol action; do
                        # Write full data to CSV
                        echo "\"$nsg_name\",\"$priority\",\"$direction\",\"$rule_name\",\"$src_addr\",\"$src_port\",\"$dst_addr\",\"$dst_port\",\"$protocol\",\"$action\"" >> "$CSV_FILE"
                        
                        # Truncate long values for console display
                        src_addr_short=$(echo "$src_addr" | cut -c1-20)
                        dst_addr_short=$(echo "$dst_addr" | cut -c1-20)
                        
                        printf "%-25s | %-8s | %-10s | %-25s | %-20s | %-10s | %-20s | %-10s | %-10s | %-10s\n" \
                            "$nsg_name" "$priority" "$direction" "$rule_name" "$src_addr_short" "$src_port" "$dst_addr_short" "$dst_port" "$protocol" "$action"
                    done
                fi
            fi
        fi
    done <<< "$NSGS"
    
    echo ""
    echo "NSG rules exported to: $CSV_FILE"
else
    echo "No Network Security Groups found in subscription"
fi

# Get NSG-Subnet Associations
echo ""
echo "=========================================="
echo "Network Security Group - Subnet Associations:"
echo "=========================================="

VNETS=$(az network vnet list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$VNETS" ]; then
    # Print table header
    printf "%-40s | %-40s\n" "Subnet Name" "Network Security Group"
    printf "%.40s-+-%.40s\n" "----------------------------------------" "----------------------------------------"
    
    while IFS= read -r vnet_name; do
        if [ -n "$vnet_name" ]; then
            # Get VNet resource group
            VNET_RG=$(az network vnet list --query "[?name=='$vnet_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$VNET_RG" ]; then
                # Get all subnets in this VNet
                SUBNETS=$(az network vnet subnet list -g "$VNET_RG" --vnet-name "$vnet_name" --query "[].name" -o tsv 2>/dev/null)
                
                while IFS= read -r subnet_name; do
                    if [ -n "$subnet_name" ]; then
                        # Get NSG associated with this subnet
                        NSG_ID=$(az network vnet subnet show -g "$VNET_RG" --vnet-name "$vnet_name" -n "$subnet_name" --query "networkSecurityGroup.id" -o tsv 2>/dev/null)
                        
                        if [ -n "$NSG_ID" ] && [ "$NSG_ID" != "null" ]; then
                            # Extract NSG name from ID
                            NSG_NAME=$(echo "$NSG_ID" | awk -F'/' '{print $NF}')
                        else
                            NSG_NAME="None"
                        fi
                        
                        # Format subnet name with VNet for clarity
                        FULL_SUBNET_NAME="${vnet_name}/${subnet_name}"
                        
                        printf "%-40s | %-40s\n" "$FULL_SUBNET_NAME" "$NSG_NAME"
                    fi
                done <<< "$SUBNETS"
            fi
        fi
    done <<< "$VNETS"
else
    echo "No virtual networks found in subscription"
fi

# Get Azure Firewall Rules
echo ""
echo "=========================================="
echo "Azure Firewall Rules:"
echo "=========================================="

FIREWALLS=$(az network firewall list --query "[].name" -o tsv 2>/dev/null)

if [ -n "$FIREWALLS" ]; then
    while IFS= read -r firewall_name; do
        if [ -n "$firewall_name" ]; then
            # Get firewall resource group
            FW_RG=$(az network firewall list --query "[?name=='$firewall_name'].resourceGroup" -o tsv 2>/dev/null)
            
            if [ -n "$FW_RG" ]; then
                echo ""
                echo "Firewall: $firewall_name"
                echo "----------------------------------------"
                
                # Print table header
                printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "Source" "Dest" "Port/Protocol" "URLs/Resources/IPs" "Direction" "Rule Type" "Comment"
                printf "%.20s-+-%.20s-+-%.20s-+-%.30s-+-%.15s-+-%.15s-+-%.15s\n" "--------------------" "--------------------" "--------------------" "------------------------------" "---------------" "---------------" "---------------"
                
                # Get firewall policy if attached
                POLICY_ID=$(az network firewall show -n "$firewall_name" -g "$FW_RG" --query "firewallPolicy.id" -o tsv 2>/dev/null)
                
                if [ -n "$POLICY_ID" ] && [ "$POLICY_ID" != "null" ]; then
                    # Extract policy name and resource group from ID
                    POLICY_NAME=$(echo "$POLICY_ID" | awk -F'/' '{print $NF}')
                    POLICY_RG=$(echo "$POLICY_ID" | awk -F'/' '{for(i=1;i<=NF;i++) if($i=="resourceGroups") print $(i+1)}')
                    
                    # Get rule collection groups
                    RULE_GROUPS=$(az network firewall policy rule-collection-group list --policy-name "$POLICY_NAME" -g "$POLICY_RG" --query "[].name" -o tsv 2>/dev/null)
                    
                    if [ -n "$RULE_GROUPS" ]; then
                        while IFS= read -r group_name; do
                            if [ -n "$group_name" ]; then
                                # Get rule collections in this group
                                GROUP_INFO=$(az network firewall policy rule-collection-group show --name "$group_name" --policy-name "$POLICY_NAME" -g "$POLICY_RG" 2>/dev/null)
                                
                                if [ -n "$GROUP_INFO" ]; then
                                    # Parse Application Rules
                                    APP_RULES=$(echo "$GROUP_INFO" | jq -r '.ruleCollections[]? | select(.ruleCollectionType=="FirewallPolicyFilterRuleCollection") | .rules[]? | select(.ruleType=="ApplicationRule") | [(.sourceAddresses // [] | join(",")), (.destinationAddresses // [] | join(",")), "App", (.targetFqdns // [] | join(",")), "Outbound", "Application", ""] | @tsv' 2>/dev/null)
                                    
                                    if [ -n "$APP_RULES" ]; then
                                        echo "$APP_RULES" | while IFS=$'\t' read -r src dest proto urls direction ruletype comment; do
                                            src_short=$(echo "$src" | cut -c1-20)
                                            dest_short=$(echo "$dest" | cut -c1-20)
                                            urls_short=$(echo "$urls" | cut -c1-30)
                                            printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "$src_short" "$dest_short" "$proto" "$urls_short" "$direction" "$ruletype" "$comment"
                                        done
                                    fi
                                    
                                    # Parse Network Rules
                                    NET_RULES=$(echo "$GROUP_INFO" | jq -r '.ruleCollections[]? | select(.ruleCollectionType=="FirewallPolicyFilterRuleCollection") | .rules[]? | select(.ruleType=="NetworkRule") | [(.sourceAddresses // [] | join(",")), (.destinationAddresses // [] | join(",")), ((.destinationPorts // [] | join(",")) + "/" + (.ipProtocols // [] | join(","))), (.destinationAddresses // [] | join(",")), "Outbound", "Network", ""] | @tsv' 2>/dev/null)
                                    
                                    if [ -n "$NET_RULES" ]; then
                                        echo "$NET_RULES" | while IFS=$'\t' read -r src dest proto ips direction ruletype comment; do
                                            src_short=$(echo "$src" | cut -c1-20)
                                            dest_short=$(echo "$dest" | cut -c1-20)
                                            proto_short=$(echo "$proto" | cut -c1-20)
                                            ips_short=$(echo "$ips" | cut -c1-30)
                                            printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "$src_short" "$dest_short" "$proto_short" "$ips_short" "$direction" "$ruletype" "$comment"
                                        done
                                    fi
                                    
                                    # Parse NAT Rules
                                    NAT_RULES=$(echo "$GROUP_INFO" | jq -r '.ruleCollections[]? | select(.ruleCollectionType=="FirewallPolicyNatRuleCollection") | .rules[]? | [(.sourceAddresses // [] | join(",")), (.translatedAddress // ""), ((.destinationPorts // [] | join(",")) + "/" + (.ipProtocols // [] | join(","))), (.destinationAddresses // [] | join(",")), "Inbound", "NAT", ""] | @tsv' 2>/dev/null)
                                    
                                    if [ -n "$NAT_RULES" ]; then
                                        echo "$NAT_RULES" | while IFS=$'\t' read -r src dest proto ips direction ruletype comment; do
                                            src_short=$(echo "$src" | cut -c1-20)
                                            dest_short=$(echo "$dest" | cut -c1-20)
                                            proto_short=$(echo "$proto" | cut -c1-20)
                                            ips_short=$(echo "$ips" | cut -c1-30)
                                            printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "$src_short" "$dest_short" "$proto_short" "$ips_short" "$direction" "$ruletype" "$comment"
                                        done
                                    fi
                                fi
                            fi
                        done <<< "$RULE_GROUPS"
                    else
                        echo "No rule collection groups found in firewall policy"
                    fi
                else
                    # Check for classic rules (non-policy based)
                    # Get Application Rule Collections
                    APP_COLLECTIONS=$(az network firewall application-rule collection list -f "$firewall_name" -g "$FW_RG" --query "[].name" -o tsv 2>/dev/null)
                    
                    if [ -n "$APP_COLLECTIONS" ]; then
                        while IFS= read -r collection_name; do
                            if [ -n "$collection_name" ]; then
                                RULES=$(az network firewall application-rule list -f "$firewall_name" -g "$FW_RG" -c "$collection_name" --query "[].[sourceAddresses | join(',', @), targetFqdns | join(',', @), protocols | join(',', @)]" -o tsv 2>/dev/null)
                                
                                if [ -n "$RULES" ]; then
                                    echo "$RULES" | while IFS=$'\t' read -r src fqdns protocols; do
                                        src_short=$(echo "$src" | cut -c1-20)
                                        fqdns_short=$(echo "$fqdns" | cut -c1-30)
                                        proto_short=$(echo "$protocols" | cut -c1-20)
                                        printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "$src_short" "*" "$proto_short" "$fqdns_short" "Outbound" "Application" ""
                                    done
                                fi
                            fi
                        done <<< "$APP_COLLECTIONS"
                    fi
                    
                    # Get Network Rule Collections
                    NET_COLLECTIONS=$(az network firewall network-rule collection list -f "$firewall_name" -g "$FW_RG" --query "[].name" -o tsv 2>/dev/null)
                    
                    if [ -n "$NET_COLLECTIONS" ]; then
                        while IFS= read -r collection_name; do
                            if [ -n "$collection_name" ]; then
                                RULES=$(az network firewall network-rule list -f "$firewall_name" -g "$FW_RG" -c "$collection_name" --query "[].[sourceAddresses | join(',', @), destinationAddresses | join(',', @), destinationPorts | join(',', @), protocols | join(',', @)]" -o tsv 2>/dev/null)
                                
                                if [ -n "$RULES" ]; then
                                    echo "$RULES" | while IFS=$'\t' read -r src dest ports protocols; do
                                        src_short=$(echo "$src" | cut -c1-20)
                                        dest_short=$(echo "$dest" | cut -c1-20)
                                        proto_info="${ports}/${protocols}"
                                        proto_short=$(echo "$proto_info" | cut -c1-20)
                                        ips_short=$(echo "$dest" | cut -c1-30)
                                        printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "$src_short" "$dest_short" "$proto_short" "$ips_short" "Outbound" "Network" ""
                                    done
                                fi
                            fi
                        done <<< "$NET_COLLECTIONS"
                    fi
                    
                    # Get NAT Rule Collections
                    NAT_COLLECTIONS=$(az network firewall nat-rule collection list -f "$firewall_name" -g "$FW_RG" --query "[].name" -o tsv 2>/dev/null)
                    
                    if [ -n "$NAT_COLLECTIONS" ]; then
                        while IFS= read -r collection_name; do
                            if [ -n "$collection_name" ]; then
                                RULES=$(az network firewall nat-rule list -f "$firewall_name" -g "$FW_RG" -c "$collection_name" --query "[].[sourceAddresses | join(',', @), destinationAddresses | join(',', @), destinationPorts | join(',', @), protocols | join(',', @), translatedAddress]" -o tsv 2>/dev/null)
                                
                                if [ -n "$RULES" ]; then
                                    echo "$RULES" | while IFS=$'\t' read -r src dest ports protocols translated; do
                                        src_short=$(echo "$src" | cut -c1-20)
                                        dest_short=$(echo "$translated" | cut -c1-20)
                                        proto_info="${ports}/${protocols}"
                                        proto_short=$(echo "$proto_info" | cut -c1-20)
                                        ips_short=$(echo "$dest" | cut -c1-30)
                                        printf "%-20s | %-20s | %-20s | %-30s | %-15s | %-15s | %-15s\n" "$src_short" "$dest_short" "$proto_short" "$ips_short" "Inbound" "NAT" ""
                                    done
                                fi
                            fi
                        done <<< "$NAT_COLLECTIONS"
                    fi
                fi
            fi
        fi
    done <<< "$FIREWALLS"
else
    echo "No Azure Firewalls found in subscription"
fi

echo ""
echo "=========================================="
echo "Inventory complete!"
