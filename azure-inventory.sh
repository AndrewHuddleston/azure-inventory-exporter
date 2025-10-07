#!/bin/bash

# Azure Subscription Services Inventory Script
# Purpose: Extract deployed services from multiple Azure subscriptions for Solution Design Document
# Usage: ./azure-inventory-multi.sh [subscription_prefix]

echo "=========================================="
echo "Azure Subscription Inventory"
echo "=========================================="
echo ""

# Check if logged in to Azure
if ! az account show &> /dev/null; then
    echo "Error: Not logged in to Azure. Please run 'az login' first."
    exit 1
fi

# Parse command line arguments
SUBSCRIPTION_PREFIX=""
if [ "$1" ]; then
    SUBSCRIPTION_PREFIX="$1"
    echo "Subscription prefix filter: $SUBSCRIPTION_PREFIX"
fi

# Get subscriptions to process
if [ -n "$SUBSCRIPTION_PREFIX" ]; then
    # Find all subscriptions matching the prefix
    SUBSCRIPTION_IDS=$(az account list --query "[?starts_with(name, '$SUBSCRIPTION_PREFIX')].id" -o tsv)
    
    if [ -z "$SUBSCRIPTION_IDS" ]; then
        echo "Error: No subscriptions found matching prefix '$SUBSCRIPTION_PREFIX'"
        exit 1
    fi
    
    SUBSCRIPTION_COUNT=$(echo "$SUBSCRIPTION_IDS" | wc -l | tr -d ' ')
    echo "Found $SUBSCRIPTION_COUNT subscription(s) matching prefix"
    CSV_FILE_BASE="${SUBSCRIPTION_PREFIX// /_}"
else
    # Use current subscription only
    SUBSCRIPTION_IDS=$(az account show --query id -o tsv)
    SUBSCRIPTION_COUNT=1
    CURRENT_SUB_NAME=$(az account show --query name -o tsv)
    CSV_FILE_BASE="${CURRENT_SUB_NAME// /_}"
fi

echo ""

# Helper function to safely write CSV field
csv_field() {
    local value="$1"
    if [ -z "$value" ] || [ "$value" = "null" ]; then
        echo '""'
    else
        echo "\"${value//\"/\"\"}\""
    fi
}

# Initialize CSV files (ONCE, before loop)
VM_CSV="${CSV_FILE_BASE}-vms.csv"
NSG_CSV="${CSV_FILE_BASE}-nsg-rules.csv"
VNET_CSV="${CSV_FILE_BASE}-vnets.csv"
SUBNET_CSV="${CSV_FILE_BASE}-subnets.csv"
DNS_CSV="${CSV_FILE_BASE}-private-dns.csv"

# Write CSV headers
echo "Role,Instance Name,OS,AZ,Instance Type,Storage Details" > "$VM_CSV"
echo "NSG Name,Priority,Direction,Name,Source,Src Port,Dst,Dst Port,Protocol,Action" > "$NSG_CSV"
echo "VNet Name,Location,CIDR Block,DNS Servers" > "$VNET_CSV"
echo "Subnet Name,Subnet Address,Subnet Range,# of Addresses,Delegation,Description" > "$SUBNET_CSV"
echo "Azure Resource,Azure PrivateLink DNS Zone Name,Existing,Record,Comment" > "$DNS_CSV"

# Track unique NSG rules across subscriptions (using a simpler approach for compatibility)
UNIQUE_NSG_RULES_FILE=$(mktemp)

# Function to print unique sorted array
print_category() {
    local category=$1
    shift
    local items=("$@")
    
    if [ ${#items[@]} -gt 0 ]; then
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

echo "Processing subscriptions..."
echo ""

# MAIN LOOP - Process each subscription
CURRENT_SUB=1
while IFS= read -r sub_id; do
    if [ -z "$sub_id" ]; then
        continue
    fi
    
    # Switch to subscription
    az account set --subscription "$sub_id" 2>/dev/null
    SUBSCRIPTION=$(az account show --query name -o tsv)
    
    echo "=========================================="
    echo "[$CURRENT_SUB/$SUBSCRIPTION_COUNT] Subscription: $SUBSCRIPTION"
    echo "=========================================="
    echo ""
    
    # Get all resource types for this subscription
    echo "Gathering resource information..."
    RESOURCES=$(az resource list --query "[].type" -o tsv | sort -u)
    
    if [ -z "$RESOURCES" ]; then
        echo "WARNING: No resources found in this subscription"
        echo ""
        CURRENT_SUB=$((CURRENT_SUB + 1))
        continue
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
    
    # Categorize resources
    while IFS= read -r resource; do
        case $resource in
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
            
            Microsoft.Storage/storageAccounts) STORAGE+=("Storage Account") ;;
            Microsoft.ContainerRegistry/registries) STORAGE+=("Container Registry") ;;
            
            Microsoft.Sql/servers) DATABASE+=("SQL Server") ;;
            Microsoft.Sql/servers/databases) DATABASE+=("SQL Database") ;;
            Microsoft.DocumentDB/databaseAccounts|Microsoft.DocumentDb/databaseAccounts) DATABASE+=("Cosmos DB") ;;
            Microsoft.EventHub/namespaces) DATABASE+=("Event Hub Namespace") ;;
            Microsoft.ServiceBus/namespaces) DATABASE+=("Service Bus Namespace") ;;
            Microsoft.Search/searchServices) DATABASE+=("Azure Cognitive Search") ;;
            
            Microsoft.KeyVault/vaults) SECURITY+=("Key Vault") ;;
            Microsoft.ManagedIdentity/userAssignedIdentities) SECURITY+=("Managed Identity") ;;
            
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
            
            *) OTHER+=("$resource") ;;
        esac
    done <<< "$RESOURCES"
    
    # Output resource summary
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
    echo "----------------------------------------"
    TAGS=$(az resource list --query "[].tags" -o json 2>/dev/null)
    
    if [ -n "$TAGS" ] && [ "$TAGS" != "[]" ] && [ "$TAGS" != "null" ]; then
        echo "$TAGS" | jq -r 'map(select(. != null) | to_entries[] | "\(.key): \(.value)") | unique | sort[]' 2>/dev/null | while IFS= read -r tag; do
            if [ -n "$tag" ]; then
                echo "  $tag"
            fi
        done
    else
        echo "  No tags found on resources"
    fi
    
    echo ""
    echo "Backup Configuration:"
    echo "----------------------------------------"
    
    # Check for Recovery Services Vaults
    VAULTS=$(az backup vault list --query "[].name" -o tsv 2>/dev/null)
    
    if [ -n "$VAULTS" ]; then
        while IFS= read -r vault_name; do
            if [ -n "$vault_name" ]; then
                VAULT_RG=$(az backup vault list --query "[?name=='$vault_name'].resourceGroup" -o tsv 2>/dev/null)
                
                if [ -n "$VAULT_RG" ]; then
                    echo ""
                    echo "Recovery Services Vault: $vault_name"
                    
                    # Get backup items (VMs)
                    VM_BACKUPS=$(az backup item list --vault-name "$vault_name" -g "$VAULT_RG" --query "[?properties.workloadType=='VM'].[properties.friendlyName, properties.policyName]" -o tsv 2>/dev/null)
                    
                    if [ -n "$VM_BACKUPS" ]; then
                        echo "  Virtual Machine Backups:"
                        echo "$VM_BACKUPS" | while IFS=$'\t' read -r item_name policy_name; do
                            if [ -n "$policy_name" ]; then
                                POLICY_INFO=$(az backup policy show --name "$policy_name" --vault-name "$vault_name" -g "$VAULT_RG" --query "{freq: properties.schedulePolicy.scheduleRunFrequency, retention: properties.retentionPolicy.dailySchedule.retentionDuration.count}" -o json 2>/dev/null)
                                
                                if [ -n "$POLICY_INFO" ]; then
                                    FREQUENCY=$(echo "$POLICY_INFO" | jq -r '.freq // "N/A"')
                                    RETENTION=$(echo "$POLICY_INFO" | jq -r '.retention // "N/A"')
                                    echo "    - $item_name | Policy: $policy_name | Frequency: $FREQUENCY | Retention: ${RETENTION} days"
                                fi
                            fi
                        done
                    fi
                    
                    # Get SQL backups
                    SQL_BACKUPS=$(az backup item list --vault-name "$vault_name" -g "$VAULT_RG" --query "[?properties.workloadType=='SQLDataBase'].[properties.friendlyName, properties.policyName]" -o tsv 2>/dev/null)
                    
                    if [ -n "$SQL_BACKUPS" ]; then
                        echo "  SQL Database Backups:"
                        echo "$SQL_BACKUPS" | while IFS=$'\t' read -r item_name policy_name; do
                            if [ -n "$policy_name" ]; then
                                POLICY_INFO=$(az backup policy show --name "$policy_name" --vault-name "$vault_name" -g "$VAULT_RG" --query "{freq: properties.schedulePolicy.scheduleRunFrequency, retention: properties.retentionPolicy.dailySchedule.retentionDuration.count}" -o json 2>/dev/null)
                                
                                if [ -n "$POLICY_INFO" ]; then
                                    FREQUENCY=$(echo "$POLICY_INFO" | jq -r '.freq // "N/A"')
                                    RETENTION=$(echo "$POLICY_INFO" | jq -r '.retention // "N/A"')
                                    echo "    - $item_name | Policy: $policy_name | Frequency: $FREQUENCY | Retention: ${RETENTION} days"
                                fi
                            fi
                        done
                    fi
                fi
            fi
        done <<< "$VAULTS"
    else
        echo "  No Recovery Services Vaults found"
    fi
    
    # Check for SQL Server Long-Term Retention
    echo ""
    echo "SQL Server Long-Term Retention Policies:"
    SQL_SERVERS=$(az sql server list --query "[].name" -o tsv 2>/dev/null)
    
    if [ -n "$SQL_SERVERS" ]; then
        SQL_LTR_FOUND=0
        while IFS= read -r sql_server; do
            if [ -n "$sql_server" ]; then
                SQL_RG=$(az sql server list --query "[?name=='$sql_server'].resourceGroup" -o tsv 2>/dev/null)
                
                if [ -n "$SQL_RG" ]; then
                    DBS=$(az sql db list -s "$sql_server" -g "$SQL_RG" --query "[?name!='master'].name" -o tsv 2>/dev/null)
                    
                    while IFS= read -r db_name; do
                        if [ -n "$db_name" ]; then
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
            echo "  No SQL databases with long-term retention policies"
        fi
    else
        echo "  No SQL servers found"
    fi
    
    echo ""
    
    # ========================================
    # VIRTUAL MACHINES
    # ========================================
    VMS=$(az vm list 2>/dev/null)
    if [ -n "$VMS" ] && [ "$VMS" != "[]" ]; then
        VM_COUNT=$(echo "$VMS" | jq '. | length')
        echo "  - Found $VM_COUNT VMs"
        
        az vm list --query "[].[name, resourceGroup]" -o tsv 2>/dev/null | while IFS=$'\t' read -r vm_name rg; do
            if [ -n "$vm_name" ] && [ -n "$rg" ]; then
                VM_SIZE=$(az vm show -n "$vm_name" -g "$rg" --query "hardwareProfile.vmSize" -o tsv 2>/dev/null)
                VM_OS=$(az vm show -n "$vm_name" -g "$rg" --query "storageProfile.osDisk.osType" -o tsv 2>/dev/null)
                VM_ZONES=$(az vm show -n "$vm_name" -g "$rg" --query "zones | join(',', @)" -o tsv 2>/dev/null)
                OS_DISK_SIZE=$(az vm show -n "$vm_name" -g "$rg" --query "storageProfile.osDisk.diskSizeGb" -o tsv 2>/dev/null)
                OS_DISK_TYPE=$(az vm show -n "$vm_name" -g "$rg" --query "storageProfile.osDisk.managedDisk.storageAccountType" -o tsv 2>/dev/null)
                DATA_DISK_COUNT=$(az vm show -n "$vm_name" -g "$rg" --query "length(storageProfile.dataDisks)" -o tsv 2>/dev/null)
                
                VM_OS=${VM_OS:-"Unknown"}
                VM_ZONES=${VM_ZONES:-"None"}
                OS_DISK_SIZE=${OS_DISK_SIZE:-"N/A"}
                OS_DISK_TYPE=${OS_DISK_TYPE:-"N/A"}
                DATA_DISK_COUNT=${DATA_DISK_COUNT:-"0"}
                
                if [ "$DATA_DISK_COUNT" -gt 0 ]; then
                    STORAGE_INFO="OS: ${OS_DISK_SIZE}GB (${OS_DISK_TYPE}), Data: ${DATA_DISK_COUNT} disk(s)"
                else
                    STORAGE_INFO="OS: ${OS_DISK_SIZE}GB (${OS_DISK_TYPE})"
                fi
                
                # Append to CSV
                echo "$(csv_field ""),$(csv_field "$vm_name"),$(csv_field "$VM_OS"),$(csv_field "$VM_ZONES"),$(csv_field "$VM_SIZE"),$(csv_field "$STORAGE_INFO")" >> "$VM_CSV"
            fi
        done
    fi
    
    # ========================================
    # VIRTUAL NETWORKS
    # ========================================
    VNETS=$(az network vnet list --query "[].name" -o tsv 2>/dev/null)
    if [ -n "$VNETS" ]; then
        VNET_COUNT=$(echo "$VNETS" | wc -l | tr -d ' ')
        echo "  - Found $VNET_COUNT VNets"
        
        while IFS= read -r vnet_name; do
            if [ -n "$vnet_name" ]; then
                VNET_RG=$(az network vnet list --query "[?name=='$vnet_name'].resourceGroup" -o tsv 2>/dev/null)
                
                if [ -n "$VNET_RG" ]; then
                    LOCATION=$(az network vnet show -n "$vnet_name" -g "$VNET_RG" --query "location" -o tsv 2>/dev/null)
                    CIDR_BLOCKS=$(az network vnet show -n "$vnet_name" -g "$VNET_RG" --query "addressSpace.addressPrefixes | join(', ', @)" -o tsv 2>/dev/null)
                    CIDR_BLOCKS=${CIDR_BLOCKS:-"N/A"}
                    DNS_SERVERS=$(az network vnet show -n "$vnet_name" -g "$VNET_RG" --query "dhcpOptions.dnsServers | join(', ', @)" -o tsv 2>/dev/null)
                    
                    if [ -z "$DNS_SERVERS" ] || [ "$DNS_SERVERS" = "null" ]; then
                        DNS_SERVERS="Default (Azure-provided)"
                    fi
                    
                    # Append to CSV
                    echo "$(csv_field "$vnet_name"),$(csv_field "$LOCATION"),$(csv_field "$CIDR_BLOCKS"),$(csv_field "$DNS_SERVERS")" >> "$VNET_CSV"
                fi
            fi
        done <<< "$VNETS"
    fi
    
    # ========================================
    # SUBNETS
    # ========================================
    if [ -n "$VNETS" ]; then
        SUBNET_COUNT=0
        while IFS= read -r vnet_name; do
            if [ -n "$vnet_name" ]; then
                VNET_RG=$(az network vnet list --query "[?name=='$vnet_name'].resourceGroup" -o tsv 2>/dev/null)
                
                if [ -n "$VNET_RG" ]; then
                    SUBNETS=$(az network vnet subnet list -g "$VNET_RG" --vnet-name "$vnet_name" --query "[].name" -o tsv 2>/dev/null)
                    
                    while IFS= read -r subnet_name; do
                        if [ -n "$subnet_name" ]; then
                            SUBNET_COUNT=$((SUBNET_COUNT + 1))
                            
                            SUBNET_PREFIX=$(az network vnet subnet show -g "$VNET_RG" --vnet-name "$vnet_name" -n "$subnet_name" --query "addressPrefix" -o tsv 2>/dev/null)
                            
                            if [ -n "$SUBNET_PREFIX" ]; then
                                PREFIX_LEN=$(echo "$SUBNET_PREFIX" | cut -d'/' -f2)
                                TOTAL_ADDRESSES=$((2**(32-PREFIX_LEN)))
                                USABLE_ADDRESSES=$((TOTAL_ADDRESSES - 5))
                                SUBNET_RANGE="$SUBNET_PREFIX"
                            else
                                SUBNET_RANGE="N/A"
                                USABLE_ADDRESSES="N/A"
                            fi
                            
                            DELEGATION=$(az network vnet subnet show -g "$VNET_RG" --vnet-name "$vnet_name" -n "$subnet_name" --query "delegations[0].serviceName" -o tsv 2>/dev/null)
                            
                            if [ -z "$DELEGATION" ] || [ "$DELEGATION" = "null" ]; then
                                DELEGATION="None"
                            fi
                            
                            # Append to CSV
                            echo "$(csv_field "$subnet_name"),$(csv_field "$SUBNET_PREFIX"),$(csv_field "$SUBNET_RANGE"),$(csv_field "$USABLE_ADDRESSES"),$(csv_field "$DELEGATION"),$(csv_field "")" >> "$SUBNET_CSV"
                        fi
                    done <<< "$SUBNETS"
                fi
            fi
        done <<< "$VNETS"
        
        if [ $SUBNET_COUNT -gt 0 ]; then
            echo "  - Found $SUBNET_COUNT Subnets"
        fi
    fi
    
    # ========================================
    # PRIVATE DNS ZONES
    # ========================================
    DNS_ZONES=$(az network private-dns zone list --query "[].name" -o tsv 2>/dev/null)
    if [ -n "$DNS_ZONES" ]; then
        DNS_COUNT=$(echo "$DNS_ZONES" | wc -l | tr -d ' ')
        echo "  - Found $DNS_COUNT Private DNS Zones"
        
        while IFS= read -r zone_name; do
            if [ -n "$zone_name" ]; then
                ZONE_RG=$(az network private-dns zone list --query "[?name=='$zone_name'].resourceGroup" -o tsv 2>/dev/null)
                
                if [ -n "$ZONE_RG" ]; then
                    RECORD_SETS=$(az network private-dns record-set list -g "$ZONE_RG" -z "$zone_name" --query "[].[type, name]" -o tsv 2>/dev/null)
                    VNET_LINKS=$(az network private-dns link vnet list -g "$ZONE_RG" -z "$zone_name" --query "[].name" -o tsv 2>/dev/null | head -1)
                    
                    if [ -n "$VNET_LINKS" ]; then
                        AZURE_RESOURCE="VNet: $VNET_LINKS"
                    else
                        AZURE_RESOURCE="Private DNS Zone"
                    fi
                    
                    if [ -n "$RECORD_SETS" ]; then
                        FIRST_RECORD=1
                        echo "$RECORD_SETS" | while IFS=$'\t' read -r record_type record_name; do
                            if [ -n "$record_type" ] && [ -n "$record_name" ]; then
                                RECORD_TYPE_SHORT=$(echo "$record_type" | awk -F'/' '{print $NF}')
                                
                                # Skip SOA and NS records
                                if [ "$record_name" = "@" ] && { [ "$RECORD_TYPE_SHORT" = "SOA" ] || [ "$RECORD_TYPE_SHORT" = "NS" ]; }; then
                                    continue
                                fi
                                
                                if [ "$record_name" = "@" ]; then
                                    RECORD_DISPLAY="@ ($RECORD_TYPE_SHORT)"
                                else
                                    RECORD_DISPLAY="$record_name ($RECORD_TYPE_SHORT)"
                                fi
                                
                                if [ $FIRST_RECORD -eq 1 ]; then
                                    echo "$(csv_field "$AZURE_RESOURCE"),$(csv_field "$zone_name"),$(csv_field ""),$(csv_field "$RECORD_DISPLAY"),$(csv_field "")" >> "$DNS_CSV"
                                    FIRST_RECORD=0
                                else
                                    echo "$(csv_field ""),$(csv_field ""),$(csv_field ""),$(csv_field "$RECORD_DISPLAY"),$(csv_field "")" >> "$DNS_CSV"
                                fi
                            fi
                        done
                    else
                        echo "$(csv_field "$AZURE_RESOURCE"),$(csv_field "$zone_name"),$(csv_field ""),$(csv_field "No custom records"),$(csv_field "")" >> "$DNS_CSV"
                    fi
                fi
            fi
        done <<< "$DNS_ZONES"
    fi
    
    # ========================================
    # NSG RULES (with deduplication)
    # ========================================
    NSGS=$(az network nsg list --query "[].name" -o tsv 2>/dev/null)
    if [ -n "$NSGS" ]; then
        NSG_COUNT=$(echo "$NSGS" | wc -l | tr -d ' ')
        RULE_COUNT=0
        
        while IFS= read -r nsg_name; do
            if [ -n "$nsg_name" ]; then
                NSG_RG=$(az network nsg list --query "[?name=='$nsg_name'].resourceGroup" -o tsv 2>/dev/null)
                
                if [ -n "$NSG_RG" ]; then
                    # Use JSON output to avoid tab-parsing issues with null/empty values
                    RULES_JSON=$(az network nsg rule list -g "$NSG_RG" --nsg-name "$nsg_name" --query "[]" -o json 2>/dev/null)
                    
                    if [ -n "$RULES_JSON" ] && [ "$RULES_JSON" != "[]" ]; then
                        # Use jq to extract fields in correct order matching CSV header
                        # CSV Header: NSG Name,Priority,Direction,Name,Source,Src Port,Dst,Dst Port,Protocol,Action
                        echo "$RULES_JSON" | jq -r '.[] | 
                            (.priority // "-" | tostring) + "\t" + 
                            (.direction // "-") + "\t" + 
                            (.name // "-") + "\t" + 
                            (.sourceAddressPrefix // "-") + "\t" + 
                            (if .sourcePortRange then (if (.sourcePortRange | type) == "array" then (.sourcePortRange | join(",")) else (.sourcePortRange | tostring) end) else "-" end) + "\t" + 
                            (.destinationAddressPrefix // "-") + "\t" + 
                            (if .destinationPortRange then (if (.destinationPortRange | type) == "array" then (.destinationPortRange | join(",")) else (.destinationPortRange | tostring) end) else "-" end) + "\t" + 
                            (.protocol // "-") + "\t" + 
                            (.access // "-")' | while IFS=$'\t' read -r priority direction rule_name src_addr src_port dst_addr dst_port protocol action || [ -n "$priority" ]; do
                            # Ensure all fields have values (use - as placeholder for empty)
                            priority=${priority:-"-"}
                            direction=${direction:-"-"}
                            rule_name=${rule_name:-"-"}
                            src_addr=${src_addr:-"-"}
                            src_port=${src_port:-"-"}
                            dst_addr=${dst_addr:-"-"}
                            dst_port=${dst_port:-"-"}
                            protocol=${protocol:-"-"}
                            action=${action:-"-"}
                            
                            # Create unique key for deduplication
                            RULE_KEY="${priority}|${direction}|${rule_name}|${src_addr}|${src_port}|${dst_addr}|${dst_port}|${protocol}|${action}"
                            
                            # Only add if not already seen (using grep on temp file)
                            if ! grep -Fxq "$RULE_KEY" "$UNIQUE_NSG_RULES_FILE" 2>/dev/null; then
                                echo "$(csv_field "$nsg_name"),$(csv_field "$priority"),$(csv_field "$direction"),$(csv_field "$rule_name"),$(csv_field "$src_addr"),$(csv_field "$src_port"),$(csv_field "$dst_addr"),$(csv_field "$dst_port"),$(csv_field "$protocol"),$(csv_field "$action")" >> "$NSG_CSV"
                                echo "$RULE_KEY" >> "$UNIQUE_NSG_RULES_FILE"
                                RULE_COUNT=$((RULE_COUNT + 1))
                            fi
                        done
                    fi
                fi
            fi
        done <<< "$NSGS"
        
        echo "  - Found $NSG_COUNT NSGs with $RULE_COUNT unique rules"
    fi
    
    echo ""
    CURRENT_SUB=$((CURRENT_SUB + 1))
    
done <<< "$SUBSCRIPTION_IDS"

echo "=========================================="
echo "Inventory Complete!"
echo "=========================================="
echo ""
echo "CSV Files Generated:"
echo "  - $VM_CSV"
echo "  - $NSG_CSV"
echo "  - $VNET_CSV"
echo "  - $SUBNET_CSV"
echo "  - $DNS_CSV"
echo ""
